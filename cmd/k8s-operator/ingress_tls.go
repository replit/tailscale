// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/util/mak"
)

const indexIngressTLSSecret = ".spec.tls.secretName"

type ingressCustomTLS struct {
	hosts      []string
	secretName string
	secret     *corev1.Secret
}

func customTLSForIngress(ctx context.Context, cl client.Client, ing *networkingv1.Ingress) (*ingressCustomTLS, error) {
	hosts := ingressTLSHosts(ing)
	if len(hosts) == 0 || len(ing.Spec.TLS) == 0 || ing.Spec.TLS[0].SecretName == "" {
		return nil, nil
	}

	secret := &corev1.Secret{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ing.Namespace, Name: ing.Spec.TLS[0].SecretName}, secret); err != nil {
		return nil, fmt.Errorf("getting TLS Secret %s/%s: %w", ing.Namespace, ing.Spec.TLS[0].SecretName, err)
	}
	if len(secret.Data[corev1.TLSCertKey]) == 0 || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		return nil, fmt.Errorf("TLS Secret %s/%s must contain tls.crt and tls.key data", ing.Namespace, ing.Spec.TLS[0].SecretName)
	}

	return &ingressCustomTLS{
		hosts:      hosts,
		secretName: ing.Spec.TLS[0].SecretName,
		secret:     secret,
	}, nil
}

// ingressTLSHosts returns all hosts from the first TLS entry of the Ingress.
func ingressTLSHosts(ing *networkingv1.Ingress) []string {
	if ing.Spec.TLS != nil && len(ing.Spec.TLS) > 0 && len(ing.Spec.TLS[0].Hosts) > 0 {
		return ing.Spec.TLS[0].Hosts
	}
	return nil
}

// ingressTLSHost returns the first host from the first TLS entry of the Ingress.
func ingressTLSHost(ing *networkingv1.Ingress) string {
	if hosts := ingressTLSHosts(ing); len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}

func ingressHTTPSHost(ing *networkingv1.Ingress, defaultHost string) string {
	if host := ingressTLSHost(ing); host != "" {
		return host
	}
	return defaultHost
}

func hasTLSSecretData(ctx context.Context, cl client.Client, ns, name string) (bool, error) {
	secret := &corev1.Secret{}
	err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return len(secret.Data[corev1.TLSCertKey]) > 0 && len(secret.Data[corev1.TLSPrivateKeyKey]) > 0, nil
}

func ingressHTTPSHosts(defaultHost string, customTLS *ingressCustomTLS) []string {
	if customTLS == nil {
		return []string{defaultHost}
	}
	// Custom TLS hosts come first, followed by the default MagicDNS host
	// (if it's not already one of the custom hosts).
	seen := make(map[string]bool, len(customTLS.hosts)+1)
	var hosts []string
	for _, h := range customTLS.hosts {
		if !seen[h] {
			hosts = append(hosts, h)
			seen[h] = true
		}
	}
	if !seen[defaultHost] {
		hosts = append(hosts, defaultHost)
	}
	return hosts
}

func copyCustomTLSSecretData(data map[string][]byte, customTLS *ingressCustomTLS) {
	if customTLS == nil {
		return
	}
	for _, host := range customTLS.hosts {
		mak.Set(&data, host+".crt", append([]byte(nil), customTLS.secret.Data[corev1.TLSCertKey]...))
		mak.Set(&data, host+".key", append([]byte(nil), customTLS.secret.Data[corev1.TLSPrivateKeyKey]...))
	}
}

func ensureCustomTLSStateSecrets(ctx context.Context, cl client.Client, namespace string, pg *tsapi.ProxyGroup, customTLS *ingressCustomTLS) error {
	if customTLS == nil {
		return nil
	}
	secrets := &corev1.SecretList{}
	if err := cl.List(ctx, secrets, client.InNamespace(namespace), client.MatchingLabels(pgSecretLabels(pg.Name, kubetypes.LabelSecretTypeState))); err != nil {
		return fmt.Errorf("listing ProxyGroup state Secrets for %q: %w", pg.Name, err)
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		orig := secret.DeepCopy()
		copyCustomTLSSecretData(secret.Data, customTLS)
		if err := cl.Patch(ctx, secret, client.MergeFrom(orig)); err != nil {
			return fmt.Errorf("updating ProxyGroup state Secret %s/%s: %w", namespace, secret.Name, err)
		}
	}
	return nil
}

func indexTLSSecretName(o client.Object) []string {
	ing, ok := o.(*networkingv1.Ingress)
	if !ok || len(ing.Spec.TLS) == 0 {
		return nil
	}
	name := strings.TrimSpace(ing.Spec.TLS[0].SecretName)
	if name == "" {
		return nil
	}
	return []string{name}
}

func ingressesFromTLSSecret(cl client.Client, logger clientLogger, ingressClassName string, requireProxyGroup bool) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		secret, ok := o.(*corev1.Secret)
		if !ok {
			logger.Infof("[unexpected] TLS Secret handler triggered for a non-Secret object")
			return nil
		}

		ingList := &networkingv1.IngressList{}
		if err := cl.List(ctx, ingList, client.InNamespace(secret.Namespace), client.MatchingFields{indexIngressTLSSecret: secret.Name}); err != nil {
			logger.Infof("error listing Ingresses for TLS Secret %s/%s: %v", secret.Namespace, secret.Name, err)
			return nil
		}

		requests := make([]reconcile.Request, 0, len(ingList.Items))
		for _, ing := range ingList.Items {
			if ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName != ingressClassName {
				continue
			}
			hasProxyGroup := ing.Annotations[AnnotationProxyGroup] != ""
			if hasProxyGroup != requireProxyGroup {
				continue
			}
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ing)})
		}
		return requests
	}
}

func markManagedTLSSecretLabels(labels map[string]string, parent client.Object) map[string]string {
	out := make(map[string]string, len(labels)+3)
	for key, value := range labels {
		out[key] = value
	}
	mkParentLabels(&out, parent)
	return out
}

func mkParentLabels(labels *map[string]string, parent client.Object) {
	mak.Set(labels, LabelParentType, strings.ToLower(parent.GetObjectKind().GroupVersionKind().Kind))
	mak.Set(labels, LabelParentName, parent.GetName())
	if ns := parent.GetNamespace(); ns != "" {
		mak.Set(labels, LabelParentNamespace, ns)
	}
}

type clientLogger interface {
	Infof(string, ...any)
}
