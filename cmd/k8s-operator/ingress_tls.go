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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/kube/kubetypes"
	"tailscale.com/util/mak"
)

const indexIngressTLSSecret = ".spec.tls.secretName"

type ingressCustomTLS struct {
	host       string
	secretName string
	secret     *corev1.Secret
}

func customTLSForIngress(ctx context.Context, cl client.Client, ing *networkingv1.Ingress) (*ingressCustomTLS, error) {
	host := ingressTLSHost(ing)
	if host == "" || len(ing.Spec.TLS) == 0 || ing.Spec.TLS[0].SecretName == "" {
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
		host:       host,
		secretName: ing.Spec.TLS[0].SecretName,
		secret:     secret,
	}, nil
}

func ingressTLSHost(ing *networkingv1.Ingress) string {
	if ing.Spec.TLS != nil && len(ing.Spec.TLS) > 0 && len(ing.Spec.TLS[0].Hosts) > 0 {
		return ing.Spec.TLS[0].Hosts[0]
	}
	return ""
}

func ingressHTTPSHost(ing *networkingv1.Ingress, defaultHost string) string {
	if host := ingressTLSHost(ing); host != "" {
		return host
	}
	return defaultHost
}

func managedTLSSecret(name, namespace string, labels map[string]string, source *corev1.Secret) *corev1.Secret {
	managedLabels := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		managedLabels[key] = value
	}
	managedLabels[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeCerts

	managed := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    managedLabels,
		},
		Type: corev1.SecretTypeTLS,
	}
	if source != nil {
		managed.Data = map[string][]byte{
			corev1.TLSCertKey:       append([]byte(nil), source.Data[corev1.TLSCertKey]...),
			corev1.TLSPrivateKeyKey: append([]byte(nil), source.Data[corev1.TLSPrivateKeyKey]...),
		}
	}
	return managed
}

func ingressCertShareMode(customTLS bool) string {
	if customTLS {
		return "rw"
	}
	return ""
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

func ensureManagedTLSSecret(ctx context.Context, cl client.Client, name, namespace string, labels map[string]string, source *corev1.Secret) error {
	secret := managedTLSSecret(name, namespace, labels, source)
	_, err := createOrUpdate(ctx, cl, namespace, secret, func(existing *corev1.Secret) {
		existing.Labels = secret.Labels
		existing.Type = secret.Type
		existing.Data = secret.Data
	})
	if err != nil {
		return fmt.Errorf("creating or updating managed TLS Secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

func customTLSSecretsForProxyGroup(ctx context.Context, cl client.Client, pgName string) ([]ingressCustomTLS, error) {
	ingList := &networkingv1.IngressList{}
	if err := cl.List(ctx, ingList); err != nil {
		return nil, fmt.Errorf("listing Ingresses for ProxyGroup %q: %w", pgName, err)
	}

	custom := make([]ingressCustomTLS, 0)
	for i := range ingList.Items {
		ing := &ingList.Items[i]
		if ing.Annotations[AnnotationProxyGroup] != pgName {
			continue
		}
		tlsCfg, err := customTLSForIngress(ctx, cl, ing)
		if err != nil {
			return nil, fmt.Errorf("Ingress %s/%s: %w", ing.Namespace, ing.Name, err)
		}
		if tlsCfg == nil {
			continue
		}
		custom = append(custom, *tlsCfg)
	}
	return custom, nil
}

func proxyGroupUsesCustomTLS(ctx context.Context, cl client.Client, pgName string) (bool, error) {
	ingList := &networkingv1.IngressList{}
	if err := cl.List(ctx, ingList); err != nil {
		return false, fmt.Errorf("listing Ingresses for ProxyGroup %q: %w", pgName, err)
	}

	var total, custom int
	for i := range ingList.Items {
		ing := &ingList.Items[i]
		if ing.Annotations[AnnotationProxyGroup] != pgName {
			continue
		}
		total++
		if len(ing.Spec.TLS) > 0 && ing.Spec.TLS[0].SecretName != "" {
			custom++
		}
	}

	if custom == 0 {
		return false, nil
	}
	if custom != total {
		return false, fmt.Errorf("all Ingresses on ProxyGroup %q must set spec.tls[0].secretName when any of them use a custom TLS Secret", pgName)
	}
	return true, nil
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
