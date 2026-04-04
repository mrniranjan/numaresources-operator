/*
 * Copyright 2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift-kni/numaresources-operator/internal/remoteexec"
)

var sslConnectionRe = regexp.MustCompile(`SSL connection using (\S+)\s*/\s*(\S+)`)

// ProbeMaxTLSVersion checks whether the endpoint's server rejects
// TLS connections capped at the given maximum version.
func ProbeMaxTLSVersion(ctx context.Context, cli kubernetes.Interface, pod *corev1.Pod, endpoint string, maxVersion uint16) (string, error) {
	cmd := []string{
		"curl", "-k", "-s", "-o", "/dev/null",
		"--connect-timeout", "5",
		"--tls-max", CurlTLSValue(maxVersion),
		"-w", "%{http_code}",
		endpoint,
	}
	key := client.ObjectKeyFromObject(pod)
	stdout, stderr, err := remoteexec.CommandOnPod(ctx, cli, pod, cmd...)
	klog.InfoS("probe with max TLS version", "pod", key.String(), "cmd", cmd, "stdout", string(stdout), "stderr", string(stderr), "err", err)
	trimmed := strings.TrimSpace(string(stdout))
	return trimmed, err
}

// ProbeTLSCipher checks whether the endpoint's server rejects
// TLS connections when the client only offers the given cipher (OpenSSL name).
// Since this is dedicated to invalidating ciphers, it is assumed that it is
// called on non TLS 1.3 configuration
func ProbeTLSCipher(ctx context.Context, cli kubernetes.Interface, pod *corev1.Pod, endpoint string, cipher string) error {
	// we explicitly use TLS 1.2 because it is the highest version that supports the ciphers
	// that way both client and server will agree to use the same version and cipher that is <= TLS 1.2
	cmd := []string{
		"curl", "-k", "-s", "-o", "/dev/null",
		"--connect-timeout", "5",
		"--tls-max", "1.2",
		"--ciphers", cipher,
		endpoint,
	}
	key := client.ObjectKeyFromObject(pod)
	stdout, stderr, err := remoteexec.CommandOnPod(ctx, cli, pod, cmd...)
	klog.InfoS("probe with TLS cipher", "pod", key.String(), "cmd", cmd, "stdout", string(stdout), "stderr", string(stderr), "err", err)

	return err
}

// ProbeTLSSettings execs curl -v inside the pod and returns the negotiated
// TLS version and cipher suite by parsing curl's verbose output for the
// "SSL connection using <version> / <cipher>" line.
func ProbeTLSSettings(ctx context.Context, cli kubernetes.Interface, pod *corev1.Pod, endpoint string) (version string, cipher string, err error) {
	cmd := []string{
		"curl", "-k", "-s", "-v", "-o", "/dev/null",
		"--connect-timeout", "5",
		endpoint,
	}
	key := client.ObjectKeyFromObject(pod)

	stdout, stderr, err := remoteexec.CommandOnPod(ctx, cli, pod, cmd...)
	klog.InfoS("probe TLS settings", "pod", key.String(), "cmd", cmd, "stdout", string(stdout), "stderr", string(stderr), "err", err)
	if err != nil {
		return "", "", err
	}
	// With TTY enabled in remoteexec, stderr merges into stdout
	output := string(stdout) + string(stderr)
	matches := sslConnectionRe.FindStringSubmatch(output)
	if len(matches) < 3 {
		return "", "", fmt.Errorf("could not find SSL connection info in curl output on pod %q: %s", key.String(), output)
	}
	return matches[1], matches[2], nil
}

// findDisallowedCipher returns the first TLS 1.2 cipher (OpenSSL name)
// from the broadest upstream profile (Old) that is not in the allowed set.
// TLS 1.3 ciphers are skipped because they are not individually configurable.
func FindDisallowedCipher(allowed []string) string {
	allowedSet := make(map[string]bool, len(allowed))
	for _, c := range allowed {
		allowedSet[c] = true
	}
	allCiphers := configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers
	for _, cipher := range allCiphers {
		if strings.HasPrefix(cipher, "TLS_") {
			continue
		}
		if !allowedSet[cipher] {
			return cipher
		}
	}
	return ""
}

func CurlTLSVersionToUint16(curlVersion string) (uint16, error) {
	switch curlVersion {
	case "TLSv1", "TLSv1.0":
		return tls.VersionTLS10, nil
	case "TLSv1.1":
		return tls.VersionTLS11, nil
	case "TLSv1.2":
		return tls.VersionTLS12, nil
	case "TLSv1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown curl TLS version %q", curlVersion)
	}
}

func CurlTLSValue(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return ""
	}
}

func TlsVersionBelow(v uint16) uint16 {
	switch v {
	case tls.VersionTLS13:
		return tls.VersionTLS12
	case tls.VersionTLS12:
		return tls.VersionTLS11
	case tls.VersionTLS11:
		return tls.VersionTLS10
	default:
		return 0
	}
}
