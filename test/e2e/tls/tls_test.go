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

	"k8s.io/klog/v2"

	ctrltls "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"

	nropv1 "github.com/openshift-kni/numaresources-operator/api/v1"
	"github.com/openshift-kni/numaresources-operator/internal/podlist"
	intls "github.com/openshift-kni/numaresources-operator/internal/tls"
	e2eclient "github.com/openshift-kni/numaresources-operator/test/internal/clients"
	"github.com/openshift-kni/numaresources-operator/test/internal/objects"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const schedulerSecurePort = "10259"

var _ = Describe("TLS", func() {
	It("should reject TLS connections that are not compatible with the profile - negative test", func(ctx context.Context) {
		By("getting the current OCP TLS profile")
		tlsProfileSpec, err := ctrltls.FetchAPIServerTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred(), "unable to get TLS profile from APIServer")

		tlsConfigFn, _ := ctrltls.NewTLSConfigFromProfile(tlsProfileSpec)
		tlsCfg := &tls.Config{}
		tlsConfigFn(tlsCfg)
		minVersion := tlsCfg.MinVersion
		klog.InfoS("current TLS minimum version", "version", libgocrypto.TLSVersionToNameOrDie(minVersion))

		belowMinVersion := intls.TlsVersionBelow(minVersion)
		if belowMinVersion == 0 {
			Skip(fmt.Sprintf("no TLS version below %s to test against", libgocrypto.TLSVersionToNameOrDie(minVersion)))
		}

		By("getting the scheduler deployment and pods")
		nroSchedObj := &nropv1.NUMAResourcesScheduler{}
		nroSchedKey := objects.NROSchedObjectKey()
		Expect(e2eclient.Client.Get(ctx, nroSchedKey, nroSchedObj)).To(Succeed(), "failed to get %q in the cluster", nroSchedKey.String())

		deployment, err := podlist.With(e2eclient.Client).DeploymentByOwnerReference(ctx, nroSchedObj.GetUID())
		Expect(err).ToNot(HaveOccurred(), "failed to get the deployment")
		Expect(deployment).ToNot(BeNil(), "scheduler deployment not found")

		pods, err := podlist.With(e2eclient.Client).ByDeployment(ctx, *deployment)
		Expect(err).ToNot(HaveOccurred(), "failed to get the pods")
		Expect(pods).ToNot(BeEmpty(), "no pods found for the deployment")

		schedulerPod := &pods[0]

		By(fmt.Sprintf("verifying that TLS connections at version %s are rejected by the server", intls.CurlTLSValue(belowMinVersion)))
		endpoint := fmt.Sprintf("https://localhost:%s/healthz", schedulerSecurePort)
		_, err = intls.ProbeMaxTLSVersion(ctx, e2eclient.K8sClient, schedulerPod, endpoint, belowMinVersion)
		Expect(err).To(HaveOccurred(), "scheduler server should reject TLS connections capped at %s", intls.CurlTLSValue(belowMinVersion))
		// expects SSl/TLS connection error
		Expect(err.Error()).To(ContainSubstring("code 35"))

		By(fmt.Sprintf("verifying that TLS connections with unsupported ciphers are rejected by the server"))
		if minVersion == tls.VersionTLS13 {
			klog.InfoS("TLS 1.3 is not configurable, so we cannot test unsupported ciphers")
			return
		}

		disallowedCipher := intls.FindDisallowedCipher(tlsProfileSpec.Ciphers)
		if disallowedCipher == "" {
			Skip("all known TLS 1.2 ciphers are in the allowed set, nothing to test")
		}
		klog.InfoS("testing with disallowed cipher", "cipher", disallowedCipher)
		err = intls.ProbeTLSCipher(ctx, e2eclient.K8sClient, schedulerPod, endpoint, disallowedCipher)
		Expect(err).To(HaveOccurred(), "scheduler server should reject connections with disallowed cipher %s", disallowedCipher)
		Expect(err.Error()).To(ContainSubstring("code 35"))
	})

	It("should adhere to openshift TLS profile - positive test", func(ctx context.Context) {
		By("getting the current OCP TLS profile")
		tlsProfileSpec, err := ctrltls.FetchAPIServerTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred(), "unable to get TLS profile from APIServer")

		tlsConfigFn, _ := ctrltls.NewTLSConfigFromProfile(tlsProfileSpec)
		tlsCfg := &tls.Config{}
		tlsConfigFn(tlsCfg)
		minVersion := tlsCfg.MinVersion
		klog.InfoS("current TLS minimum version", "version", libgocrypto.TLSVersionToNameOrDie(minVersion))

		By("getting the scheduler deployment and pods")
		nroSchedObj := &nropv1.NUMAResourcesScheduler{}
		nroSchedKey := objects.NROSchedObjectKey()
		Expect(e2eclient.Client.Get(ctx, nroSchedKey, nroSchedObj)).To(Succeed(), "failed to get %q in the cluster", nroSchedKey.String())

		deployment, err := podlist.With(e2eclient.Client).DeploymentByOwnerReference(ctx, nroSchedObj.GetUID())
		Expect(err).ToNot(HaveOccurred(), "failed to get the deployment")
		Expect(deployment).ToNot(BeNil(), "scheduler deployment not found")

		pods, err := podlist.With(e2eclient.Client).ByDeployment(ctx, *deployment)
		Expect(err).ToNot(HaveOccurred(), "failed to get the pods")
		Expect(pods).ToNot(BeEmpty(), "no pods found for the deployment")

		schedulerPod := &pods[0]

		By("probing the scheduler HTTPS endpoint to verify TLS connection is accepted")
		endpoint := fmt.Sprintf("https://localhost:%s/healthz", schedulerSecurePort)
		gotVersion, gotCipher, err := intls.ProbeTLSSettings(ctx, e2eclient.K8sClient, schedulerPod, endpoint)
		Expect(err).ToNot(HaveOccurred(), "failed to probe TLS settings on pod %q", schedulerPod.Name)
		klog.InfoS("negotiated TLS settings", "version", gotVersion, "cipher", gotCipher)

		uint16Version, err := intls.CurlTLSVersionToUint16(gotVersion)
		Expect(err).ToNot(HaveOccurred(), "failed to get TLS version from %q", gotVersion)
		Expect(uint16Version).To(BeNumerically(">=", minVersion), "negotiated TLS version %q is below the expected minimum %q", gotVersion, libgocrypto.TLSVersionToNameOrDie(minVersion))

		ianaCiphers := libgocrypto.OpenSSLToIANACipherSuites([]string{gotCipher})
		klog.InfoS("ciphers mapping", "gotCipher", gotCipher, "ianaCiphers", ianaCiphers)
		// TLS 1.3 cipher suites are not configurable and won't appear in
		// the profile's list; only validate for TLS 1.2 and below.
		if uint16Version < tls.VersionTLS13 {
			Expect(ianaCiphers).ToNot(BeEmpty(), "could not map negotiated cipher %v to any IANA name", gotCipher)
			for _, cipher := range ianaCiphers {
				Expect(tlsProfileSpec.Ciphers).To(ContainElement(cipher), "negotiated cipher %v (IANA: %v) is not in the allowed set %v", gotCipher, cipher, tlsProfileSpec.Ciphers)
			}
		}
	})
})
