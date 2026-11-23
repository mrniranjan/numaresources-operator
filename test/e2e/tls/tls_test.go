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
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"

	nropv1 "github.com/openshift-kni/numaresources-operator/api/v1"
	"github.com/openshift-kni/numaresources-operator/internal/podlist"
	"github.com/openshift-kni/numaresources-operator/pkg/objectnames"
	"github.com/openshift-kni/numaresources-operator/test/e2e/label"
	e2eclient "github.com/openshift-kni/numaresources-operator/test/internal/clients"
	"github.com/openshift-kni/numaresources-operator/test/internal/deploy"
	e2efixture "github.com/openshift-kni/numaresources-operator/test/internal/fixture"
	"github.com/openshift-kni/numaresources-operator/test/internal/objects"
	intls "github.com/openshift-kni/numaresources-operator/test/internal/tls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const schedulerSecurePort = "10259"
const operatorMetricsPort = "8080"

var _ = Describe("TLS", func() {
	Context("[tlscompliance][scheduler] scheduler complies with TLS Profile modifications",
		Label(label.Tier0, "feature:tlscompliance"), Ordered, func() {
			var (
				minVersion      uint16
				tlsProfileSpec     configv1.TLSProfileSpec
				allowedCurves []tls.CurveID
				schedulerPod corev1.Pod
			)

			BeforeAll(func(ctx context.Context) {
				var err error
				e2efixture.By("getting the current OCP TLS profile")
				minVersion, tlsProfileSpec, err = intls.GetClusterTLSProfile(ctx, e2eclient.Client)
				Expect(err).ToNot(HaveOccurred())
				klog.InfoS("current TLS minimum version", "version", libgocrypto.TLSVersionToNameOrDie(minVersion))			
				allowedCurves = intls.CurveIDsFromProfile(tlsProfileSpec)
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
				schedulerPod = pods[0]				
					
			})
				It("[test_id:90743] should reject TLS connections that are not compatible with the profile - negative test", func(ctx context.Context) {

					belowMinVersion, err := intls.TLSVersionBelow(minVersion)
					Expect(err).ToNot(HaveOccurred(), "failed to get TLS version below %s", libgocrypto.TLSVersionToNameOrDie(minVersion))
					By(fmt.Sprintf("verifying that TLS connections at version %s are rejected by the server", tls.VersionName(belowMinVersion)))
					err = intls.ProbeMaxTLSVersion(e2eclient.K8sClient, &schedulerPod, schedulerSecurePort, belowMinVersion)
					Expect(err).To(HaveOccurred(), "scheduler server should reject TLS connections capped at %s", tls.VersionName(belowMinVersion))
					Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(),
						"expected TLS handshake rejection, got: %v", err)
					if minVersion == tls.VersionTLS13 {
						By("skipping disallowed-cipher probe: TLS 1.3 ciphers are not individually configurable")
						return
					}

					disallowedCipher := intls.FindDisallowedCipher(tlsProfileSpec.Ciphers)
					if disallowedCipher == "" {
						Skip("all known TLS 1.2 ciphers are in the allowed set, nothing to test")
					}
					By(fmt.Sprintf("verifying that TLS connections with disallowed cipher %s are rejected by pod %s", disallowedCipher, schedulerPod.Name))
					err = intls.ProbeTLSCipher(e2eclient.K8sClient, &schedulerPod, schedulerSecurePort, disallowedCipher)
					Expect(err).To(HaveOccurred(), "scheduler server should reject connections with disallowed cipher %s", disallowedCipher)
					Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(), "expected TLS handshake rejection for cipher %s, got: %v", disallowedCipher, err)
				})

				It("[test_id:90744] should adhere to openshift TLS profile - positive test", func(ctx context.Context) {

					By("probing the scheduler HTTPS endpoint to verify TLS connection is accepted")
					state, err := intls.ProbeTLSState(e2eclient.K8sClient, &schedulerPod, schedulerSecurePort)
					Expect(err).ToNot(HaveOccurred())
					gotVersionName := tls.VersionName(state.Version)
					gotCipherName := tls.CipherSuiteName(state.CipherSuite)
					klog.InfoS("negotiated TLS settings", "version", gotVersionName, "cipher", gotCipherName)

					Expect(state.Version).To(BeNumerically(">=", minVersion), "negotiated TLS version %s is below the expected minimum %s", gotVersionName, libgocrypto.TLSVersionToNameOrDie(minVersion))

					// TLS 1.3 cipher suites are not configurable and won't appear in
					// the profile's list; only validate for TLS 1.2 and below.
					allowedCipherNames := libgocrypto.OpenSSLToIANACipherSuites(tlsProfileSpec.Ciphers)
					if state.Version < tls.VersionTLS13 {
						Expect(gotCipherName).ToNot(BeEmpty(), "could not resolve negotiated cipher suite ID 0x%04x", state.CipherSuite)
						Expect(allowedCipherNames).To(ContainElement(gotCipherName), "negotiated cipher %s is not in the allowed set %v", gotCipherName, tlsProfileSpec.Ciphers)
					}
				})
			
			It("[test_id:TBD] should negotiate a curve allowed by the cluster TLS profile", Label("curve"), func(ctx context.Context) {
				if len(allowedCurves) == 0 {
					Skip("Profile defines no groups; Go defaults are used")
				}
				By("probing the scheduler HTTPS endpoint and reading the negotiated curve")
				state, err := intls.ProbeTLSState(e2eclient.K8sClient, &schedulerPod, schedulerSecurePort)
				Expect(err).ToNot(HaveOccurred(), "TLS handshake failed on scheduler pod %q", schedulerPod.Name)
				klog.InfoS("negotiated TLS Settings", "pod", schedulerPod.Name, "version", tls.VersionName(state.Version),
					"cipher", tls.CipherSuiteName(state.CipherSuite), "curve", state.CurveID.String())
				if state.CurveID == 0 {
					Skip("the negotiated cipher suite did not use ECDHE; curve preferences do not apply")
				}
				Expect(allowedCurves).To(ContainElement(state.CurveID),
					"negotiated curve %s (id %d) is not allowed by profile groups %v; check --tls-curve-preferences on the scheduler deployment",state.CurveID, uint16(state.CurveID), tlsProfileSpec.Groups)
				
			})
			It("[test_id:TBD] should reject handshake when client offers only a disallowed curve", Label("curve"), func(ctx context.Context) {
				if len(allowedCurves) == 0 {
					Skip("Profile defines no groups; Go defaults are used")
				}
				disallowed, err := intls.FindDisallowedCurve(allowedCurves)
				if err != nil {
					Skip(err.Error())
				}
				klog.InfoS("probing with a disallowed curve",
					"curve", disallowed.String(), "id", uint16(disallowed), "allowed", allowedCurves)
				state, err := intls.ProbeTLSCurve(e2eclient.K8sClient, &schedulerPod, schedulerSecurePort, disallowed)
				Expect(err).To(HaveOccurred(),"scheduler accepted curve %s (id %d) which the profile does not allow; negotiated=%s",
					disallowed, uint16(disallowed), state.CurveID)
				Expect(errors.Is(err, intls.ErrTLSServerRejected)).To(BeTrue(),"expected scheduler to enforce its curve list, got:%v", err)
			})
	})
	Context("[tlscompliance][rte] rte complies with TLS Profile modifications", Label(label.Tier0, "feature:tlscompliance"), func() {
		const (
			rteDaemonSetCheckTimeout  = 30 * time.Second
			rteDaemonSetCheckInterval = 5 * time.Second
		)
		It("[test_id:88380] should have RTE DaemonSet args aligned with the cluster TLS profile", func(ctx context.Context) {
			By("Verifying RTE DaemonSet TLS flags match the cluster TLS profile")
			Eventually(func() error {
				return intls.CheckRTEDaemonSetTLSFlagsMatchClusterProfile(ctx, e2eclient.Client)
			}).WithTimeout(rteDaemonSetCheckTimeout).WithPolling(rteDaemonSetCheckInterval).Should(Succeed())
		})

		Context("RTE Metrics end point TLS Compliance", Ordered, func() {
			const rteMetricsPort = "2112"
			var (
				minVersion       uint16
				tlsProfileSpec      configv1.TLSProfileSpec
				rtePods          []corev1.Pod
				disallowedCipher string
				allowedCurves []tls.CurveID
			)
			BeforeAll(func(ctx context.Context) {
				var err error
				minVersion, tlsProfileSpec, err = intls.GetClusterTLSProfile(ctx, e2eclient.Client)
				Expect(err).ToNot(HaveOccurred())
				allowedCurves = intls.CurveIDsFromProfile(tlsProfileSpec)
				rtePods = getRTEPodsFromNRO(ctx)
				disallowedCipher = intls.FindDisallowedCipher(tlsProfileSpec.Ciphers)
				if disallowedCipher != "" {
					e2efixture.By("selected disallowed cipher for negative tests: %s", disallowedCipher)
				}
			})

			It("[test_id:88381] should service metrics over TLS adhering to cluster profile", func(ctx context.Context) {
				for _, rtePod := range rtePods {
					By("Verifying TLS Handshake succeeds and negotiated version meets the cluster profile")
					// fetch TLS Version and the cipher supported by TLS version
					state, err := intls.ProbeTLSState(e2eclient.K8sClient, &rtePod, rteMetricsPort)
					Expect(err).ToNot(HaveOccurred(), "TLS Handshake failed on pod %q", rtePod.Name)
					klog.InfoS("negotiated TLS settings",
						"version", tls.VersionName(state.Version),
						"cipher", tls.CipherSuiteName(state.CipherSuite))

					Expect(state.Version).To(BeNumerically(">=", minVersion),
						"negotiated version %s below minimum %s",
						tls.VersionName(state.Version), tls.VersionName(minVersion))

					By("Fetching /metrics over TLS via port-fortward")
					body, err := intls.FetchMetrics(e2eclient.K8sClient, &rtePod, rteMetricsPort)
					Expect(err).ToNot(HaveOccurred(), "failed to fetch metrics from pod %q", rtePod.Name)

					Expect(body).ToNot(BeEmpty(), "metrics response body should not be empty")
					Expect(string(body)).To(ContainSubstring("rte_noderesourcetopology_writes_total"))
				}
			})

			It("[test_id:88382] should reject TLS connections incompatible with the cluster profile", func() {
				belowMinVersion, err := intls.TLSVersionBelow(minVersion)
				Expect(err).ToNot(HaveOccurred(), "cannot determine version below %s", tls.VersionName(minVersion))
				e2efixture.By("verifying TLS %s is rejected on each RTE pod", tls.VersionName(belowMinVersion))
				for _, rtePod := range rtePods {
					err = intls.ProbeMaxTLSVersion(e2eclient.K8sClient, &rtePod, rteMetricsPort, belowMinVersion)
					Expect(err).To(HaveOccurred(), "pod %q should reject TLS %s", rtePod.Name, tls.VersionName(belowMinVersion))
					Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(), "pod %q: got: %v", rtePod.Name, err)
				}
				if minVersion == tls.VersionTLS13 {
					Skip("TLS 1.3 ciphers are not individually configurable, skipping cipher rejection test")
				}

				if disallowedCipher == "" {
					Skip("all known TLS 1.2 ciphers are in the allowed set, nothing to test")
				}
				e2efixture.By("verifying disallowed cipher %s is rejected on each RTE pod", disallowedCipher)
				for _, rtePod := range rtePods {
					e2efixture.By("probing pod %s/%s with disallowed cipher %s", rtePod.Namespace, rtePod.Name, disallowedCipher)
					err = intls.ProbeTLSCipher(e2eclient.K8sClient, &rtePod, rteMetricsPort, disallowedCipher)
					Expect(err).To(HaveOccurred(), "pod %q should reject cipher %s", rtePod.Name, disallowedCipher)
					Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(),
						"pod %q cipher %s: expected TLS handshake rejection, got: %v", rtePod.Name, disallowedCipher, err)
					klog.InfoS("disallowed cipher rejected as expected", "pod", rtePod.Name, "cipher", disallowedCipher)
				}
			})
			It("[test_id:TBD] should negotiate a curve allowed by the cluster profile on every RTE pod", Label("curve"), func(ctx context.Context) {
				if len(allowedCurves) == 0 {
					Skip("profile defineds no groups; Go defaults are used")
				}
				verified := 0
				for _, rtePod := range rtePods {
					state, err := intls.ProbeTLSState(e2eclient.K8sClient, &rtePod, rteMetricsPort)
					Expect(err).ToNot(HaveOccurred(), "pod %q failed TLS handshake on port %s", rtePod.Name, rteMetricsPort)
					klog.InfoS("negotiated TLS Settings",
						"pod", rtePod.Name,
						"version", tls.VersionName(state.Version),
						"cipher", tls.CipherSuiteName(state.CipherSuite),
						"curve", state.CurveID.String())
					
					if state.CurveID == 0 {
						klog.InfoS("no curve negotiated (non-ECDHE cipher)", "pod", rtePod.Name)
						continue
					}
					verified++
					Expect(allowedCurves).To(ContainElement(state.CurveID),
						"pod %q negotiated curve %v (%s) which is not allowed by profile groups %v",
						rtePod.Name, state.CurveID, state.CurveID.String(), tlsProfileSpec.Groups)
				}
				if verified == 0 {
					Skip("no RTE pod negotiated an ECDHE curve; curve preferences cannot be verified")
				}
			})
			It("[test_id: TBD] should reject a curve disallowed by the cluster profile on every RTE pod", Label("curve"), func(ctx context.Context) {
				if len(allowedCurves) == 0 {
					Skip("profile defineds no groups; Go defaults are used")
				}
				disallowed, err := intls.FindDisallowedCurve(allowedCurves)
				if err != nil {
					Skip(fmt.Sprintf("cannot find a disallowed curve: %v", err))
				}
				klog.InfoS("probing with disallowed curve:", "curve", disallowed.String(), "id", uint16(disallowed), "allowed", allowedCurves)

				for _, rtePod := range rtePods {
					state, err := intls.ProbeTLSCurve(e2eclient.K8sClient, &rtePod, rteMetricsPort, disallowed)
					Expect(err).To(HaveOccurred(),"pod %q unexpectedly accepted disallowed curve %s (id %d); negotiated %s",
						rtePod.Name, disallowed, uint16(disallowed), state.CurveID)
					Expect(errors.Is(err, intls.ErrTLSServerRejected)).To(BeTrue(),
						"pod %q: expected RTE server to enforce its curve list, got: %v", rtePod.Name, err)
				}
			})
		})
		Context("[tlscompliance][operator] operator metrics complies with TLS Profile modifications", Label(label.Tier0, "feature:tlscompliance"), Ordered, func() {
			var (
				minVersion       uint16
				tlsProfileSpec      configv1.TLSProfileSpec
				operatorPod         *corev1.Pod
				allowedCurves []tls.CurveID
			)			
			BeforeAll(func(ctx context.Context) {
				var err error
				minVersion, tlsProfileSpec, err = intls.GetClusterTLSProfile(ctx, e2eclient.Client)
				Expect(err).ToNot(HaveOccurred())
				allowedCurves = intls.CurveIDsFromProfile(tlsProfileSpec)
				nropObj := &nropv1.NUMAResourcesOperator{}
				Expect(e2eclient.Client.Get(ctx, objects.NROObjectKey(), nropObj)).To(Succeed())
				Eventually(func() error {
					var err error
					operatorPod, err = deploy.FindNUMAResourcesOperatorPod(ctx, e2eclient.Client, nropObj)
					return err
				}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())				
			})
			It("[test_id:TBD] should adhere to Openshift TLS profile", Label("opcurve"), func(ctx context.Context) {
				By("probing the scheduler HTTPS endpoint to verify TLS connection is accepted")
				state, err := intls.ProbeTLSState(e2eclient.K8sClient, operatorPod, operatorMetricsPort)
				Expect(err).ToNot(HaveOccurred())
				gotVersionName := tls.VersionName(state.Version)
				gotCipherName := tls.CipherSuiteName(state.CipherSuite)
				klog.InfoS("negotiated TLS settings", "version", gotVersionName, "cipher", gotCipherName)
				Expect(state.Version).To(BeNumerically(">=", minVersion), "negotiated TLS version %s is below the expected minimum %s", gotVersionName, libgocrypto.TLSVersionToNameOrDie(minVersion))

				// TLS 1.3 cipher suites are not configurable and won't appear in
				// the profile's list; only validate for TLS 1.2 and below.
				allowedCipherNames := libgocrypto.OpenSSLToIANACipherSuites(tlsProfileSpec.Ciphers)
				if state.Version < tls.VersionTLS13 {
					Expect(gotCipherName).ToNot(BeEmpty(), "could not resolve negotiated cipher suite ID 0x%04x", state.CipherSuite)
					Expect(allowedCipherNames).To(ContainElement(gotCipherName), "negotiated cipher %s is not in the allowed set %v", gotCipherName, tlsProfileSpec.Ciphers)
				}
			})
			It("[test_id:90743] should reject TLS connections that are not compatible with the profile - negative test", Label("opcurve"), func(ctx context.Context) {
				belowMinVersion, err := intls.TLSVersionBelow(minVersion)
				Expect(err).ToNot(HaveOccurred(), "failed to get TLS version below %s", libgocrypto.TLSVersionToNameOrDie(minVersion))
				By(fmt.Sprintf("verifying that TLS connections at version %s are rejected by the server", tls.VersionName(belowMinVersion)))
				err = intls.ProbeMaxTLSVersion(e2eclient.K8sClient, operatorPod, operatorMetricsPort, belowMinVersion)
				Expect(err).To(HaveOccurred(), "Operator pod should reject TLS connections capped at %s", tls.VersionName(belowMinVersion))
				Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(),
					"expected TLS handshake rejection, got: %v", err)
				if minVersion == tls.VersionTLS13 {
					By("skipping disallowed-cipher probe: TLS 1.3 ciphers are not individually configurable")
					return
				}

				disallowedCipher := intls.FindDisallowedCipher(tlsProfileSpec.Ciphers)
				if disallowedCipher == "" {
					Skip("all known TLS 1.2 ciphers are in the allowed set, nothing to test")
				}
				By(fmt.Sprintf("verifying that TLS connections with disallowed cipher %s are rejected by pod %s", disallowedCipher, operatorPod.Name))
				err = intls.ProbeTLSCipher(e2eclient.K8sClient, operatorPod, operatorMetricsPort, disallowedCipher)
				Expect(err).To(HaveOccurred(), "scheduler server should reject connections with disallowed cipher %s", disallowedCipher)
				Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(), "expected TLS handshake rejection for cipher %s, got: %v", disallowedCipher, err)			
			})
			It("[test_id:TBD] should negotiate a curve allowed by the cluster TLS profile", Label("opcurve"), func(ctx context.Context) {
				if len(allowedCurves) == 0 {
					Skip("Profile defines no groups; Go defaults are used")
				}
				By("probing the scheduler HTTPS endpoint and reading the negotiated curve")
				state, err := intls.ProbeTLSState(e2eclient.K8sClient, operatorPod, operatorMetricsPort)
				Expect(err).ToNot(HaveOccurred(), "TLS handshake failed on scheduler pod %q", operatorPod.Name)
				klog.InfoS("negotiated TLS Settings", "pod", operatorPod.Name, "version", tls.VersionName(state.Version),
					"cipher", tls.CipherSuiteName(state.CipherSuite), "curve", state.CurveID.String())
				if state.CurveID == 0 {
					Skip("the negotiated cipher suite did not use ECDHE; curve preferences do not apply")
				}
				Expect(allowedCurves).To(ContainElement(state.CurveID),
					"negotiated curve %s (id %d) is not allowed by profile groups %v; check --tls-curve-preferences on the scheduler deployment",state.CurveID, uint16(state.CurveID), tlsProfileSpec.Groups)
				
			})
			It("[test_id:TBD] should reject handshake when client offers only a disallowed curve", Label("opcurve"), func(ctx context.Context) {
				if len(allowedCurves) == 0 {
					Skip("Profile defines no groups; Go defaults are used")
				}
				disallowed, err := intls.FindDisallowedCurve(allowedCurves)
				if err != nil {
					Skip(err.Error())
				}
				klog.InfoS("probing with a disallowed curve",
					"curve", disallowed.String(), "id", uint16(disallowed), "allowed", allowedCurves)
				state, err := intls.ProbeTLSCurve(e2eclient.K8sClient, operatorPod, operatorMetricsPort, disallowed)
				Expect(err).To(HaveOccurred(),"scheduler accepted curve %s (id %d) which the profile does not allow; negotiated=%s",
					disallowed, uint16(disallowed), state.CurveID)
				Expect(errors.Is(err, intls.ErrTLSServerRejected)).To(BeTrue(),"expected scheduler to enforce its curve list, got:%v", err)
			})			
		})
	})
})


func getRTEPodsFromNRO(ctx context.Context) []corev1.Pod {
	GinkgoHelper()
	nropObj := &nropv1.NUMAResourcesOperator{}
	nropKey := client.ObjectKey{Name: objectnames.DefaultNUMAResourcesOperatorCrName}
	Expect(e2eclient.Client.Get(ctx, nropKey, nropObj)).To(Succeed(), "failed to get NRO %q in the cluster", nropKey.Name)
	Expect(nropObj.Status.NodeGroups).ToNot(BeEmpty(), "NRO %q must have at least one NodeGroup", nropKey.Name)
	var rtePods []corev1.Pod
	for _, nodeGroup := range nropObj.Status.NodeGroups {
		daemonSet := &appsv1.DaemonSet{}
		dsKey := client.ObjectKey{
			Namespace: nodeGroup.DaemonSet.Namespace,
			Name:      nodeGroup.DaemonSet.Name,
		}
		Expect(e2eclient.Client.Get(ctx, dsKey, daemonSet)).To(Succeed(), "failed to get RTE DaemonSet %s/%s", dsKey.Namespace, dsKey.Name)
		pods, err := podlist.With(e2eclient.Client).ByDaemonset(ctx, *daemonSet)
		Expect(err).ToNot(HaveOccurred(), "failed to list pods for RTE DaemonSet %s/%s", dsKey.Namespace, dsKey.Name)
		Expect(pods).ToNot(BeEmpty(), "expected at least one RTE pod from Daemonset %s/%s", dsKey.Namespace, dsKey.Name)
		rtePods = append(rtePods, pods...)
	}
	Expect(rtePods).ToNot(BeEmpty(), "expected at least one RTE Pod from NRO managed Daemonsets")
	return rtePods
}
