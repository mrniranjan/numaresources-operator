package learning

import (
	"context"
	"fmt"
	"time"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/klog/v2"

	e2enrtint "github.com/openshift-kni/numaresources-operator/internal/noderesourcetopology"
	e2efixture "github.com/openshift-kni/numaresources-operator/test/internal/fixture"
	nrtv1alpha2 "github.com/k8stopologyawareschedwg/noderesourcetopology-api/pkg/apis/topology/v1alpha2"
    e2enrt "github.com/openshift-kni/numaresources-operator/test/internal/noderesourcetopologies"
	serialconfig "github.com/openshift-kni/numaresources-operator/test/e2e/serial/config"
	"github.com/openshift-kni/numaresources-operator/internal/wait"
	"github.com/openshift-kni/numaresources-operator/test/internal/nrosched"
	"github.com/openshift-kni/numaresources-operator/test/internal/images"
	"github.com/openshift-kni/numaresources-operator/test/internal/objects"
    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

const (
	interferenceAnnotation = "e2e.test.openshift-kni.io/scheduler-interference"
)
type machineDesc struct {
	desiredPodsPerNUMAZone int
	// how many cores (HTs) per CPU?
	coresPerCPU int
	// node resource load (1.0=fully loaded, unachiavable because of infra pods)
	loadFactor float64
}
type interferenceDesc struct {
	// QoS of the inteference pods. Payload pods will always be GU.
	qos corev1.PodQOSClass
	// ratio of interference pods: 1 every Ratio pods will be interference
	ratio int
}

var _ = Describe("[Learning][nrt] Get latest nrt", Serial, func() {
	var nrtList nrtv1alpha2.NodeResourceTopologyList
	var fxt *e2efixture.Fixture
	BeforeEach(func() {
		var err error
		Expect(serialconfig.Config).ToNot(BeNil())
		Expect(serialconfig.Config.Ready()).To(BeTrue(), "NUMA fixture initialization failed")
		
		//fxt, err = e2efixture.Setup("e2e-test-my-feature", nrtv1alpha2.NodeResourceTopologyList{})
		fxt, err = e2efixture.Setup("e2e-test-non-regression-fundamentals", serialconfig.Config.NRTList)
		Expect(err).ToNot(HaveOccurred())
		
		err = fxt.Client.List(context.TODO(), &nrtList)
		Expect(err).ToNot(HaveOccurred())
	})
	AfterEach(func() {
		err := e2efixture.Teardown(fxt)
		Expect(err).ToNot(HaveOccurred())
	})
	Context("learning NRT Updates", func() {
		It("Get latest nrt", func() {
		for k, v := range nrtList.Items {
				fmt.Println("key = ", k, "value = ", v)
			}
		})

		It("Get NRT Candidates", func() {
			var nrtCandidates []nrtv1alpha2.NodeResourceTopology
			nrtCandidates = e2enrt.FilterZoneCountEqual(nrtList.Items, 2)
			fmt.Println("!!!!!!!!!!!!!!!!!!!!!!nrt Candidate Name is :", nrtCandidates[0].ObjectMeta.Name)
			fmt.Println("@@@@@@@@@@@@@@@Length of nrt candidate: ", len(nrtCandidates))
			referenceNode := nrtCandidates[0]
			referenceZone := referenceNode.Zones[0]			
			cpuQty, ok := e2enrt.FindResourceAllocatableByName(referenceZone.Resources, string(corev1.ResourceCPU))
			fmt.Println(cpuQty)
			cpuNum, ok := cpuQty.AsInt64()
			fmt.Println(cpuNum)
			fmt.Println(ok)
			for i, zone := range referenceNode.Zones {
				fmt.Printf("Zone[%d]: %s\n", i, zone.Name)
				for _, res := range zone.Resources {
					fmt.Printf("  %s  Capacity: %s  Allocatable: %s  Available: %s\n",
					res.Name, res.Capacity.String(), res.Allocatable.String(), res.Available.String())
				}
			}
			cpuPerPod := int64(float64(cpuNum) * 0.6)
			memoryPerPod := int64(8 * 1024 * 1024 * 1024) // random non-zero amount
			fmt.Println(cpuPerPod)
			fmt.Println(memoryPerPod)
		})
		DescribeTable("should keep possibly-fitting pod in pending state until overreserve is corrected by update handling interference",
			func(mdesc machineDesc, interference interferenceDesc) {
				hostsRequired := 1
				NUMAZonesRequired := 2
				desiredPods := hostsRequired * NUMAZonesRequired * mdesc.desiredPodsPerNUMAZone
				Expect(desiredPods).To(BeNumerically(">", hostsRequired))
				Expect(interference.ratio).To(BeNumerically("<=", desiredPods)) // this is more like a C assert. Should never ever fail
				By(fmt.Sprintf("filtering available nodes with at least %d NUMA zones", NUMAZonesRequired))
				nrtCandidates := e2enrt.FilterZoneCountEqual(nrtList.Items, NUMAZonesRequired)
				if len(nrtCandidates) < hostsRequired {
					e2efixture.Skipf(fxt, "not enough nodes with %d NUMA Zones: found %d", NUMAZonesRequired, len(nrtCandidates))
				}
				By("computing the pod resources to trigger the test conditions")
				sizerFn := createCpuSizerFn(mdesc)
				podRequiredRes := autoSizePodResources(nrtCandidates, sizerFn)
				tag := podQOSClassToTag(interference.qos)
				By("creating the test pods")
				var zero int64
				testPods := []*corev1.Pod{}
				for seqno := 0; seqno < desiredPods; seqno++ {
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:        fmt.Sprintf("ovrfix-pod-%s-%d", tag, seqno),
							Namespace:   fxt.Namespace.Name,
							Annotations: map[string]string{},
						},
						Spec: corev1.PodSpec{
							TerminationGracePeriodSeconds: &zero,
							Containers: []corev1.Container{
								{
									Name:    fmt.Sprintf("ovrfix-cnt-%s-0", tag),
									Image:   images.GetPauseImage(),
									Command: []string{images.PauseCommand},
								},
							},
						},
					}
					if (seqno % interference.ratio) == 0 {
							pod.Annotations[interferenceAnnotation] = "true"
							if interference.qos == corev1.PodQOSGuaranteed {
								pod.Spec.Containers[0].Resources.Limits = podRequiredRes
							} else {
								pod.Spec.Containers[0].Resources.Requests = podRequiredRes
							}
							klog.InfoS("pod -> interference", "name", pod.Name)
						} else {
							pod.Spec.SchedulerName = serialconfig.Config.SchedulerName
							pod.Spec.Containers[0].Resources.Limits = podRequiredRes
							klog.InfoS("pod -> payload", "name", pod.Name)
						}
						testPods = append(testPods, pod)
				}
				ctx := context.Background()
				for _, testPod := range testPods {
					err := fxt.Client.Create(ctx, testPod)
					Expect(err).ToNot(HaveOccurred())
				}
				// note the cleanup is done automatically once the ns on which we run is deleted - the fixture takes care
				By("waiting for the test pods to go running")
				// even more generous timeout here. We need to tolerate more reconciliation time because of the interference
				startTime := time.Now()
				failedPods, updatedPods := wait.With(fxt.Client).Interval(5*time.Second).Timeout(5*time.Minute).ForPodsAllRunning(ctx, testPods)
				dumpFailedPodInfo(fxt, failedPods)
				elapsed := time.Since(startTime)
				klog.InfoS("test pods (payload + interference) gone running", "elapsed", elapsed)
				Expect(failedPods).To(BeEmpty(), "unexpected failed pods: %q", accumulatePodNamespacedNames(failedPods))

				By("checking the test pods once running")
				for _, updatedPod := range updatedPods {
					if isInterferencePod(updatedPod) {
						continue
					}
					schedOK, err := nrosched.CheckPODWasScheduledWith(ctx, fxt.K8sClient, updatedPod.Namespace, updatedPod.Name, serialconfig.Config.SchedulerName)
					Expect(err).ToNot(HaveOccurred())
					Expect(schedOK).To(BeTrue(), "pod %s/%s not scheduled with expected scheduler %s", updatedPod.Namespace, updatedPod.Name, serialconfig.Config.SchedulerName)
				}
			},
			Entry("[test_id:85787] from GU pods, low", Label("qos:gu"), machineDesc{coresPerCPU: 2, desiredPodsPerNUMAZone: 2, loadFactor: 0.6}, interferenceDesc{ ratio: 2, qos: corev1.PodQOSGuaranteed}),
			Entry("[test_id:85788] from BU pods, moderate", Label("qos:bu"), machineDesc{coresPerCPU: 2, desiredPodsPerNUMAZone: 4, loadFactor: 0.6}, interferenceDesc{ ratio: 5, qos: corev1.PodQOSBurstable}),
		)
			
	})
})
	
func createCpuSizerFn(mdesc machineDesc) func(int64) int64 {
	return func(cpuNum int64) int64 {
		physCPUs := cpuNum / int64(mdesc.coresPerCPU)
		totalCPUs := physCPUs / int64(mdesc.desiredPodsPerNUMAZone)
		return int64(float64(totalCPUs)*mdesc.loadFactor)*int64(mdesc.coresPerCPU)
	}
}

func autoSizePodResources(nrtCandidates []nrtv1alpha2.NodeResourceTopology, sizer  func(int64) int64) corev1.ResourceList {
	GinkgoHelper()
	referenceNode := nrtCandidates[0]
	referenceZone := referenceNode.Zones[0]
	cpuQty, ok := e2enrt.FindResourceAvailableByName(referenceZone.Resources, string(corev1.ResourceCPU))
	Expect(ok).To(BeTrue(), "no CPU resource in zone %q node %q", referenceZone.Name, referenceNode.Name)

	cpuNum, ok := cpuQty.AsInt64()
	Expect(ok).To(BeTrue(), "invalid CPU resource in zone %q node %q: %v", referenceZone.Name, referenceNode.Name, cpuQty)
	cpuPerPod := sizer(cpuNum)
	memoryPerPod := int64(8 * 1024 * 1024 * 1024)
	podRequiredRes := corev1.ResourceList{
		corev1.ResourceMemory: *resource.NewQuantity(memoryPerPod, resource.BinarySI),
		corev1.ResourceCPU:    *resource.NewQuantity(cpuPerPod, resource.DecimalSI),
	}
	return podRequiredRes
}

func podQOSClassToTag(qos corev1.PodQOSClass) string {
	switch qos {
	case corev1.PodQOSGuaranteed:
		return "gu"
	case corev1.PodQOSBurstable:
		return "bu"
	case corev1.PodQOSBestEffort:
		return "be"
	}
	return ""
}
func dumpFailedPodInfo(fxt *e2efixture.Fixture, failedPods []*corev1.Pod) {
	if len(failedPods) == 0 {
		return // not much to do here
	}
	nrtListFailed, _ := e2enrt.GetUpdated(fxt.Client, nrtv1alpha2.NodeResourceTopologyList{}, time.Minute)
	klog.InfoS("NRT list", "content", e2enrtint.ListToString(nrtListFailed.Items, "post failure"))

	for _, failedPod := range failedPods {
		_ = objects.LogEventsForPod(fxt.K8sClient, failedPod.Namespace, failedPod.Name)
	}
}
func isInterferencePod(pod *corev1.Pod) bool {
	if pod == nil || pod.Annotations == nil {
		return false
	}
	return pod.Annotations[interferenceAnnotation] == "true"
}

func accumulatePodNamespacedNames(pods []*corev1.Pod) string {
	podNames := []string{}
	for _, pod := range pods {
		podNames = append(podNames, pod.Namespace+"/"+pod.Name)
	}
	return strings.Join(podNames, ",")
}
