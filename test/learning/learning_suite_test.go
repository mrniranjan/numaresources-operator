package learning

import (
	"os"
	"testing"

	serialconfig "github.com/openshift-kni/numaresources-operator/test/e2e/serial/config"
	e2eclient "github.com/openshift-kni/numaresources-operator/test/internal/clients"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var setupExecuted = false

func TestLearning(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Learning Suite")
}

var _ = BeforeSuite(func() {
	Expect(e2eclient.ClientsEnabled).To(BeTrue(), "cannot create kubernetes clients")

	//ctx := context.Background()
	serialconfig.DumpEnvironment(os.Stderr)
	//Expect(serialconfig.CheckNodesTopology(ctx)).Should(Succeed())
	serialconfig.Setup()
	setupExecuted = true
})

var _ = AfterSuite(func() {
	if !setupExecuted {
		return
	}
	serialconfig.Teardown()
})
