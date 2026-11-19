package tls

import (
	"context"
	"crypto/tls"
	"k8s.io/klog/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	e2eclient "github.com/openshift-kni/numaresources-operator/test/internal/clients"
	intls "github.com/openshift-kni/numaresources-operator/test/internal/tls"
	ctrltls "github.com/openshift/controller-runtime-common/pkg/tls"
	objtls "github.com/openshift-kni/numaresources-operator/pkg/objectupdate/tls"
)

var _= Describe("TLS", func() {
	It("derives expected tls settings from the cluster profile", Label("tls"), func(ctx context.Context) {
		minVersion, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())
		applyProfile, unsupported := ctrltls.NewTLSConfigFromProfile(profileSpec)
		Expect(unsupported).To(BeEmpty())
		cfg := &tls.Config{}
		applyProfile(cfg)
		settings := objtls.NewSettings(cfg)
		Expect(settings.MinVersion).ToNot(BeEmpty())
		Expect(minVersion).To(Equal(cfg.MinVersion))
		klog.InfoS("Cluster TLS settings",
			"minVersion", settings.MinVersion,
			"ciphers", settings.CipherSuites,
			"curves", settings.CurvePreferences)
		
	})
	DescribeTable("formats curve IDs", Label("tls"), func(curves []tls.CurveID, expected string) {
		settings := objtls.NewSettings(&tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: curves,
		})
		Expect(settings.CurvePreferences).To(Equal(expected))
	},
		Entry("classic curves", []tls.CurveID{tls.X25519, tls.CurveP256}, "29,23"),
		Entry("post-quantum hybird", []tls.CurveID{tls.X25519MLKEM768}, "4588"),
		Entry("empty means go defaults", nil, ""),
	)
})
