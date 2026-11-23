# NROP E2E Testing and TLS Curves: A Newcomer's Guide

This guide is for someone who has never worked on NUMA Resources Operator
(NROP) test automation and needs to add end-to-end coverage for TLS curve
(group) preferences. It explains the test suites, the Ginkgo patterns used in
this repository, how TLS curves flow through NROP, which functions implement
that flow, what the current tests cover, and what tests are still missing.

The guide was verified against commit `6b76dcedb` on branch `tls_learning`.
Paths such as `@test/serial` in informal discussion map to the real repository
path `test/e2e/serial`.

If you are new to NROP automation and need to write the code, start with
[`nrop_tls_curves_automation.md`](nrop_tls_curves_automation.md). It provides a
first-week onboarding path, explains every TLS curve function line by line in
plain English, and gives copy-paste unit, non-disruptive E2E, and serial E2E
examples.

### Requested-topic map

| Requested topic | Where it is covered |
|---|---|
| How to write NROP E2E test cases | Section 3 |
| Many example programs | Sections 3, 9, and 10 |
| How TLS works in NROP | Section 4 |
| How TLS curve support was added | Section 4.6 |
| Every function related to TLS curves | Section 5 |
| How to test those functions using existing tests | Section 6 |
| Missing TLS curve test coverage | Section 7 |
| Test cases to add | Sections 8.1-8.4 |
| Function-by-function automation and onboarding | [`nrop_tls_curves_automation.md`](nrop_tls_curves_automation.md) |
| Detailed E2E curve design with example code | Section 9 |

---

## 1. The one-paragraph mental model

NROP is an OpenShift/Kubernetes operator that deploys RTE (Resource Topology
Exporter), the Node Resource Topology API, and optionally a secondary
NUMA-aware scheduler. At startup the operator reads the cluster-wide TLS
security profile from `apiserver.config.openshift.io/cluster`. It converts the
profile's minimum TLS version, cipher list, and group/curve list into strings,
then writes those strings into operand command-line arguments. The scheduler
receives `--tls-min-version`, `--tls-cipher-suites`, and
`--tls-curve-preferences`; RTE receives the `--metrics-tls-*` equivalents.
E2E tests either inspect those arguments (configuration correctness) or open
real TLS connections to the scheduler/RTE endpoints and inspect the handshake
(runtime correctness).

---

## 2. Repository map for E2E work

| Path | What it contains | When to touch it |
|---|---|---|
| `test/e2e/serial/` | Main serial/disruptive suite. Its `BeforeSuite` creates the NRT fixture and test infrastructure. | Tests that change cluster state, reboot nodes, or mutate `APIServer`/`NUMAResourcesOperator`. |
| `test/e2e/serial/tests/` | Spec files registered by blank import from `test/e2e/serial/e2e_serial_test.go`. | New serial `It()` blocks. TLS profile mutation tests live in `configuration.go`. |
| `test/e2e/tls/` | Lightweight non-disruptive TLS suite. No fixture, no NRT setup. | Read-only TLS handshake and operand-argument checks. |
| `test/e2e/tls/tls_test.go` | Scheduler and RTE TLS compliance specs. | New non-disruptive curve checks. |
| `test/internal/tls/` | Shared TLS helpers used by both suites. | Reusable probes, profile conversion, RTE/scheduler argument checks. |
| `test/e2e/label/label.go` | Shared Ginkgo labels/tiers. | Add `Label(label.Tier0)`, `Label(label.Slow)`, etc. |
| `internal/api/features/_topics.json` | Registered feature topics. | Add a new `feature:<name>` topic. `tlscompliance` already exists. |
| `pkg/objectupdate/tls/` | `Settings` value type and `NewSettings` conversion. | Curve IDs are formatted here. |
| `pkg/objectupdate/rte/` | Writes RTE DaemonSet arguments. | `DaemonSetArgs` sets/deletes `--metrics-tls-curve-preferences`. |
| `pkg/objectupdate/sched/` | Writes scheduler Deployment arguments. | `DeploymentTLSSettings` sets/deletes `--tls-curve-preferences`. |

The E2E suites deliberately differ:

- `test/e2e/tls` is **non-disruptive**. It assumes NROP is installed and only
  reads cluster state or opens port-forwarded TLS connections.
- `test/e2e/serial` is **disruptive**. It owns the cluster for the duration of
  each spec and must restore anything it changes. A TLS profile change causes
  MachineConfigPool rollouts and node reboots.

---

## 3. How to write an NROP E2E test

### 3.1 Ginkgo and Gomega in one page

NROP uses Ginkgo v2 for structure and Gomega for assertions.

- `Describe`, `Context`, `It`, `BeforeEach`, `AfterEach`, `BeforeSuite`,
  `AfterSuite` structure the suite.
- `By("...")` documents progress in test output. In serial tests, prefer
  `e2efixture.By(...)` when the fixture supports it.
- `Expect(actual).To(matcher)` asserts. `Eventually(func() ...)` retries
  asynchronous cluster reconciliation.
- `Skip(...)` is appropriate when a cluster precondition is absent (for
  example, a feature gate is disabled or no suitable curve exists).
- `Label(...)` is the current way to tag tests. Bracket tags in the title are
  legacy and should not be used for new tests.

Every spec must have a tier label. TLS compliance uses
`Label("feature:tlscompliance")`; that topic already exists in
`internal/api/features/_topics.json`.

### 3.2 Minimal non-disruptive suite

This mirrors `test/e2e/tls/tls_suite_test.go`:

```go
package tls

import (
	"testing"

	e2eclient "github.com/openshift-kni/numaresources-operator/test/internal/clients"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTLS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS")
}

var _ = BeforeSuite(func() {
	Expect(e2eclient.ClientsEnabled).To(BeTrue(), "failed to create runtime-controller client")
})
```

This suite needs no `serialconfig.Config`, no fixture, and no NRT data. It is
the right home for read-only TLS checks.

### 3.3 Minimal non-disruptive spec

This test fetches the active profile and derives the same expected settings
the operator derives. It does not mutate anything.

```go
var _ = Describe("TLS", func() {
	It("[test_id:TBD] derives expected TLS settings from the cluster profile",
		Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
			minVersion, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
			Expect(err).ToNot(HaveOccurred())

			applyProfile, unsupported := ctrltls.NewTLSConfigFromProfile(profileSpec)
			Expect(unsupported).To(BeEmpty())

			cfg := &tls.Config{}
			applyProfile(cfg)
			settings := objtls.NewSettings(cfg)

			Expect(settings.MinVersion).ToNot(BeEmpty())
			Expect(minVersion).To(Equal(cfg.MinVersion))
			klog.InfoS("cluster TLS settings",
				"minVersion", settings.MinVersion,
				"ciphers", settings.CipherSuites,
				"curves", settings.CurvePreferences)
		})
})
```

### 3.4 Minimal serial suite pattern

Serial specs live in `test/e2e/serial/tests/`. The suite entry point is
`test/e2e/serial/e2e_serial_test.go`; spec files are loaded by blank import:

```go
import (
	_ "github.com/openshift-kni/numaresources-operator/test/e2e/serial/tests"
	_ "github.com/openshift-kni/numaresources-operator/test/internal/configuration"
)
```

The suite `BeforeSuite` validates clients, checks the node topology, and calls
`serialconfig.Setup()`. `serialconfig.Config` then contains the shared fixture,
NRO objects, scheduler object, and NRT reference data.

A serial spec typically owns a per-spec fixture and cleans it up:

```go
var _ = Describe("[serial][disruptive] example",
	Serial,
	Label("disruptive"),
	Label("feature:tlscompliance"), func() {
		var fxt *e2efixture.Fixture

		BeforeEach(func() {
			Expect(serialconfig.Config).ToNot(BeNil())
			Expect(serialconfig.Config.Ready()).To(BeTrue(), "NUMA fixture initialization failed")

			var err error
			fxt, err = e2efixture.Setup("e2e-test-example", serialconfig.Config.NRTList)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			Expect(e2efixture.Teardown(fxt)).To(Succeed())
		})

		It("[test_id:TBD] mutates and restores something",
			Label(label.Tier2, label.Slow, label.Reboot), func(ctx context.Context) {
				fxt.IsRebootTest = true
				// Save original state, register DeferCleanup, mutate, wait, verify.
			})
	})
```

For read-only serial checks, `serialconfig.Config.Fixture.Client` can be used
instead of creating another fixture. For tests that create workloads, follow
the existing `e2efixture.Setup` / `Teardown` pattern in
`configuration.go` and `workload_placement.go`.

### 3.5 Parameterized tests

Use `DescribeTable` when the same flow must run with different profiles,
curves, or operands:

```go
DescribeTable("formats curve IDs",
	Label(label.Tier0),
	func(curves []tls.CurveID, expected string) {
		settings := objtls.NewSettings(&tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: curves,
		})
		Expect(settings.CurvePreferences).To(Equal(expected))
	},
	Entry("classic curves", []tls.CurveID{tls.X25519, tls.CurveP256}, "29,23"),
	Entry("post-quantum hybrid", []tls.CurveID{tls.X25519MLKEM768}, "4588"),
	Entry("empty means Go defaults", nil, ""),
)
```

### 3.6 Unit-testing helpers with a fake client

`test/internal/tls/tls_test.go` demonstrates the pattern used for
`CheckRTEDaemonSetTLSFlags`:

```go
func TestCurveFlagIsChecked(t *testing.T) {
	nro := newNROP(nropv1.NodeGroupStatus{
		DaemonSet: nropv1.NamespacedName{Namespace: "test-ns", Name: "rte-ds"},
	})
	ds := newRTEDaemonSetWithMainContainerArgs(
		"test-ns", "rte-ds",
		"--metrics-tls-min-version=VersionTLS12",
		"--metrics-tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"--metrics-tls-curve-preferences=29,23,24",
	)

	cli := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(nro, ds).
		Build()

	err := CheckRTEDaemonSetTLSFlags(context.Background(), cli, objtls.Settings{
		MinVersion:       "VersionTLS12",
		CipherSuites:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		CurvePreferences: "29,23,24",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

The fake client is enough because the helper only reads a
`NUMAResourcesOperator` and its referenced `DaemonSet`s.

### 3.7 Running the tests

Prefer Makefile targets:

```bash
make help
make test-unit
make test-controllers
make build-e2e-tls
make binary-e2e-serial
```

Build and run the non-disruptive TLS suite directly:

```bash
bin/e2e-nrop-tls.test \
  --ginkgo.v \
  --ginkgo.label-filter='feature:tlscompliance'
```

Run the serial suite through the repo runner (the next subsection covers the
curve-specific selectors):

```bash
hack/run-test-serial-e2e.sh --focus '88383' --verbose
```

`hack/run-test-serial-e2e.sh` assumes an already configured TAS-enabled
cluster unless `--setup`/`--teardown` are supplied. Do not run the serial
suite on a shared cluster: its tests expect exclusive access.

#### Running only the serial TLS curve spec

The curve spec lives in `test/e2e/serial/tests/configuration.go` and has this
full Ginkgo text path (Ginkgo focus is a regex over the concatenated path):

```
[serial][disruptive] numaresources configuration management
  [tlscompliance]RTE and scheduler comply with restricted TLS profile modifications
    [test_id: TBD] should reconcile restricted and empty TLS curve arguments for both operands
```

Its decorators are `[Serial, disruptive, feature:config, curve]`. There is no
`tier*`, `slow`, `reboot_required` or `feature:tlscompliance` label, so
`--ginkgo.label-filter='feature:tlscompliance'` does **not** select it (that
filter matches only `[test_id:88383]`). Use `curve` instead.

Build the binary once (writes `bin/e2e-nrop-serial.test`):

```bash
make binary-e2e-serial
```

That target is a compile-only step, not a test run. It expands to
`CGO_ENABLED=0 go test -c -o bin/e2e-nrop-serial.test ./test/e2e/serial` and
depends on `generate-source`, which refreshes `pkg/version/_buildinfo.json`
(embedded into the binary with `//go:embed`). It matters because:

- `hack/run-test-serial-e2e.sh` and the CI runner hardcode
  `${BIN_DIR}/e2e-nrop-serial.test`; there is no separate `go test` path there.
- Compiling once lets you run several focused selections against the same
  cluster without paying the build cost each time.
- The `[test_id:85791]` version spec compares the embedded build info against
  the cluster, so a stale `_buildinfo.json` gives misleading output.
- `CGO_ENABLED=0` produces the same static binary CI uses.

If you prefer, `go test ./test/e2e/serial -args -ginkgo.focus='...'` is
equivalent but recompiles, does not refresh `_buildinfo.json`, and is not what
the runners execute.

Then pick any one of these three equivalent selectors. All three were verified
with `--ginkgo.dry-run` to select exactly 1 of 161 specs:

```bash
# by spec text (simplest, no escaping problems)
bin/e2e-nrop-serial.test \
  --ginkgo.focus='restricted TLS profile modifications' \
  --ginkgo.v --ginkgo.timeout=5h

# by label (the curve Context carries Label("curve"))
bin/e2e-nrop-serial.test \
  --ginkgo.label-filter='curve' \
  --ginkgo.v --ginkgo.timeout=5h

# by source location (Ginkgo >= 2.10; this repo vendors v2.28.1)
bin/e2e-nrop-serial.test \
  --ginkgo.focus-file='test/e2e/serial/tests/configuration.go:1891' \
  --ginkgo.v --ginkgo.timeout=5h
```

Or through the repo runner, which adds the JUnit report and the 5h timeout:

```bash
hack/run-test-serial-e2e.sh --focus 'restricted TLS profile modifications' --verbose
```

`--focus`/`--skip`/`--label-filter` set in the runner are the same Ginkgo v2
flags; `--tier-up-to N` expands to `--ginkgo.label-filter='tier0 || tier1 ...'`
and therefore **skips** this spec because it has no tier label. The env-var
equivalents are `E2E_SERIAL_FOCUS`, `E2E_SERIAL_SKIP` and
`E2E_SERIAL_TIER_UPTO`.

Check selection without touching the cluster first. `--ginkgo.dry-run` walks
the spec tree and reports what would run without executing it:

```bash
bin/e2e-nrop-serial.test --ginkgo.dry-run --ginkgo.focus='restricted TLS profile modifications'
hack/run-test-serial-e2e.sh --dry-run --focus 'restricted TLS profile modifications'
```

The runner's `--dry-run` only echoes the command it would run; it is the
safest way to confirm the focus string before a disruptive run.

What actually happens on a real run:

- `BeforeSuite` in `test/e2e/serial/e2e_serial_test.go` always runs
  `serialconfig.Setup()` (node topology check plus fixture) even when only one
  spec is selected. Run this suite against an already installed NRO on a
  TAS-capable cluster, not from a bare `go test` shell without cluster access.
- An alternative to the prebuilt binary is
  `go test ./test/e2e/serial -args -ginkgo.focus='restricted TLS profile modifications' -ginkgo.v`;
  the Makefile path is preferred because it pins the same build flags CI uses.
- The spec sets `fxt.IsRebootTest = true`, rewrites
  `APIServer/cluster.spec.tlsSecurityProfile`, waits for every MCP to roll out
  and verifies per-node MachineConfig alignment (tens of minutes). Use a
  disposable cluster; `DeferCleanup` restores the original spec.
- The spec calls `Skip()` when the `TLSGroupPreferences` feature gate is off,
  so a green run with a skip is not evidence that curves were exercised.

---

## 4. How TLS works in NROP

### 4.1 Endpoints

| Endpoint | Port | TLS | Certificate | Consumer |
|---|---:|---|---|---|
| Operator metrics | 8080 | Always | OpenShift service-serving CA secret mounted at `/certs` | Prometheus / port-forward tests |
| Admission webhook | 9443 | Disabled by default | OLM-managed certificate when enabled | Out of scope: not exposed by the shipped bundle |
| Scheduler secure serving | 10259 | Always | Scheduler serving certificate | Scheduler clients and tests |
| RTE metrics | 2112 | `--metrics-mode=httptls` | RTE serving certificate | Prometheus / port-forward tests |
| Health probes | 8081 | No | N/A | Kubelet |

The admission webhook on `9443` is disabled by default in the shipped OLM
bundle (the Deployment does not pass `--enable-webhooks`) and is not an exposed
user-facing endpoint, so webhook curve coverage is intentionally out of scope.
The three in-scope TLS surfaces for this work are operator metrics (`8080`),
RTE metrics (`2112`), and scheduler secure serving (`10259`).

The operator reads the cluster profile once at startup and constructs one
`tls.Config`. A `SecurityProfileWatcher` watches `APIServer`; when the profile
changes, the operator shuts down gracefully and restarts so the new profile is
loaded.

### 4.2 Profile resolution

`ctrltls.FetchAPIServerTLSProfile(ctx, client)` reads the singleton
`APIServer/cluster` object and resolves `spec.tlsSecurityProfile`:

| Profile type | Resolution |
|---|---|
| empty / omitted | Intermediate |
| `Old` | `configv1.TLSProfiles[Old]` |
| `Intermediate` | `configv1.TLSProfiles[Intermediate]` |
| `Modern` | `configv1.TLSProfiles[Modern]` |
| `Custom` | `spec.tlsSecurityProfile.custom` verbatim |

The result is a `configv1.TLSProfileSpec`:

```go
type TLSProfileSpec struct {
	Ciphers       []string             // OpenSSL names
	Groups        []configv1.TLSGroup  // X25519, secp256r1, ...
	MinTLSVersion configv1.TLSProtocolVersion
}
```

### 4.3 TLS groups and curve IDs

OpenShift calls them **groups** in the API because TLS 1.3 renamed the registry
to "NamedGroup". Go calls them **curves** for historical reasons. NROP and
Kubernetes expose numeric IDs on the command line.

| OpenShift `TLSGroup` | Go constant | Decimal ID | Notes |
|---|---|---:|---|
| `secp256r1` | `tls.CurveP256` | 23 | NIST P-256 |
| `secp384r1` | `tls.CurveP384` | 24 | NIST P-384 |
| `secp521r1` | `tls.CurveP521` | 25 | NIST P-521 |
| `X25519` | `tls.X25519` | 29 | X25519 |
| `SecP256r1MLKEM768` | `tls.SecP256r1MLKEM768` | 4587 | PQ hybrid, not FIPS-approved |
| `X25519MLKEM768` | `tls.X25519MLKEM768` | 4588 | PQ hybrid, not FIPS-approved |
| `SecP384r1MLKEM1024` | `tls.SecP384r1MLKEM1024` | 4589 | PQ hybrid, not FIPS-approved |

The built-in Old, Intermediate, and Modern profiles in this vendor snapshot
all use:

```text
X25519MLKEM768, X25519, secp256r1, secp384r1
```

Since Go's `tls.Config.CurvePreferences` order is ignored, Go treats the list
as an allowlist and chooses from it using its own internal preference order.
Consequently:

- Argument tests must compare the exact CSV string NROP generated.
- Handshake tests must assert that the negotiated curve is **in** the allowed
  set, not that it is the first entry.

When a profile has no groups, `tls.Config.CurvePreferences` stays nil and Go's
default curve set is used. NROP must therefore remove stale curve flags from
operand arguments rather than leaving an old list in place.

### 4.4 End-to-end conversion pipeline

```text
APIServer/cluster .spec.tlsSecurityProfile
        |
        | ctrltls.FetchAPIServerTLSProfile
        v
configv1.TLSProfileSpec{MinTLSVersion, Ciphers, Groups}
        |
        | ctrltls.NewTLSConfigFromProfile
        |   -> libgocrypto.TLSGroupsToCurveIDs(profile.Groups)
        v
tls.Config{MinVersion, CipherSuites, CurvePreferences}
        |
        | objtls.NewSettings
        |   -> curveIDsToString
        v
objtls.Settings{MinVersion, CipherSuites, CurvePreferences}
        |
        +--> rteupdate.DaemonSetArgs
        |      --metrics-tls-min-version
        |      --metrics-tls-cipher-suites
        |      --metrics-tls-curve-preferences=4588,29,23,24
        |
        +--> schedupdate.DeploymentTLSSettings
               --tls-min-version
               --tls-cipher-suites
               --tls-curve-preferences=4588,29,23,24
```

### 4.5 Feature gate

`TLSProfileSpec.Groups` is gated by the OpenShift `TLSGroupPreferences`
feature gate. The built-in profiles already define groups, so reading them
works without a special test cluster. Writing a **Custom** profile with an
explicit `groups` list may require the gate. E2E code should detect this and
skip rather than fail when the API drops or rejects the field:

```go
func tlsGroupPreferencesEnabled(ctx context.Context, cli client.Client) (bool, error) {
	fg := &configv1.FeatureGate{}
	if err := cli.Get(ctx, client.ObjectKey{Name: "cluster"}, fg); err != nil {
		return false, err
	}
	for _, version := range fg.Status.FeatureGates {
		for _, enabled := range version.Enabled {
			if enabled.Name == "TLSGroupPreferences" {
				return true, nil
			}
		}
	}
	return false, nil
}
```

Always re-read the `APIServer` after an update and verify the groups actually
persisted. Some APIs silently drop gated fields instead of rejecting them.

#### Why the gate is needed at all

`groups` is not a normal field of the config API. It carries
`+openshift:enable:FeatureGate=TLSGroupPreferences`
(vendor/github.com/openshift/api/config/v1/types_tlssecurityprofile.go:229), so
in a payload where the gate is off the API server does not expose it: a write
carrying `groups` is pruned, and a later read returns nothing. There is no
error to notice, which is exactly why the spec re-reads the object before
asserting anything.

The NROP side is not gated. The operator vendors an `openshift/api` that always
has `TLSProfileSpec.Groups`, and `GetTLSProfileSpec` feeds it straight into
`TLSGroupsToCurveIDs`; nothing in `pkg/objectupdate` checks a feature gate. Two
consequences follow:

- built-in profiles already carry groups in the compile-time `TLSProfiles`
  table, so curve flags are rendered on the operands with or without the gate,
  and `test/e2e/tls` can probe curve negotiation on any cluster;
- only a `Custom` profile needs the gate, because only then does the group list
  come from the API object rather than from a table compiled into the
  operator.

Without the gate the restricted-groups half of the serial spec is unreachable:
the patch cannot persist `[X25519, secp256r1]`, so the operand flags can never
become `29,23`. The empty-groups half is still reproducible, because "no
groups" is also what a pruned field looks like. The spec still gates on
`tlsGroupPreferencesEnabled` so that the skip is explicit instead of an
assertion on args derived from `nil` groups that would pass for the wrong
reason.

#### Enabling the gate

This is a cluster-level OpenShift setting, not an NROP option. Check the
current state:

```bash
oc get featuregate cluster -o jsonpath='{.spec.featureSet}{"\n"}'
oc get featuregate cluster -o jsonpath='{range .status.featureGates[*].enabled[*]}{.name}{"\n"}{end}' | grep TLSGroupPreferences
```

Two ways to turn it on:

```bash
# A: all tech-preview gates (broad, invasive)
oc patch featuregate cluster --type merge \
  -p '{"spec":{"featureSet":"TechPreviewNoUpgrade"}}'

# B: this gate only
oc patch featuregate cluster --type merge \
  -p '{"spec":{"featureSet":"CustomNoUpgrade","customNoUpgrade":{"enabled":["TLSGroupPreferences"]}}}'
```

Both make the cluster-version operator roll the control plane and every MCP,
so nodes reboot and you must wait for `oc get clusterversion` and all
`oc get mcp` to settle. Both sets are one-way on most releases; use a
disposable cluster. `CustomNoUpgrade` rejects gates whose prerequisites are
not also enabled — if the patch fails, add the gates named in the error or
fall back to `TechPreviewNoUpgrade`.

The test helper reads `status.featureGates`, which the operator fills in after
the rollout, so a freshly patched cluster reports the gate only once the
feature set has been applied. Enabling the gate does not change the profile by
itself; the serial spec is what writes a Custom profile with
`groups: [X25519, secp256r1]`.

#### If `TLSGroupPreferences` is absent from `status.featureGates`

That list contains only gates that are currently **on**; known-but-disabled
gates are never listed. Absence therefore means "not enabled", not necessarily
"unknown to this payload". Note that `TLSAdherence` is a different gate (it
controls whether components must honour the cluster profile); it does not
expose `custom.groups`.

Separate the two cases:

```bash
oc get featuregate cluster -o jsonpath='{.spec.featureSet}{"\n"}'
oc get featuregate cluster -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.message}{"\n"}{end}'
```

A `Default` cluster has an empty enabled list; if you already run
`TechPreviewNoUpgrade` and the gate is still absent, the payload's tech-preview
set does not include it. Patching `CustomNoUpgrade` with only this name makes
the cluster-version operator report an unknown gate in `status.conditions`
instead of enabling it.

The decisive check is behavioural, and it is the same thing the spec asserts:

```bash
oc patch apiserver cluster --type merge -p '{"spec":{"tlsSecurityProfile":{"type":"Custom","custom":{"minTLSVersion":"VersionTLS12","ciphers":["ECDHE-ECDSA-AES128-GCM-SHA256"],"groups":["X25519","secp256r1"]}}}}'
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile.custom.groups}'
```

If the array reads back empty, the API server pruned the field: the gate is not
active in this payload and the serial curve spec will always `Skip()` at its
`tlsGroupPreferencesEnabled` guard. A newer payload that ships the gate is then
required for the Custom-profile phase; `test/e2e/tls` still exercises curve
negotiation from the built-in profile groups, which do not need the gate.

### 4.6 How TLS curve support was added

The feature was delivered in layers: dependency support first, then operator
core conversion, then RTE and scheduler operand propagation, then TLS E2E
coverage.

| Commit | Change | Why it mattered |
|---|---|---|
| `41f2e89cf` | Bumped `openshift/api` for `TLSGroup`/`Groups` and `library-go` for `TLSGroupsToCurveIDs`. | Without the API and mapping helper, NROP had no way to express or convert group names. |
| `e368f662f` | Bumped OpenShift dependencies for TLS group support. | Kept the API and helper versions aligned with the group feature gate. |
| `51665176b` | Bumped RTE for metrics TLS curve preferences. | RTE gained `--metrics-tls-curve-preferences`; NROP alone could not enforce curves on the metrics endpoint. |
| `c470310ec` | Bumped RTE for curve validation. | RTE v0.25.4 added validation of numeric curve IDs. Its static allowlist is narrower than Go 1.26's full curve set. |
| `cdd1a3510` | Added curve preferences to `pkg/objectupdate/tls` and operator startup. | `objtls.Settings` gained `CurvePreferences`; `NewSettings` began producing a decimal CSV; the operator's own metrics/webhook servers received curve preferences automatically through `NewTLSConfigFromProfile`. |
| `4c8f83bd8` | Cleaned up return-value naming and comments. | No behavior change; clarified the conversion path. |
| `0defe620e` | Passed curve preferences to the RTE operand. | `rteupdate.DaemonSetArgs` began setting or deleting `--metrics-tls-curve-preferences`. |
| `db992f8ab` | Passed curve preferences to the scheduler operand. | `schedupdate.DeploymentTLSSettings` began setting or deleting `--tls-curve-preferences`. |
| `cf3bde233` | Checked args for emptiness before adding them. | Established the set-or-delete behavior so stale flags are removed. |
| `359b9b090` | Merged the scheduler curve-argument work. | Completed operand propagation for both RTE and the scheduler. |

Before this series, the operator propagated only minimum TLS version and
cipher suites. Operand arguments looked like:

```text
Scheduler:
  --tls-min-version=VersionTLS12
  --tls-cipher-suites=TLS_ECDHE_...

RTE:
  --metrics-tls-min-version=VersionTLS12
  --metrics-tls-cipher-suites=TLS_ECDHE_...
```

After the series, both operands also receive the group restriction:

```text
Scheduler:
  --tls-curve-preferences=4588,29,23,24

RTE:
  --metrics-tls-curve-preferences=4588,29,23,24
```

Design decisions worth remembering:

- The OpenShift API uses group names; the operands use numeric IANA IDs.
- NROP converts once at startup and stores the result in `objtls.Settings`.
- The operator restarts when the profile changes, so `Settings` is immutable
  for the lifetime of a manager process.
- Unsupported groups are logged and skipped rather than aborting startup.
- Empty groups must delete the operand flags so Go's defaults apply.
- The operator's own endpoints need no operand flags because the same TLS
  callback is passed directly to controller-runtime's metrics and webhook
  servers.

---

## 5. Every function involved in TLS curve handling

### 5.1 OpenShift library functions

#### `libgocrypto.TLSGroupToCurveID`

```go
func TLSGroupToCurveID(group configv1.TLSGroup) (tls.CurveID, bool)
```

Maps one OpenShift group name to one Go curve ID. The boolean is false for an
unrecognized name.

#### `libgocrypto.TLSGroupsToCurveIDs`

```go
func TLSGroupsToCurveIDs(groups []configv1.TLSGroup) ([]tls.CurveID, []configv1.TLSGroup)
```

Maps all recognized groups in order and returns unrecognized groups
separately. NROP does not fail startup for unrecognized groups; they are logged
as unsupported and skipped.

#### `libgocrypto.ValidTLSGroups`

```go
func ValidTLSGroups() []configv1.TLSGroup
```

Returns the recognized group names sorted alphabetically. Useful in unit tests
or diagnostics, not used by the NROP reconcile path.

#### `ctrltls.FetchAPIServerTLSProfile`

```go
func FetchAPIServerTLSProfile(ctx context.Context, k8sClient client.Client) (configv1.TLSProfileSpec, error)
```

Reads `APIServer/cluster` and resolves its profile. This is the source of truth
for both production code and tests.

#### `ctrltls.GetTLSProfileSpec`

```go
func GetTLSProfileSpec(profile *configv1.TLSSecurityProfile) (configv1.TLSProfileSpec, error)
```

Resolves a named profile or a custom profile. Empty input means Intermediate.
A Custom type with a nil custom block returns `ErrCustomProfileNil`.

#### `ctrltls.NewTLSConfigFromProfile`

```go
func NewTLSConfigFromProfile(profile configv1.TLSProfileSpec) (func(*tls.Config), []string)
```

Returns a callback that sets `MinVersion`, `CipherSuites`, and
`CurvePreferences`, plus a list of unsupported ciphers/groups. The callback is
used as a `TLSOpts` entry on the operator's metrics and webhook servers and is
also used to precompute operand settings.

Important behavior:

- `CurvePreferences` is only assigned when the mapped list is non-empty.
- `CipherSuites` is only assigned when `MinVersion != tls.VersionTLS13`.
- Unsupported ciphers and groups are aggregated into one `[]string`.

### 5.2 NROP settings functions

#### `objtls.Settings`

```go
type Settings struct {
	MinVersion       string
	CipherSuites     string
	CurvePreferences string // comma-separated decimal IDs
}
```

This is the operator's operand-facing representation. It is not a
`tls.Config`; every field is already formatted for a command line.

#### `objtls.Settings.String`

Returns a log-friendly string. Curve preferences are appended only when
non-empty. This function is unit-tested and should be used in `klog.InfoS`.

#### `objtls.NewSettings`

```go
func NewSettings(cfg *tls.Config) Settings
```

Converts `MinVersion` to names such as `VersionTLS12`, converts cipher IDs to
IANA names, and converts curve IDs to decimal CSV. An empty
`CurvePreferences` slice produces an empty string. This is the exact
transformation used in `cmd/main.go` before constructing both controllers.

#### `objtls.curveIDsToString`

```go
func curveIDsToString(ids []tls.CurveID) string
```

Private helper that writes `strconv.Itoa(int(id))` joined by commas. It is
covered indirectly by `TestNewSettings_WithCurvePreferences`.

### 5.3 Operand argument functions

#### `rteupdate.DaemonSetArgs`

```go
func DaemonSetArgs(ds *appsv1.DaemonSet, conf nropv1.NodeGroupConfig, metricsTLS objtls.Settings) error
```

For every RTE DaemonSet this function:

1. Finds the `resource-topology-exporter` container.
2. Parses its args with `flagcodec.ParseArgvKeyValue`.
3. Forces `--metrics-mode=httptls`.
4. Sets or deletes `--metrics-tls-min-version`.
5. Sets or deletes `--metrics-tls-cipher-suites`.
6. Sets or deletes `--metrics-tls-curve-preferences`.

The set-or-delete behavior is essential. Empty settings must remove an old
flag, otherwise a profile transition to empty groups would keep enforcing the
previous curves.

#### `schedupdate.DeploymentTLSSettings`

```go
func DeploymentTLSSettings(dp *appsv1.Deployment, tlsSettings objtls.Settings) error
```

The scheduler equivalent. It finds the `secondary-scheduler` container and
sets/deletes `--tls-min-version`, `--tls-cipher-suites`, and
`--tls-curve-preferences`.

### 5.4 Controller wiring

These are the functions/fields that carry curve settings into the operand
updaters:

- `cmd/main.go`: calls `FetchAPIServerTLSProfile`, `NewTLSConfigFromProfile`,
  and `objtls.NewSettings` once at startup.
- `NUMAResourcesOperatorReconciler.RTEMetricsTLS`: field of type
  `objtls.Settings`; populated from `cmd/main.go`.
- `daemonsetUpdater(poolName, gdm, rteMetricsTLS)`: calls
  `rteupdate.DaemonSetArgs`.
- `NUMAResourcesSchedulerReconciler.TLSSettings`: field of type
  `objtls.Settings`; populated from `cmd/main.go`.
- Scheduler reconcile path: calls `schedupdate.DeploymentTLSSettings`.

### 5.5 Test helper functions

#### `intls.GetClusterTLSProfile`

```go
func GetClusterTLSProfile(ctx context.Context, cli client.Client) (uint16, configv1.TLSProfileSpec, error)
```

Fetches the profile, converts it to a `tls.Config`, and returns the numeric
minimum version plus the raw profile. Use this when a test needs both the
profile's cipher names and the Go `tls.Config`.

#### `intls.RTESettingsFromClusterProfile`

```go
func RTESettingsFromClusterProfile(ctx context.Context, cli client.Client) (objtls.Settings, error)
```

Returns the expected operand settings. Despite the name, the result is
operand-agnostic; it is suitable for both RTE and scheduler comparisons.

#### `intls.CheckRTEDaemonSetTLSFlagsMatchClusterProfile`

```go
func CheckRTEDaemonSetTLSFlagsMatchClusterProfile(ctx context.Context, cli client.Client) error
```

Convenience wrapper: derive settings from the cluster, then check RTE flags.
Used by non-disruptive test `[test_id:88380]`.

#### `intls.CheckRTEDaemonSetTLSFlags`

```go
func CheckRTEDaemonSetTLSFlags(ctx context.Context, cli client.Client, expected objtls.Settings) error
```

Reads `NUMAResourcesOperator/status.nodeGroups`, loads each referenced
DaemonSet, finds the main RTE container, parses its args, and compares three
flags against `expected`: `--metrics-tls-min-version`,
`--metrics-tls-cipher-suites` and `--metrics-tls-curve-preferences`. It walks
every node group in status, so one stale DaemonSet fails the call and the error
names that DaemonSet.

#### `intls.matchTLSFlag`

```go
func matchTLSFlag(flags *flagcodec.Flags, flagName, expected, objectName string) error
```

Comparison rules:

- `expected == ""`: the flag may be absent or present with an empty value, but
  a non-empty stale value fails.
- `expected != ""`: the flag must exist and match exactly.

The error includes the object name and expected/actual values. There is no
direct `TestMatchTLSFlag`; it is covered indirectly by
`TestCheckRTEDaemonSetTLSFlags`.

#### `intls.tlsConfigFromProfileSpec`

Private helper used by `GetClusterTLSProfile`. It applies the profile, logs
unsupported ciphers, and returns a populated `tls.Config`.

#### `intls.TLSVersionBelow`

Returns the previous TLS version for negative version tests. It errors for TLS
1.0 and unknown versions.

#### `intls.OpenSSLCipherToGoID`

Converts an OpenSSL cipher name to a Go cipher suite ID. Used by
`ProbeTLSCipher`.

#### `intls.FindDisallowedCipher`

Returns the first TLS 1.2 cipher from the Old profile that is not in the
allowed list. TLS 1.3 cipher names are skipped because they are not
individually configurable.

#### `intls.ProbeMaxTLSVersion`

```go
func ProbeMaxTLSVersion(cli kubernetes.Interface, pod *corev1.Pod, podPort string, maxVersion uint16) error
```

Port-forwards to the pod, pins both `MinVersion` and `MaxVersion` to the given
version, and performs a handshake. A rejection is wrapped as a TLS handshake
error.

#### `intls.ProbeTLSCipher`

```go
func ProbeTLSCipher(cli kubernetes.Interface, pod *corev1.Pod, podPort string, cipher string) error
```

Pins the client to one TLS 1.2 cipher and performs a handshake. Use only when
the active minimum version is below TLS 1.3.

#### `intls.ProbeTLSState`

```go
func ProbeTLSState(cli kubernetes.Interface, pod *corev1.Pod, port string) (tls.ConnectionState, error)
```

Performs an unconstrained handshake (no pinned version, cipher or curve) and
returns the full `tls.ConnectionState`. This is the replacement for the
removed `ProbeTLSSettings`: callers read `state.Version`,
`state.CipherSuite` and, for curve tests, `state.CurveID`.

`ProbeTLSSettings` no longer exists. Its two call sites in
`test/e2e/tls/tls_test.go` were migrated to `ProbeTLSState`; see
"Migrating the `ProbeTLSSettings` call sites" for the before/after code.

#### `intls.ProbeTLSCurve`

```go
func ProbeTLSCurve(cli kubernetes.Interface, pod *corev1.Pod, port string, curve tls.CurveID) (tls.ConnectionState, error)
```

Pins the client's `CurvePreferences` to exactly one curve and returns the
resulting state. On success the caller should assert
`state.CurveID == curve`; on rejection the error wraps
`ErrTLSHandshakeRejected`. Unlike `ProbeTLSCipher` it applies to both TLS 1.2
and TLS 1.3, because curves are negotiated in both.

#### `intls.ProbeTLSWithConfig`

```go
func ProbeTLSWithConfig(cli kubernetes.Interface, pod *corev1.Pod, port string, opts ...tlsConfigOpt) (tls.ConnectionState, error)
```

The single handshake implementation behind `ProbeTLSState`,
`ProbeTLSCurve`, `ProbeTLSCipher` and `ProbeMaxTLSVersion`. It applies the
option functions to a baseline `tls.Config` (`InsecureSkipVerify: true`) and
wraps handshake errors through `wrapTLSHandshakeError`.

Design decision: this function is meant to stay unexported
(`probeTLSWithConfig`) because its variadic parameter type `tlsConfigOpt` is
unexported, and because no test outside the package needs an arbitrary client
configuration. Export only the semantic wrappers. If a future test must
combine constraints (for example curve plus maximum version), export a named
`ConfigOpt` type first instead of exposing an option type that callers cannot
name.

#### `intls.FetchMetrics`

Port-forwards to RTE's metrics port and performs an HTTPS `GET /metrics` over
the same stream. The HTTP transport is configured to use exactly one dial so
the port-forward connection is not accidentally replaced.

#### Error helpers

`wrapTLSHandshakeError` classifies failures:

- `ErrTLSServerRejected`: the server sent a TLS alert or rejected the protocol.
- `ErrTLSClientConfigIncompatible`: the Go client refused to attempt the
  handshake because its own configuration was impossible.
- Both wrap `ErrTLSHandshakeRejected`, so tests can use
  `errors.Is(err, intls.ErrTLSHandshakeRejected)`.

#### Test-only helpers in `test/e2e/tls/tls_test.go`

`getRTEPodsFromNRO(ctx)` walks NRO status node groups, loads each DaemonSet,
and returns all RTE pods. It asserts that at least one node group and one pod
exist.

#### Serial MCP helpers in `configuration.go`

TLS profile mutation causes MachineConfigPool rollouts. Relevant helpers:

- `waitForMCPConditionWithRetry`: retries transient transport errors while
  waiting for `Updating`/`Updated`.
- `isTransientMCPError`: recognizes URL errors, timeouts, service-unavailable,
  HTTP/2 stream errors, and `INTERNAL_ERROR`.
- `verifyNodesMatchMCPConfig`: confirms every node's current config annotation
  matches the MCP's rendered config.

### 5.6 Operator metrics discovery and exec helpers

These helpers are not curve-specific, but an operator metrics curve test needs
them. Their line-by-line explanation is in
[`nrop_tls_curves_automation.md#49-operator-metrics-endpoint-layer`](nrop_tls_curves_automation.md#49-operator-metrics-endpoint-layer).

#### `deploy.FindNUMAResourcesOperatorPod`

```go
func FindNUMAResourcesOperatorPod(ctx context.Context, cli client.Client, nrop *nropv1.NUMAResourcesOperator) (*corev1.Pod, error)
```

Derives the operator namespace from `nrop.Status.DaemonSets`, selects
`app=numaresources-operator`, and requires exactly one Pod. A rollout can
temporarily break the "exactly one" rule, so wrap the call in `Eventually`.

#### `remoteexec.CommandOnPod` and `CommandOnPodByNames`

```go
func CommandOnPod(ctx context.Context, c kubernetes.Interface, pod *corev1.Pod, command ...string) ([]byte, []byte, error)
func CommandOnPodByNames(ctx context.Context, c kubernetes.Interface, podNamespace, podName, cntName string, command ...string) ([]byte, []byte, error)
```

Streams a command through the Pod `exec` subresource with SPDY. `CommandOnPod`
always targets `pod.Spec.Containers[0]`. These helpers are useful for
availability checks such as `curl -k`, but they cannot observe the negotiated
curve. Use port-forward probes for TLS policy.

#### `fetchMetricsFromPod`

Runs `/bin/curl -k https://<address>:<port>/metrics` inside the Pod and returns
stdout. It proves the HTTPS endpoint responds and returns metrics. It does not
assert minimum version, cipher, or curve.

---

## 6. How the existing TLS tests are written

### 6.1 Non-disruptive scheduler tests (`test/e2e/tls/tls_test.go`)

#### `[test_id:90743]` negative version/cipher test

Flow:

1. `GetClusterTLSProfile` returns the numeric minimum version and raw profile.
2. `TLSVersionBelow` computes the next lower version.
3. The test finds the scheduler Deployment via
   `DeploymentByOwnerReference`, then its pods via `ByDeployment`.
4. `ProbeMaxTLSVersion` connects to port `10259` and caps the client at the
   lower version. The server must reject it.
5. If the minimum version is TLS 1.3, the cipher probe is skipped because
   there are no configurable TLS 1.2 cipher suites.
6. Otherwise `FindDisallowedCipher` picks a cipher absent from the profile and
   `ProbeTLSCipher` must be rejected.

This test checks runtime behavior, not operand arguments.

#### `[test_id:90744]` positive scheduler test

Flow:

1. Fetch profile and minimum version.
2. Find scheduler deployment and pod.
3. `ProbeTLSSettings` returns negotiated version and cipher.
4. Assert negotiated version is at least the profile minimum.
5. For TLS 1.2 and below, convert profile OpenSSL cipher names to IANA names
   and assert the negotiated cipher is in the allowed set.

There is no curve assertion here today.

### 6.2 Non-disruptive RTE tests

#### `[test_id:88380]` RTE DaemonSet arguments

The test runs inside an `Eventually` block (30-second timeout, 5-second poll):

```go
Eventually(func() error {
	return intls.CheckRTEDaemonSetTLSFlagsMatchClusterProfile(ctx, e2eclient.Client)
}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())
```

`CheckRTEDaemonSetTLSFlags` now includes a third `matchTLSFlag` call for
`--metrics-tls-curve-preferences`, so 88380 validates steady-state curve
arguments without any change to the test body.

#### `[test_id:88381]` RTE metrics endpoint positive test

For every RTE pod, the test:

1. Probes the TLS handshake on port `2112`.
2. Asserts the negotiated version meets the profile minimum.
3. Fetches `/metrics` over TLS and asserts a known metric is present.

This proves the endpoint is alive and compliant for version/cipher, but it
does not inspect the negotiated curve.

#### `[test_id:88382]` RTE metrics endpoint negative test

For every RTE pod, the test:

1. Caps the client at a version below the minimum and expects rejection.
2. Skips the cipher probe for TLS 1.3.
3. Picks a disallowed TLS 1.2 cipher and expects rejection.

Again, no curve negative probe exists.

### 6.3 Operator metrics tests (`test/e2e/serial/tests/metrics.go`)

#### `[test_id:85769]` operator metrics availability

Flow:

1. `FindNUMAResourcesOperatorPod` finds the manager Pod.
2. `fetchMetricsFromPod` execs `/bin/curl -k https://127.0.0.1:8080/metrics`.
3. The body is asserted to contain operator and scheduler
   `workqueue_adds_total` metrics.

This is labeled `feature:metrics`, not `feature:tlscompliance`. It proves the
HTTPS endpoint serves metrics but asserts nothing about the TLS profile, so it
does **not** cover curve enforcement. `curl -k` also hides the negotiated
curve.

#### `[test_id:85770]` RTE metrics availability

Same idea against an RTE Pod on port `2112`. The stricter TLS tests are 88381
and 88382; 85770 remains a lightweight availability check.

The operator metrics curve gap is closed by probing `8080` with
`ProbeTLSState` and `ProbeTLSCurve`, as described in Scenarios 19-21 and the
automation cookbook.

### 6.4 Serial TLS test (`test/e2e/serial/tests/configuration.go`)

#### `[test_id:88383]` RTE arguments after profile mutation

This is the only disruptive TLS curve-adjacent test. Important correction:
despite some older notes describing it as a scheduler test, the current code
only checks RTE DaemonSet arguments.

Flow:

1. `fxt.IsRebootTest = true`.
2. Read `APIServer/cluster`, save the original TLS profile, and determine the
   effective original type (Intermediate when unset).
3. Choose Modern, or Intermediate if the original is already Modern.
4. Update the `APIServer` profile using `Eventually` to tolerate conflict
   retries.
5. Register `DeferCleanup` immediately after the successful update. Cleanup
   restores the original profile and waits for all MCPs again.
6. `waitForMCPsAndVerifyNodes` launches one goroutine per MCP, waits for
   `Updating`, then `Updated`, and finally verifies every node's current config.
   Requiring the transient `Updating` condition is fragile: a pool with
   `machineCount: 0` never sets it, and a fast roll can slip between polls. See
   the troubleshooting entry for the `Updated` + `observedGeneration` predicate.
7. Build the expected settings from `configv1.TLSProfiles[newProfile.Type]`
   using `NewTLSConfigFromProfile` and `objtls.NewSettings`.
8. `Eventually` calls `CheckRTEDaemonSetTLSFlags` with the expected settings.

Because Old, Intermediate, and Modern currently define the same group set,
this test only proves that the curve flag survives reconciliation. It does not
prove a value change or the empty-groups delete path.

### 6.5 Unit and controller tests that already cover curves

| Test | What it proves |
|---|---|
| `pkg/objectupdate/tls/tls_test.go:TestNewSettings_WithCurvePreferences` | Curve ID slices become decimal CSV; empty means empty string. |
| `pkg/objectupdate/tls/tls_test.go:TestSettings_String` | Logging includes curves only when present. |
| `pkg/objectupdate/sched/sched_test.go:TestDeploymentTLSSettings` | Scheduler args are added, replaced, and removed, including curve args. |
| `pkg/objectupdate/sched/sched_test.go:TestDeploymentTLSSettingsRepeated` | Repeated reconciliation does not duplicate TLS args. |
| `pkg/objectupdate/rte/rte_test.go:TestUpdateDaemonSetArgs` | RTE adds `--metrics-tls-curve-preferences` when set. |
| `internal/controller/numaresourcesoperator_controller_test.go` | Reconciler passes curve settings into the RTE DaemonSet. |
| `internal/controller/numaresourcesscheduler_controller_test.go` | Reconciler adds/removes scheduler curve args across reconciles. |

What is **not** directly unit-tested:

- `TLSGroupsToCurveIDs` with an unknown group.
- RTE deleting a stale curve flag when the new settings are empty.
- `matchTLSFlag` as a standalone unit.
- Scheduler argument validation helper (there is no such helper yet).

---

## 7. Test coverage matrix for TLS curves

Legend: **yes** = covered, **partial** = covered indirectly or only one path,
**no** = not covered.

| Area | Existing coverage | Status | Gap |
|---|---|---|---|
| Group name to curve ID mapping | `NewSettings` unit tests, built-in profile conversion | partial | No direct test with all seven groups; no unknown-group test. |
| Decimal formatting | `TestNewSettings_WithCurvePreferences` | yes | Empty and one/many values covered. |
| Settings logging | `TestSettings_String` | yes | Good. |
| Scheduler arg set | `TestDeploymentTLSSettings` | yes | Good. |
| Scheduler arg replace | `TestDeploymentTLSSettings` | yes | Good. |
| Scheduler arg delete when empty | `TestDeploymentTLSSettings` | yes | Good. |
| Scheduler arg in live cluster | None | **no** | No E2E check of `--tls-curve-preferences`. |
| RTE arg set | `TestUpdateDaemonSetArgs`, controller test | yes | Good. |
| RTE arg delete when empty | None | **no** | No unit test for stale curve flag removal. |
| RTE arg in live cluster | 88380/88383 check version/cipher/curve | partial | Steady state is covered; a changed or empty curve value is still not exercised. |
| RTE argument transition with changed curves | 88383 changes profiles with identical group membership | partial | No restricted-group profile. |
| RTE transition to empty groups | None | **no** | Delete path never exercised end to end. |
| Scheduler handshake version/cipher | 90743, 90744 | yes | Good. |
| Scheduler handshake curve positive | None | **no** | `ProbeTLSSettings` ignores `ConnectionState.CurveID`. |
| Scheduler handshake curve negative | None | **no** | No `ProbeTLSCurve`. |
| RTE handshake curve positive | None | **no** | 88381 checks version/cipher only. |
| RTE handshake curve negative | None | **no** | 88382 checks version/cipher only. |
| Multiple node groups with one stale curve flag | None | **no** | No stale-flag variant. |
| Custom profile with restricted groups | None | **no** | No E2E coverage. |
| Custom profile with no groups | None | **no** | No E2E coverage. |
| Feature gate unavailable | None | **no** | No skip/detection helper. |
| Unsupported group name | None | **no** | Operator logs and skips; untested. |
| RTE support for every OpenShift group | None | **no** | RTE v0.25.4 rejects 4587 and 4589. See below. |
| FIPS behavior | None | **no** | Intentionally out of scope until a FIPS lane exists. |
| Operator metrics endpoint curves | 85769 checks HTTPS availability only | **no** | No handshake curve assertion on `8080`; needs `ProbeTLSState`/`ProbeTLSCurve`. |
| Admission webhook curves | Disabled by default in the OLM bundle | out of scope | Not an exposed endpoint; intentionally excluded. |

### 7.1 Important compatibility finding: RTE rejects two PQ hybrid IDs

`libgocrypto.TLSGroupsToCurveIDs` maps all seven OpenShift groups, including
`SecP256r1MLKEM768` (4587) and `SecP384r1MLKEM1024` (4589). The vendored RTE
v0.25.4 parser has a static allowlist containing only:

```text
23, 24, 25, 29, 4588
```

If a cluster uses a Custom profile containing 4587 or 4589, NROP will write
those IDs to the RTE DaemonSet, but RTE's `parseCurveIDs` will return
`unsupported curve ID ...` and the metrics server will fail to start. The
built-in profiles avoid this because they only use 4588. This is both a
coverage gap and a compatibility risk.

Recommended handling:

- Keep the baseline E2E custom-profile test to `X25519` and `secp256r1`
  (`29,23`) or another subset of the RTE-supported set.
- Add a separate contract test that records the supported IDs for the pinned
  RTE version.
- Do not add a passing E2E test for 4587/4589 until RTE supports them; a red
  test is useful only if the team wants to track the incompatibility
  deliberately.

#### 7.1.1 Where the static allowlist lives

The allowlist is not in NROP and not in `library-go`; it is in the vendored
RTE metrics server. The complete path from the DaemonSet argument to the
rejection is:

| Step | File | What happens |
| --- | --- | --- |
| 1 | `vendor/github.com/k8stopologyawareschedwg/resource-topology-exporter/pkg/config/flags.go:84` | `--metrics-tls-curve-preferences` is bound to `pArgs.RTE.MetricsTLSCfg.CurvePreferences` as a plain `string`. No validation at parse time. |
| 2 | `vendor/.../resource-topology-exporter/pkg/config/cfgdispatch.go:142` | The config-file equivalent `topologyExporter.metricsTLS.curvePreferences` is copied into the same field. |
| 3 | `vendor/.../resource-topology-exporter/pkg/metrics/server/setup.go:68` | `TLSConfig.CurvePreferences` holds the raw CSV. |
| 4 | `vendor/.../resource-topology-exporter/pkg/metrics/server/setup.go:97` | The value is copied into the metrics server `Config`. |
| 5 | `vendor/.../resource-topology-exporter/pkg/metrics/server/setup.go:179` | `buildSecureMetricsTLSOpts(conf.TLS)` runs only when the metrics mode is HTTPS. |
| 6 | `vendor/.../resource-topology-exporter/pkg/metrics/server/tls_policy.go:160` | `metricsTLSPolicyOpts` receives the string. |
| 7 | `vendor/.../resource-topology-exporter/pkg/metrics/server/tls_policy.go:40,89` | `parseCurveIDs` splits the CSV and parses each token as a base-10 `uint16`. |
| 8 | `vendor/.../resource-topology-exporter/pkg/metrics/server/tls_policy.go:103` | Each parsed ID is checked with `isSupportedCurve`. An ID outside the list returns `unsupported curve ID %d`. |
| 9 | `vendor/.../resource-topology-exporter/pkg/metrics/server/tls_policy.go:127-135` | `isSupportedCurve` contains the hardcoded slice. |

The hardcoded slice is:

```go
func isSupportedCurve(id tls.CurveID) bool {
	supported := []tls.CurveID{
		tls.CurveP256,      // 23
		tls.CurveP384,      // 24
		tls.CurveP521,      // 25
		tls.X25519,         // 29
		tls.X25519MLKEM768, // 4588
	}
	return slices.Contains(supported, id)
}
```

The function's own comment explains why it is static: Go's standard library
does not expose a public API to enumerate the runtime's supported curves.
Consequently `tls.SecP256r1MLKEM768` (4587) and `tls.SecP384r1MLKEM1024`
(4589) are rejected even though Go 1.26 defines those constants and
`library-go` maps them. The comment says the list should be extended when the
project's minimum Go version increases; this repository already declares
`go 1.26.0` in `go.mod`, so the gap is live rather than hypothetical. This is
why the E2E expectations for 4587/4589 are negative (RTE fails to start)
until the vendored RTE is updated.

#### 7.1.2 Can a Custom profile select 4587 and 4588?

Yes at the OpenShift API layer, with two caveats: the
`TLSGroupPreferences` feature gate must be enabled so `groups` is not pruned,
and RTE v0.25.4 still cannot consume 4587.

```yaml
spec:
  tlsSecurityProfile:
    type: Custom
    custom:
      minTLSVersion: VersionTLS13
      ciphers:
      - TLS_AES_128_GCM_SHA256
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
      groups:
      - X25519MLKEM768
      - SecP256r1MLKEM768
```

NROP maps this to `CurvePreferences=4588,4587` and writes it to both
operands. The scheduler accepts both IDs because its parser uses Go's
`tls.CurveID` stringer. RTE rejects 4587 at startup, so an all-PQ Custom
profile containing 4587 is accepted by OpenShift but breaks RTE metrics. Use
4588 alone until the vendored RTE allowlist is extended. Both groups are
TLS 1.3-only and are not FIPS-approved; Go removes them from the TLS 1.2
curve list.

---

## 8. What test cases need to be added

The list is ordered by value and cost. Use project test-management IDs in place
of `TBD`; recent TLS IDs are 88380-88383 and 90743-90744.

### 8.1 Priority P0: cheap unit/helper coverage

| ID | Test | Why |
|---|---|---|
| CU-01 | `CheckRTEDaemonSetTLSFlags` accepts matching curve flag | Implemented in `TestCheckRTEDaemonSetTLSFlags`; keep as a regression case. |
| CU-02 | `CheckRTEDaemonSetTLSFlags` rejects a different curve CSV | Implemented; prevents silently passing a wrong list. |
| CU-03 | Empty expected curves and flag absent succeeds | Implemented by the existing matching-profile case. |
| CU-04 | Empty expected curves and stale non-empty flag fails | Implemented in `TestCheckRTEDaemonSetTLSFlags`. |
| CU-05 | Two node groups, second has stale curve flag | Implemented; proves all DaemonSets are checked. |
| CU-06 | `rteupdate.DaemonSetArgs` removes stale curve flag | Direct unit coverage of RTE delete path. |
| CU-07 | `FindDisallowedCurve` returns nil/error when all supported curves are allowed | Makes negative E2E tests skip safely. |
| CU-08 | `NewSettings` maps all seven curve IDs | Locks the full mapping and decimal strings. |

### 8.2 Priority P1: non-disruptive E2E coverage

| ID | Test | Why |
|---|---|---|
| CU-10 | RTE DaemonSet args include expected curve CSV | Extends 88380 automatically once helper changes. |
| CU-11 | Scheduler Deployment args include expected curve CSV | Optional/deprioritized: the serial Custom-profile test already exercises scheduler reconciliation. Keep only for non-disruptive default-profile coverage. |
| CU-12 | Scheduler handshake negotiated curve is allowed | Positive runtime proof; requires `ProbeTLSState`. |
| CU-13 | Scheduler rejects a disallowed curve | Negative runtime proof; works with built-in profiles by offering P-521. |
| CU-14 | RTE handshake negotiated curve is allowed | Positive runtime proof for metrics endpoint. |
| CU-15 | RTE rejects a disallowed curve | Negative runtime proof for metrics endpoint. |
| CU-16 | Operator metrics negotiate an allowed curve | Positive runtime proof on `8080`; no operand flag exists to assert. |
| CU-17 | Operator metrics reject a disallowed curve | Negative runtime proof that the manager metrics server enforces the profile. |

### 8.2.1 What "NROP reconciles the scheduler Deployment" means

NROP does not run `kube-scheduler` directly. It manages a Kubernetes
Deployment that runs the NUMA-aware scheduler container. The scheduler
controller is responsible for creating and updating that Deployment.

On each reconcile, NROP:

1. Starts from the scheduler Deployment manifest.
2. Applies settings from the `NUMAResourcesScheduler` CR.
3. Applies the cluster-wide TLS settings.
4. Compares the result with the existing Deployment.
5. Creates or updates the Deployment if the desired state differs.
6. Does nothing if the Deployment already matches.

The TLS step is in the scheduler controller:

```go
if err := schedupdate.DeploymentTLSSettings(r.SchedulerManifests.Deployment, r.TLSSettings); err != nil {
	return nropv1.NUMAResourcesSchedulerStatus{}, err
}
```

That function finds the `secondary-scheduler` container and sets:

```text
--tls-min-version=VersionTLS12
--tls-cipher-suites=TLS_ECDHE...
--tls-curve-preferences=4588,29,23,24
```

NROP then writes the modified Deployment to the API server. Kubernetes notices
the pod-template change and rolls out new scheduler pods with those arguments.

The desired TLS values come from the cluster `APIServer` profile:

```text
APIServer.Spec.TLSSecurityProfile
        |
        v
ctrltls.NewTLSConfigFromProfile
        |
        v
objtls.NewSettings
        |
        v
objtls.Settings{CurvePreferences: "4588,29,23,24"}
```

That `Settings` value is passed into `NUMAResourcesSchedulerReconciler` and
applied to the Deployment. If the APIServer TLS profile changes,
`SecurityProfileWatcher` shuts the operator down so it restarts, rereads the
profile, and reconciles the new values.

The CU-11 test does not trigger a reconcile and does not start the scheduler.
It observes the result:

```text
NROS.Status.Deployment
        |
        v
scheduler Deployment
        |
        v
secondary-scheduler container args
        |
        v
--tls-curve-preferences == expected curve ID list
```

So "reconcile the scheduler Deployment" means NROP successfully copied the
curve list derived from the cluster profile into the scheduler Deployment's
pod template. If NROP computes the list correctly but never writes it to the
Deployment, CU-11 fails. This is separate from RTE, which has its own
controller, DaemonSet, and `--metrics-tls-curve-preferences` flag.

It also differs from the serial Custom-profile test: that test proves NROP
reacts to a **change** in the profile. CU-11 proves only that the scheduler
Deployment agrees with the **current** profile.

Terminology note: "curve CSV" in this guide means a comma-separated list of
numeric curve IDs, not an OLM `ClusterServiceVersion`. Prefer wording such as
"curve ID list" or "the value of `--tls-curve-preferences`" in test names.

#### CU-11 implementation note: scheduler Deployment curve CSV

This is the **non-disruptive built-in-profile** check. It is distinct from the
serial Custom-profile test: Serial coverage proves that a restricted CSV and
the delete-on-empty transition reach both operands. CU-11 proves that the
scheduler Deployment always carries the exact CSV derived from the cluster's
current profile.

Current state:

- `CheckSchedulerDeploymentTLSFlags` exists in `test/internal/tls/tls.go`.
- The serial Custom-profile test calls it for `29,23` and for empty groups.
- There is no non-disruptive scheduler assertion equivalent to RTE test
  `88380`.
- There are no fake-client unit tests for the scheduler helper.

**Helper wrappers to add**

```go
func SchedulerSettingsFromClusterProfile(ctx context.Context, cli client.Client) (objtls.Settings, error) {
	_, profileSpec, err := GetClusterTLSProfile(ctx, cli)
	if err != nil {
		return objtls.Settings{}, err
	}
	return objtls.NewSettings(tlsConfigFromProfileSpec(profileSpec)), nil
}

func CheckSchedulerDeploymentTLSFlagsMatchClusterProfile(ctx context.Context, cli client.Client) error {
	settings, err := SchedulerSettingsFromClusterProfile(ctx, cli)
	if err != nil {
		return err
	}
	return CheckSchedulerDeploymentTLSFlags(ctx, cli, settings)
}
```

These mirror `RTESettingsFromClusterProfile` and
`CheckRTEDaemonSetTLSFlagsMatchClusterProfile`, so both operands use the same
profile-to-settings path.

**Non-disruptive E2E spec**

Add a sibling context in `test/e2e/tls/tls_test.go`, not inside the
`[tlscompliance][rte]` context:

```go
Context("[tlscompliance][scheduler] scheduler complies with TLS profile",
	Label(label.Tier0, "feature:tlscompliance"), func() {
		const (
			schedulerCheckTimeout  = 30 * time.Second
			schedulerCheckInterval = 5 * time.Second
		)
		It("[test_id:TBD] should have scheduler Deployment args aligned with the cluster TLS profile",
			func(ctx context.Context) {
				By("verifying scheduler Deployment TLS flags match the cluster TLS profile")
				Eventually(func() error {
					return intls.CheckSchedulerDeploymentTLSFlagsMatchClusterProfile(ctx, e2eclient.Client)
				}).WithTimeout(schedulerCheckTimeout).
					WithPolling(schedulerCheckInterval).
					Should(Succeed())
			})
	})
```

No profile mutation, feature-gate check, MCP wait, or restart is needed. The
test derives the expected values from the cluster profile and only observes
the scheduler Deployment.

**Unit-test matrix**

Add a fake-client table in `test/internal/tls/tls_test.go`. The fixture should
create a `NUMAResourcesScheduler` whose `Status.Deployment` points to a
Deployment containing a `secondary-scheduler` container.

| Case | Result |
|---|---|
| Matching min version, ciphers, and `4588,29,23,24` | success |
| Curve CSV mismatch | exact `--tls-curve-preferences mismatch` |
| Curve flag absent while expected | exact mismatch with `got=""` |
| Empty expected curves, stale curve flag present | exact `should be absent or empty` |
| Empty expected curves, flag absent | success |
| Scheduler CR not found | `failed to get NUMAResourceScheduler` |
| Scheduler status has no Deployment | `Scheduler deployment is not reported` |
| Deployment not found | `failed to get scheduler Deployment` |
| `secondary-scheduler` container missing | `main container not found` |

**Acceptance criteria**

- `CheckSchedulerDeploymentTLSFlags` compares all three scheduler flags.
- The non-disruptive spec fails if the scheduler curve flag is absent, empty,
  or different from the profile-derived CSV.
- The spec is labeled `[tlscompliance][scheduler]` and does not run under
  `[tlscompliance][rte]`.
- The serial Custom-profile test remains the only test that proves a curve
  value change and the delete-on-empty transition.

**Known wording issue**

`matchTLSFlag` formats its error with `daemonsetName=%q`. When called by the
scheduler helper it receives the Deployment name, so the message reads
`daemonsetName="secondary-scheduler-deployment"`. This is functionally correct
but misleading. Passing a neutral label such as `resourceName` should be a
separate, small cleanup.

### 8.2.2 Which remaining tests add real value

The existing tests already cover argument propagation: `88380` for the RTE
built-in profile, `88383` for the RTE profile-switch path, and the serial
Custom-profile test for RTE and scheduler `29,23` and delete-on-empty.
Additional argument-only tests therefore add limited value.

Priority order:

| Priority | Test | Why it adds value | Cost |
|---|---|---|---|
| P0 | Fake-client unit tests for `CheckSchedulerDeploymentTLSFlags` | The helper is new and currently untested. Catches missing NROS status, wrong Deployment lookup, wrong container, missing flag, stale flag, and wrong CSV. | Low |
| P0 | Positive curve negotiation on scheduler and RTE | Proves the servers actually enforce the configured group list. Argument tests only prove YAML/args; this catches a bad `tls.Config`, an unsupported ID, or silent fallback. | Medium; extend `ProbeTLSSettings` to return `ConnectionState.CurveID` or add `ProbeTLSCurve` |
| P0 | Negative disallowed-curve negotiation on scheduler and RTE | Offers only P-521 (`25`), which is absent from built-in profiles, and expects rejection. This is the curve equivalent of the existing disallowed-cipher tests. | Medium |
| P1 | Operator metrics curve negotiation on `8080` | The operator has no operand flag; it applies the profile directly. This is a separate code path from RTE and scheduler. | Medium |
| P1 | RTE allowlist contract test for `4587`/`4589` | Documents the pinned RTE v0.25.4 incompatibility and fails visibly if the vendored version changes. Keep as unit/contract, not a passing E2E test. | Low |
| Optional | CU-11 scheduler argument test | The serial Custom-profile test already proves scheduler reconciliation. Add CU-11 only if a non-disruptive default-profile assertion is required. | Low |
| Skip | Another built-in RTE argument assertion | Duplicates `88380`/`88383`; built-in profiles all use the same groups. | None |

The first real gap is not another argument string check. It is proving that a
curve is accepted or rejected by an actual TLS handshake. `ProbeTLSSettings`
currently returns only version and cipher; it discards
`tls.ConnectionState.CurveID`, so that gap must be closed before adding the
handshake tests.

Before adding new coverage, fix the current serial both-operands draft:

- In the empty-groups phase it compares `expectedRestricted.CurvePreferences`
  with `expectedEmpty.CurvePreferences`, i.e. `"29,23"` with `""`. Replace it
  with `Expect(expectedEmpty.CurvePreferences).To(BeEmpty())`; the operand
  helpers already prove deletion because `matchTLSFlag` treats an empty
  expected value as "flag absent or empty".
- `updateProfile` waits for MCPs internally and callers wait again.
- It logs `(29,33)` instead of `(29,23)`.
- It lacks the reboot/slow/tier labels despite setting `fxt.IsRebootTest`.
- Its test name says "both operands" instead of naming RTE and scheduler, and
  "reconcile" overstates the check: the spec asserts the desired DaemonSet and
  Deployment arguments, not a completed rollout or node state. The parent
  Context already names the operands, so the `It` title should describe the two
  phases, e.g. "should apply the restricted curve list and delete it again when
  profile groups are cleared".

### 8.3 Priority P2: disruptive serial coverage

| ID | Test | Why |
|---|---|---|
| CU-20 | Custom profile with restricted groups propagates to scheduler and RTE | Proves a real value change, not just survival of reconciliation. |
| CU-21 | Transition from restricted groups to empty groups removes both flags | Exercises set-or-delete end to end. |
| CU-22 | Profile rollback restores original curve flags | Proves cleanup and watcher/restart behavior. |
| CU-23 | Feature gate disabled is detected and skipped | Keeps CI honest on clusters without the gate. |
| CU-24 | Unsupported OpenShift group is logged and skipped | Operator resilience; may be unit/controller test rather than E2E. |
| CU-25 | RTE contract for 4587/4589 | Track the known RTE compatibility gap explicitly. |
| CU-26 | Operator metrics re-enforce a changed profile after restart | Proves the profile watcher restarts the manager with the new curve policy. |

### 8.4 Scenario catalog: what to cover and why

The following scenarios are the recommended E2E scope. They are grouped by the
risk they address. A scenario can be implemented as a non-disruptive spec, a
serial spec, or a supporting unit/contract test; the suite is noted for each.

#### Scenario 1: built-in profile propagates curves to both operands

**Suite:** non-disruptive (`test/e2e/tls`).

**Setup:** the cluster uses its normal Old, Intermediate, or Modern profile.

**Steps:** fetch the profile, derive `objtls.Settings`, read the RTE DaemonSets
and scheduler Deployment, parse their args, and compare
`--metrics-tls-curve-preferences` and `--tls-curve-preferences` with the
derived CSV.

**Why:** this is the default production path. It catches a total loss of
curve propagation, a wrong flag name, or an operand that is not reconciled.
It is cheap and should run on every TLS PR.

#### Scenario 2: every NROP-managed node group is checked

**Suite:** unit/helper; optionally non-disruptive on a multi-node-group
cluster.

**Setup:** two or more `NUMAResourcesOperator.status.nodeGroups`, each
referencing a DaemonSet.

**Steps:** make the first DaemonSet correct and the second one carry a stale
or wrong curve flag. Assert that the helper fails.

**Why:** NROP creates one RTE DaemonSet per node group. A helper that checks
only the first or last DaemonSet can pass while another pool runs with wrong
curves. This is especially important on clusters with worker and worker-cnf
pools.

#### Scenario 3: restricted Custom groups change the reported value

**Suite:** serial/disruptive (`test/e2e/serial`).

**Setup:** `TLSGroupPreferences` is enabled; save the original `APIServer`
profile.

**Steps:** set a Custom profile with Intermediate ciphers/version and
`groups: [X25519, secp256r1]`. Wait for all MCPs to complete. Assert both
operands carry exactly `29,23`.

**Why:** all built-in profiles currently have the same group membership, so a
profile switch between Old/Intermediate/Modern does not prove that NROP
honors group values. A restricted Custom profile proves that the actual group
list, not just a hard-coded default, reaches both operands.

#### Scenario 4: one restricted list is replaced by another

**Suite:** serial/disruptive, ideally combined with Scenario 3.

**Setup:** start from a Custom profile with `[X25519, secp256r1]`.

**Steps:** update to `[secp384r1]` or `[X25519]` and wait for reconciliation.
Assert the old CSV is gone and the new CSV is present exactly once.

**Why:** this catches stale-value bugs where the operator updates only when
the number of curves changes, appends a second flag, or fails to replace a
previous value. Reconciliation must be idempotent and last-write-wins.

#### Scenario 5: restricted groups transition to empty groups

**Suite:** serial/disruptive.

**Setup:** start from a Custom profile with a non-empty group list.

**Steps:** update to a Custom profile with valid ciphers/version but no
`groups`. Wait for all MCPs. Assert that
`--metrics-tls-curve-preferences` and `--tls-curve-preferences` are absent on
every operand.

**Why:** this exercises the set-or-delete branch. Empty groups mean "use Go
defaults"; leaving the old flag would silently keep the old restriction. This
is the highest-value regression test for the new code.

#### Scenario 6: empty groups transition back to restricted groups

**Suite:** serial/disruptive.

**Setup:** start from a Custom profile with no groups.

**Steps:** add `[X25519, secp256r1]`, wait for rollout, and assert the flags
reappear with `29,23`.

**Why:** the forward delete path can be correct while the reverse add path is
broken (for example, a cached empty `Settings` value). The two directions
together prove the reconciler is state-driven rather than transition-specific.

#### Scenario 7: rollback restores the original profile and flags

**Suite:** serial/disruptive, always present as cleanup.

**Setup:** any of Scenarios 3-6.

**Steps:** after assertions, restore the original `APIServer` profile in
`DeferCleanup`, wait for MCPs, and assert the operand flags match the original
settings again.

**Why:** a test that leaves the cluster on a Custom profile contaminates
later specs and can leave nodes rebooting. Rollback also proves the
`SecurityProfileWatcher` restart and reconciliation path works in reverse.

#### Scenario 8: operator handles unsupported group names

**Suite:** unit/controller; E2E only if a test cluster can persist such a
profile.

**Setup:** a profile containing both a recognized group and an unknown value.

**Steps:** derive settings and assert the recognized group is present while
the unknown value is reported/logged as unsupported and skipped.

**Why:** API skew and future group names are real. The operator must not crash
or discard the entire profile because one group is unknown. A strict E2E test
is hard if the API rejects unknown enum values, so this is usually a unit test
of `NewTLSConfigFromProfile` or `TLSGroupsToCurveIDs`.

#### Scenario 9: reconciliation is idempotent and repairs drift

**Suite:** non-disruptive or controller test.

**Setup:** NROP is healthy; optionally manually add a wrong curve flag to an
operand.

**Steps:** trigger/allow reconciliation and assert there is exactly one curve
flag with the expected value. Run the assertion twice.

**Why:** operators reconcile continuously. Duplicate flags (`flag=a
--flag=b`) or stale flags can change behavior or break restart. The existing
scheduler unit test covers repeated calls; this scenario extends the idea to
curves for both operands.

#### Scenario 10: scheduler positive handshake uses an allowed curve

**Suite:** non-disruptive (`test/e2e/tls`).

**Setup:** any profile with a non-empty group list.

**Steps:** port-forward to scheduler port `10259`, perform a normal TLS
handshake, read `tls.ConnectionState.CurveID`, and assert it is in the
profile's allowed curve set.

**Why:** argument correctness does not prove the scheduler binary accepts and
enforces the flag. This validates the real serving path. It also catches a
future scheduler that ignores `--tls-curve-preferences` or fails to start.

#### Scenario 11: RTE positive handshake uses an allowed curve

**Suite:** non-disruptive (`test/e2e/tls`).

**Setup:** RTE metrics is in `httptls` mode, port `2112`.

**Steps:** handshake with one RTE pod, read `CurveID`, assert membership in
the profile's group set, then fetch `/metrics` to prove the connection is
usable.

**Why:** RTE has its own flag parser and server configuration. It can diverge
from the scheduler even when both receive the same CSV. The metrics request
also proves the TLS policy did not merely start a listener that rejects all
traffic.

#### Scenario 12: scheduler rejects a disallowed curve

**Suite:** non-disruptive (`test/e2e/tls`).

**Setup:** a profile that does not allow one known Go-supported curve. With
the built-in profiles, `secp521r1` (25) is normally disallowed.

**Steps:** offer only the disallowed curve in the client's
`CurvePreferences`; assert the handshake fails with
`ErrTLSHandshakeRejected`.

**Why:** a positive test can pass if the server accepts everything and simply
happens to negotiate an allowed curve. The negative test proves the server is
actually enforcing a group allowlist rather than ignoring the setting.

#### Scenario 13: RTE rejects a disallowed curve

**Suite:** non-disruptive (`test/e2e/tls`).

**Setup:** same as Scenario 12.

**Steps:** run the single-curve negative probe against every RTE pod.

**Why:** RTE is a separate binary with its own curve validation. A scheduler
negative test does not prove RTE enforces the restriction. Running against all
pods also catches a DaemonSet rollout where one pod still uses old args.

#### Scenario 14: TLS 1.2 and TLS 1.3 profiles behave correctly

**Suite:** non-disruptive.

**Setup:** run once with Intermediate (TLS 1.2 minimum) and once with Modern
(TLS 1.3 minimum), or assert whichever profile is active and skip the
inapplicable part.

**Steps:** for TLS 1.2, assert the negotiated cipher is in the allowed list;
for TLS 1.3, skip cipher-list assertions and assert the curve is allowed. If a
legacy RSA key exchange is selected (`CurveID == 0`), skip the curve
assertion.

**Why:** TLS 1.3 cipher suites are not configurable, and not every TLS 1.2
cipher uses a curve. Testing both paths prevents false failures and prevents a
real absence of key exchange from being mistaken for success.

#### Scenario 15: PQ hybrid X25519MLKEM768 is not dropped

**Suite:** non-disruptive if the active profile/Go build chooses it;
otherwise a unit or focused serial test.

**Setup:** profile includes `X25519MLKEM768` (4588), which is in all built-in
profiles and supported by RTE v0.25.4.

**Steps:** assert the generated CSV contains `4588` and that handshakes never
negotiate a curve outside the allowed set. If the Go client and server choose a
non-PQ curve, do not require PQ negotiation; assert only that it is allowed.

**Why:** the feature was added specifically to support TLS groups, and 4588
is the one PQ hybrid currently in the default profile. A regression that
filters out all `4xxx` IDs would be invisible to classic-curve tests.

#### Scenario 16: unsupported PQ IDs 4587/4589 are handled explicitly

**Suite:** contract/unit test against the pinned RTE version; not a passing
E2E scenario until RTE supports them.

**Setup:** a Custom profile with `SecP256r1MLKEM768` (4587) or
`SecP384r1MLKEM1024` (4589).

**Steps:** assert the known behavior of the pinned RTE version. Today it
rejects those IDs as unsupported. Either skip with a clear reason or fail with
a message that points to the RTE upgrade requirement.

**Why:** OpenShift and library-go know about seven groups, but RTE v0.25.4
accepts only five. Without an explicit test, this will appear as a mysterious
RTE crash in the field. The test documents the compatibility boundary and
becomes a positive E2E test when RTE is upgraded.

#### Scenario 17: feature gate is unavailable

**Suite:** serial/disruptive precondition.

**Setup:** `TLSGroupPreferences` is not enabled.

**Steps:** detect the gate before mutating the profile; skip with a clear
message. If an update was attempted, verify whether groups persisted and
restore the original profile before skipping.

**Why:** Custom `groups` is gated. A test that hard-fails on a valid cluster
without the gate creates noise and hides real failures. A clear skip keeps the
suite meaningful across cluster configurations.

#### Scenario 18: FIPS mode excludes non-approved PQ groups

**Suite:** not in the default E2E suite; requires a dedicated FIPS lane.

**Setup:** FIPS-enabled cluster.

**Steps:** assert that non-FIPS-approved PQ groups are not selected or are
filtered according to platform policy.

**Why:** 4587, 4588, and 4589 are not FIPS-approved. Running this on a normal
cluster would be misleading; it needs its own environment and expectations.

#### Scenario 19: operator metrics positive handshake uses an allowed curve

**Suite:** non-disruptive E2E (`test/e2e/tls/tls_test.go`).

**Setup:** a cluster with a resolvable TLS profile, whether built-in or
Custom. The operator must be running with its metrics server on `8080`.

**Steps:**

1. Fetch the profile and convert its groups to allowed curve IDs.
2. Find the single manager Pod with `FindNUMAResourcesOperatorPod`.
3. Probe `8080` with `ProbeTLSState`.
4. Assert `state.CurveID` is non-zero and is a member of the allowed set.

**Why:** the operator has no `--tls-curve-preferences` argument to inspect. The
`tlsConfig` callback in `cmd/main.go` configures the controller-runtime metrics
server directly, so a real handshake is the only proof that
`CurvePreferences` reached the server. This catches a regression where the
callback is dropped from `metricsserver.Options.TLSOpts` or a vendored
controller-runtime change stops honoring it.

#### Scenario 20: operator metrics reject a disallowed curve

**Suite:** non-disruptive E2E.

**Steps:**

1. Resolve the allowed curve set and pick an outside curve with
   `FindDisallowedCurve`.
2. Find the manager Pod.
3. Probe `8080` with `ProbeTLSCurve` offering only that curve.
4. Assert the handshake fails and `errors.Is(err, ErrTLSHandshakeRejected)`.

**Why:** a positive probe only shows that some allowed curve worked. The
negative probe proves the server does not silently fall back to Go defaults
when it sees an unacceptable preference. For built-in profiles the outside
curve is normally P-521 (25), which is absent from `4588,29,23,24`.

**Skip conditions:** no groups in the profile, or no supported curve outside
the allowed set.

#### Scenario 21: operator metrics follow a profile change

**Suite:** disruptive serial E2E (optional hardening; combine with Scenario 3).

**Steps:**

1. Apply the restricted-group profile used by Scenario 3.
2. Wait for the operator profile watcher to restart the manager.
3. Re-run the Scenario 19 positive probe against the manager Pod.
4. Restore the original profile in `DeferCleanup` and probe again.

**Why:** the operator reads the profile at startup and relies on the
`SecurityProfileWatcher` restart to pick up changes. The non-disruptive tests
prove the current process; this scenario proves the restart path. It is
optional because it adds rollout time without changing the operand argument
checks already performed by Scenario 3.

#### Recommended minimum E2E set

If time is limited, implement these first:

1. Scenario 1 (built-in profile argument propagation, both operands).
2. Scenario 2 as a unit test (multi-node-group stale flag).
3. Scenario 3 (restricted Custom groups, both operands).
4. Scenario 5 (restricted to empty, both operands).
5. Scenario 10/11 (positive handshake curve, scheduler and RTE).
6. Scenario 12/13 (negative handshake curve, scheduler and RTE).
7. Scenario 19/20 (positive and negative operator metrics curve probes).

That set covers default behavior, real value changes, the delete-on-empty
branch, and runtime enforcement for all three TLS surfaces. Scenarios 4, 6,
8, 9, and 14-17 then harden the solution against transition, API-skew, and
environment variation.

---

## 9. Detailed E2E design and example code

The code below is a complete design for closing the curve gap. It is split
into reusable helpers, unit tests, non-disruptive specs, and one disruptive
serial spec.

### 9.1 Extend the RTE flag helper

This change is already present in `test/internal/tls/tls.go`; the block is
shown for review and for readers of older revisions:

```go
if err := matchTLSFlag(rteFlags, "--metrics-tls-min-version", expected.MinVersion, ds.Name); err != nil {
	return err
}
if err := matchTLSFlag(rteFlags, "--metrics-tls-cipher-suites", expected.CipherSuites, ds.Name); err != nil {
	return err
}
if err := matchTLSFlag(rteFlags, "--metrics-tls-curve-preferences", expected.CurvePreferences, ds.Name); err != nil {
	return err
}
```

No change to `matchTLSFlag` is required. Its empty semantics already match the
operator's delete-on-empty behavior.

### 9.2 Add a scheduler flag helper

Add this to `test/internal/tls/tls.go`. It mirrors the RTE helper and uses the
same comparator. The scheduler Deployment reference comes from
`NUMAResourcesScheduler.Status.Deployment`, which the scheduler controller
publishes after apply.

```go
var ErrSchedulerNotDeployed = errors.New("scheduler is not deployed")

func CheckSchedulerDeploymentTLSFlags(ctx context.Context, cli client.Client, expected objtls.Settings) error {
	nroSched := &nropv1.NUMAResourcesScheduler{}
	if err := cli.Get(ctx, client.ObjectKey{
		Name: objectnames.DefaultNUMAResourcesSchedulerCrName,
	}, nroSched); err != nil {
		if apierrors.IsNotFound(err) {
			return ErrSchedulerNotDeployed
		}
		return fmt.Errorf("failed to get NUMAResourcesScheduler: %w", err)
	}

	depRef := nroSched.Status.Deployment
	if depRef.Namespace == "" || depRef.Name == "" {
		return errors.New("scheduler deployment is not reported in NUMAResourcesScheduler status")
	}

	dp := &appsv1.Deployment{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: depRef.Namespace, Name: depRef.Name}, dp); err != nil {
		return fmt.Errorf("failed to get scheduler Deployment %s/%s: %w", depRef.Namespace, depRef.Name, err)
	}

	container := k8swgobjupdate.FindContainerByName(
		dp.Spec.Template.Spec.Containers, schedupdate.MainContainerName)
	if container == nil {
		return fmt.Errorf("scheduler container %q not found in deployment %q",
			schedupdate.MainContainerName, dp.Name)
	}

	flags := flagcodec.ParseArgvKeyValue(container.Args, flagcodec.WithFlagNormalization)
	if err := matchTLSFlag(flags, "--tls-min-version", expected.MinVersion, dp.Name); err != nil {
		return err
	}
	if err := matchTLSFlag(flags, "--tls-cipher-suites", expected.CipherSuites, dp.Name); err != nil {
		return err
	}
	return matchTLSFlag(flags, "--tls-curve-preferences", expected.CurvePreferences, dp.Name)
}
```

Imports needed: `pkg/objectupdate/sched` (aliased `schedupdate`),
`k8s.io/apimachinery/pkg/api/errors` (aliased `apierrors`). `objectnames`,
`flagcodec` and `appsv1` are already imported.

#### 9.2.1 Three different "no scheduler" situations

The scheduler is optional; its CR exists only when the user asked for it. The
helper must not turn "not installed" into "TLS mismatch":

| Situation | How it appears | Correct handling |
|---|---|---|
| CR does not exist | `cli.Get` returns `apierrors.IsNotFound` | `ErrSchedulerNotDeployed` → spec skips |
| CR exists, `Status.Deployment` empty | fresh install or failed reconcile | retryable error; `Eventually` waits |
| Deployment exists, container missing | wrong manifests/version skew | real failure |

The sentinel matters because the serial spec wraps the call in
`Eventually(...).Should(Succeed())`. Without it, an absent CR burns the whole
timeout and then fails the spec with `failed to get NUMAResourcesScheduler:
... not found`, which reads like a TLS problem during triage.

Skip before entering `Eventually`, do not `Skip` inside it:

```go
nroSched := &nropv1.NUMAResourcesScheduler{}
err := e2eclient.Client.Get(ctx, objects.NROSchedObjectKey(), nroSched)
if apierrors.IsNotFound(err) {
	Skip("NUMAResourcesScheduler is not deployed on this cluster")
}
Expect(err).ToNot(HaveOccurred(), "failed to get NUMAResourcesScheduler")

Eventually(func(g Gomega) {
	g.Expect(intls.CheckSchedulerDeploymentTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
}).WithTimeout(timeout).WithPolling(polling).Should(Succeed())
```

`Eventually` is Gomega's polling assertion: it runs the closure immediately,
re-runs it every `polling` interval while any `g.Expect(...).To(Succeed())`
fails, and fails the spec with the last error once `timeout` expires.

The polling window exists because NROP reacts through its own watch on
`APIServer/cluster`: the instant the `Update` returns, the DaemonSet and
Deployment still carry the previous arguments for a short, non-deterministic
time. Both helpers read object specs only (never pod readiness), so the window
is small and 30s with 5s polling is enough. On timeout the error names the
exact flag and object that stayed stale, e.g.
`--metrics-tls-curve-preferences should be absent or empty for this TLS profile daemonsetName="..." got="29,23"`.

Ginkgo's `Skip` panics; calling it from inside an `Eventually` closure is not
supported and can surface as a failure. The existence check above is a single
`Get`, so it costs nothing.

The RTE helper does not need this: `NUMAResourcesOperator` is mandatory for
every cluster running these suites, so a missing CR there is a real failure.

### 9.3 Add runtime curve probing

`tls.ConnectionState.CurveID` is available in the project's Go version. Add a
state-returning probe and delete the narrower `ProbeTLSSettings`:

```go
func ProbeTLSState(cli kubernetes.Interface, pod *corev1.Pod, port string) (tls.ConnectionState, error) {
	return ProbeTLSWithConfig(cli, pod, port)
}

func ProbeTLSWithConfig(cli kubernetes.Interface, pod *corev1.Pod, port string, opts ...tlsConfigOpt) (tls.ConnectionState, error) {
	var state *tls.ConnectionState
	cfg := &tls.Config{InsecureSkipVerify: true}
	for _, opt := range opts {
		opt(cfg)
	}
	err := remoteexec.PortForwardToPod(cli, pod, port, func(conn net.Conn) error {
		var handshakeErr error
		state, handshakeErr = tlsHandshake(conn, cfg)
		return wrapTLSHandshakeError(handshakeErr)
	})
	if state == nil {
		return tls.ConnectionState{}, err
	}
	return *state, err
}
```

The curve wrapper offers exactly one curve:

```go
func ProbeTLSCurve(cli kubernetes.Interface, pod *corev1.Pod, port string, curve tls.CurveID) (tls.ConnectionState, error) {
	return ProbeTLSWithConfig(cli, pod, port, WithCurve(curve))
}

func WithCurve(curve tls.CurveID) tlsConfigOpt {
	return func(cfg *tls.Config) {
		cfg.CurvePreferences = []tls.CurveID{curve}
	}
}
```

`ProbeTLSCipher` is unaffected from a caller's point of view: it keeps its
signature and simply delegates through `withCipher`, which caps the handshake
at TLS 1.2 and offers a single suite.

Add a helper to find a curve outside the allowed set:

```go
func FindDisallowedCurve(allowed []tls.CurveID) (tls.CurveID, error) {
	allowedSet := make(map[tls.CurveID]bool, len(allowed))
	for _, id := range allowed {
		allowedSet[id] = true
	}
	// Ordered simplest-first for readable failures. All are supported by Go 1.26.
	supported := []tls.CurveID{
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.X25519,
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
	}
	for _, id := range supported {
		if !allowedSet[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("all supported curves are allowed: %v", allowed)
}
```

Helper to derive allowed curve IDs:

```go
func CurveIDsFromProfile(profileSpec configv1.TLSProfileSpec) []tls.CurveID {
	ids, _ := libgocrypto.TLSGroupsToCurveIDs(profileSpec.Groups)
	return ids
}
```

#### 9.3.1 Migrating the `ProbeTLSSettings` call sites

There are exactly two callers, both in `test/e2e/tls/tls_test.go`; nothing in
`test/e2e/serial` or elsewhere references `ProbeTLSSettings`. The migration
is mechanical: the old function returned `(version uint16, cipherSuite
uint16, err error)`, while `ProbeTLSState` returns the whole
`tls.ConnectionState`, so `gotVersion` becomes `state.Version` and
`gotCipherID` becomes `state.CipherSuite`.

**Scheduler — `[test_id:90744] should adhere to openshift TLS profile - positive test`**

Before:

```go
By("probing the scheduler HTTPS endpoint to verify TLS connection is accepted")
gotVersion, gotCipherID, err := intls.ProbeTLSSettings(e2eclient.K8sClient, schedulerPod, schedulerSecurePort)
Expect(err).ToNot(HaveOccurred(), "failed to probe TLS settings on pod %q", schedulerPod.Name)

gotVersionName := tls.VersionName(gotVersion)
gotCipherName := tls.CipherSuiteName(gotCipherID)
klog.InfoS("negotiated TLS settings", "version", gotVersionName, "cipher", gotCipherName)

Expect(gotVersion).To(BeNumerically(">=", minVersion),
	"negotiated TLS version %s is below the expected minimum %s", gotVersionName, libgocrypto.TLSVersionToNameOrDie(minVersion))

allowedCipherNames := libgocrypto.OpenSSLToIANACipherSuites(tlsProfileSpec.Ciphers)
if gotVersion < tls.VersionTLS13 {
	Expect(gotCipherName).ToNot(BeEmpty(), "could not resolve negotiated cipher suite ID 0x%04x", gotCipherID)
	Expect(allowedCipherNames).To(ContainElement(gotCipherName),
		"negotiated cipher %s is not in the allowed set %v", gotCipherName, tlsProfileSpec.Ciphers)
}
```

After:

```go
By("probing the scheduler HTTPS endpoint to verify TLS connection is accepted")
state, err := intls.ProbeTLSState(e2eclient.K8sClient, schedulerPod, schedulerSecurePort)
Expect(err).ToNot(HaveOccurred(), "failed to probe TLS settings on pod %q", schedulerPod.Name)

gotVersionName := tls.VersionName(state.Version)
gotCipherName := tls.CipherSuiteName(state.CipherSuite)
klog.InfoS("negotiated TLS settings", "version", gotVersionName, "cipher", gotCipherName,
	"curve", state.CurveID.String())

Expect(state.Version).To(BeNumerically(">=", minVersion),
	"negotiated TLS version %s is below the expected minimum %s", gotVersionName, libgocrypto.TLSVersionToNameOrDie(minVersion))

allowedCipherNames := libgocrypto.OpenSSLToIANACipherSuites(tlsProfileSpec.Ciphers)
if state.Version < tls.VersionTLS13 {
	Expect(gotCipherName).ToNot(BeEmpty(), "could not resolve negotiated cipher suite ID 0x%04x", state.CipherSuite)
	Expect(allowedCipherNames).To(ContainElement(gotCipherName),
		"negotiated cipher %s is not in the allowed set %v", gotCipherName, tlsProfileSpec.Ciphers)
}
```

**RTE — `[test_id:88381] should service metrics over TLS adhering to cluster profile`**

Before:

```go
gotVersion, gotCipherId, err := intls.ProbeTLSSettings(e2eclient.K8sClient, &rtePod, rteMetricsPort)
Expect(err).ToNot(HaveOccurred(), "TLS Handshake failed on pod %q", rtePod.Name)
klog.InfoS("negotiated TLS settings",
	"version", tls.VersionName(gotVersion),
	"cipher", tls.CipherSuiteName(gotCipherId))

Expect(gotVersion).To(BeNumerically(">=", minVersion),
	"negotiated version %s below minimum %s",
	tls.VersionName(gotVersion), tls.VersionName(minVersion))
```

After:

```go
state, err := intls.ProbeTLSState(e2eclient.K8sClient, &rtePod, rteMetricsPort)
Expect(err).ToNot(HaveOccurred(), "TLS Handshake failed on pod %q", rtePod.Name)
klog.InfoS("negotiated TLS settings",
	"version", tls.VersionName(state.Version),
	"cipher", tls.CipherSuiteName(state.CipherSuite),
	"curve", state.CurveID.String())

Expect(state.Version).To(BeNumerically(">=", minVersion),
	"negotiated version %s below minimum %s",
	tls.VersionName(state.Version), tls.VersionName(minVersion))
```

Notes for the person applying this:

- The `ProbeTLSCipher` calls at `[test_id:90743]` and `[test_id:88382]` do
  **not** change; that wrapper kept its signature.
- In the RTE spec, the later `body, err := intls.FetchMetrics(...)` still
  compiles because `body` is a new variable (`:=` needs at least one).
- `tls.CurveID` has a `String()` method, so `state.CurveID.String()` is safe
  to log even when it is zero (`CurveID(0)` prints as `CurveID(0)`); a zero
  value means no ECDHE curve was negotiated and should be treated as a test
  failure in curve-specific specs.
- Do not reintroduce a thin `ProbeTLSSettings` wrapper: with the shared
  `ProbeTLSWithConfig` path there is nothing left for it to do, and keeping
  it would suggest `CurveID` is unavailable to callers.

Verification without a cluster:

```bash
GOCACHE=/tmp/nrop-go-cache GOFLAGS=-mod=vendor \
  /home/agent/.local/go/bin/go vet ./test/internal/tls ./test/e2e/tls
GOCACHE=/tmp/nrop-go-cache GOFLAGS=-mod=vendor \
  /home/agent/.local/go/bin/go test ./test/internal/tls -count=1
```

Before the migration `go vet ./test/e2e/tls` fails with
`undefined: intls.ProbeTLSSettings`; after the migration both commands are
clean. Running the Ginkgo suites themselves still requires a live NROP
cluster.

#### 9.3.2 Classifying curve handshake failures

A curve probe can fail in three different places, and only one of them proves
that the operand enforced `--tls-curve-preferences`:

| Raw error | Where it comes from | What it proves |
|---|---|---|
| `remote error: tls: handshake failure` (`tls.AlertError`) | server rejected the key share | server policy enforced |
| `tls: no supported elliptic curves for ECDHE` | client refused before writing ClientHello | nothing about the server |
| `tls: server selected unsupported group` | client detected a protocol violation | server bug |

The middle row exists because `crypto/tls` intersects `Config.CurvePreferences`
with its own defaults (`common.go`, `Config.curvePreferences`):

```
defaultCurvePreferences()  ∩  CurvePreferences  ∩  FIPS allowlist
```

`defaultCurvePreferences()` is `X25519MLKEM768, X25519, P-256, P-384, P-521`.
Pin anything outside that set (group `4587`, an unknown ID, `X25519` under
FIPS, or `X25519MLKEM768` with `GODEBUG=tlsmlkem=0`) and the intersection is
empty; the client aborts in `makeClientHello` with
`tls: no supported elliptic curves for ECDHE`. That string matches none of the
patterns in `wrapTLSHandshakeError`, so it is returned raw and
`errors.Is(err, ErrTLSHandshakeRejected)` is false.

Two strings that look relevant are not:

- `tls: CurvePreferences includes unsupported curve` is defensive code; the
  curve list is already filtered by the defaults, so standard callers cannot
  reach it.
- `tls: no ciphers available` does not exist in Go; the fixture in
  `TestWrapTLSHandshakeError` is fictional. Real cipher mismatch arrives as a
  server alert.

**Patch 1 — classify the client-side refusal**

```go
if strings.Contains(err.Error(), "no supported versions") ||
	strings.Contains(err.Error(), "no supported elliptic curves") ||
	strings.Contains(err.Error(), "no ciphers available") {
	return fmt.Errorf("%w: %w", ErrTLSClientConfigIncompatible, err)
}
```

Keeping it under `ErrTLSClientConfigIncompatible` preserves
`errors.Is(err, ErrTLSHandshakeRejected)` for callers that only care that the
handshake was refused, while letting specs assert the stricter
`ErrTLSServerRejected` when they need to prove server enforcement.

**Patch 2 — only pick curves the client can actually offer**

```go
// goClientCurves are offered by crypto/tls by default, so a rejection can
// only come from the server policy and not from the client filtering them out.
var goClientCurves = []tls.CurveID{
	tls.CurveP521,
	tls.CurveP256,
	tls.CurveP384,
	tls.X25519,
}

func FindDisallowedCurve(allowed []tls.CurveID) (tls.CurveID, error) {
	allowedSet := make(map[tls.CurveID]bool, len(allowed))
	for _, id := range allowed {
		allowedSet[id] = true
	}
	for _, id := range goClientCurves {
		if !allowedSet[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("every curve the Go client can offer is allowed: %v", allowed)
}
```

Ordering the list `P-521` first means the common Intermediate profile selects
`P-521` (25), which is also the curve the existing docs use for the negative
scenario. `X25519` is last on purpose: under FIPS it is removed client-side,
so a spec that ends up selecting it should skip rather than fail.

**Patch 3 — pin the real Go behaviour with a unit test**

```go
func TestWrapTLSHandshakeErrorClassifiesCurveRefusal(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() { _, _ = io.Copy(io.Discard, serverConn) }()

	client := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{0x1234},
	})
	err := client.Handshake()
	if err == nil {
		t.Fatal("expected the Go client to refuse a curve it cannot offer")
	}
	if !strings.Contains(err.Error(), "no supported elliptic curves") {
		t.Skipf("runtime produced %q; revisit this test on Go upgrades", err)
	}
	if got := wrapTLSHandshakeError(err); !errors.Is(got, ErrTLSClientConfigIncompatible) {
		t.Fatalf("got %v, want ErrTLSClientConfigIncompatible", got)
	}
}
```

This pins the exact runtime string instead of trusting a hand-written fixture,
and a Go upgrade that changes the wording surfaces as a skip with an explicit
message.

**Patch 4 — assert the right sentinel in the specs**

Positive curve check (whichever operand, `ProbeTLSState` is enough):

```go
state, err := intls.ProbeTLSState(e2eclient.K8sClient, pod, port)
Expect(err).ToNot(HaveOccurred())
Expect(state.CurveID).ToNot(BeZero(), "handshake succeeded without an ECDHE curve")
Expect(allowedCurveIDs).To(ContainElement(state.CurveID),
	"negotiated curve %s is not in the allowed set %v", state.CurveID, allowedCurveIDs)
```

Negative curve check:

```go
curveID, err := intls.FindDisallowedCurve(allowedCurveIDs)
if err != nil {
	Skip(err.Error())
}
_, err = intls.ProbeTLSCurve(e2eclient.K8sClient, pod, port, curveID)
Expect(err).To(HaveOccurred())
Expect(errors.Is(err, intls.ErrTLSServerRejected)).To(BeTrue(),
	"expected the server to enforce its curve list, got: %v", err)
```

Asserting `ErrTLSServerRejected` (not just `ErrTLSHandshakeRejected`) is what
keeps the coverage honest: a client-side refusal no longer counts as proof
that the operand honoured its flag.

`allowedCurveIDs` can be derived with `libgocrypto.TLSGroupsToCurveIDs` (or
the `CurveIDsFromProfile` helper from §9.3).

A zero `CurveID` means no ECDHE exchange happened. Treat it as a failure only
when the active profile contains ECDHE cipher suites; with an RSA-only Custom
profile the curve flag cannot influence the handshake, so skip instead.

### 9.4 Unit tests for the curve helper

The curve-match and stale-when-empty cases are already present in
`TestCheckRTEDaemonSetTLSFlags`. The examples below remain useful as additional
hardening cases:

```go
{
	name: "curve preferences match",
	nrop: newNROP(nropv1.NodeGroupStatus{
		DaemonSet: nropv1.NamespacedName{Namespace: "test-ns", Name: "rte-ds"},
	}),
	daemonSets: []client.Object{
		newRTEDaemonSetWithMainContainerArgs(
			"test-ns", "rte-ds",
			"--metrics-tls-min-version=VersionTLS12",
			"--metrics-tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"--metrics-tls-curve-preferences=29,23,24",
		),
	},
	expectedTLSSettings: objtls.Settings{
		MinVersion:       "VersionTLS12",
		CipherSuites:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		CurvePreferences: "29,23,24",
	},
	expectedError: "",
},
{
	name: "curve preferences mismatch",
	nrop: newNROP(nropv1.NodeGroupStatus{
		DaemonSet: nropv1.NamespacedName{Namespace: "test-ns", Name: "rte-ds"},
	}),
	daemonSets: []client.Object{
		newRTEDaemonSetWithMainContainerArgs(
			"test-ns", "rte-ds",
			"--metrics-tls-min-version=VersionTLS12",
			"--metrics-tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"--metrics-tls-curve-preferences=29,23",
		),
	},
	expectedTLSSettings: objtls.Settings{
		MinVersion:       "VersionTLS12",
		CipherSuites:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		CurvePreferences: "29,23,24",
	},
	expectedError: "mismatch",
},
{
	name: "no curves expected and flag absent",
	nrop: newNROP(nropv1.NodeGroupStatus{
		DaemonSet: nropv1.NamespacedName{Namespace: "test-ns", Name: "rte-ds"},
	}),
	daemonSets: []client.Object{
		newRTEDaemonSetWithMainContainerArgs(
			"test-ns", "rte-ds",
			"--metrics-tls-min-version=VersionTLS12",
			"--metrics-tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		),
	},
	expectedTLSSettings: objtls.Settings{
		MinVersion:   "VersionTLS12",
		CipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	},
	expectedError: "",
},
{
	name: "no curves expected but stale flag present",
	nrop: newNROP(nropv1.NodeGroupStatus{
		DaemonSet: nropv1.NamespacedName{Namespace: "test-ns", Name: "rte-ds"},
	}),
	daemonSets: []client.Object{
		newRTEDaemonSetWithMainContainerArgs(
			"test-ns", "rte-ds",
			"--metrics-tls-min-version=VersionTLS12",
			"--metrics-tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"--metrics-tls-curve-preferences=29,23,24",
		),
	},
	expectedTLSSettings: objtls.Settings{
		MinVersion:   "VersionTLS12",
		CipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	},
	expectedError: "should be absent or empty",
},
```

### 9.5 Non-disruptive E2E: operand arguments

Add to `test/e2e/tls/tls_test.go` inside the existing
`[tlscompliance][rte]` context, or in a sibling context with the same label:

```go
It("[test_id:TBD] should align TLS curve arguments with the cluster profile",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		expected, err := intls.RTESettingsFromClusterProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func(g Gomega) {
			g.Expect(intls.CheckRTEDaemonSetTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
			g.Expect(intls.CheckSchedulerDeploymentTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())
	})
```

This is safe on clusters with a built-in profile. It also asserts the empty
case automatically when the helper's expected string is empty.

### 9.6 Non-disruptive E2E: positive handshake curve

Place this as a third `It` in the top-level `Describe("TLS", ...)`, after
`[test_id:90744]`. It complements the argument check: the Deployment may carry
the right CSV while the server ignores it, fails to start, or silently falls
back to Go defaults.

```go
It("[test_id:TBD] should negotiate a curve allowed by the cluster TLS profile",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		By("getting the cluster TLS profile and its allowed curves")
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred(), "unable to get TLS profile from APIServer")

		allowedCurves := intls.CurveIDsFromProfile(profileSpec)
		klog.InfoS("cluster TLS curve policy", "groups", profileSpec.Groups, "curveIDs", allowedCurves)
		if len(allowedCurves) == 0 {
			Skip("cluster TLS profile defines no groups; Go defaults apply and there is nothing to verify")
		}

		By("getting the scheduler deployment and pods")
		nroSchedObj := &nropv1.NUMAResourcesScheduler{}
		nroSchedKey := objects.NROSchedObjectKey()
		Expect(e2eclient.Client.Get(ctx, nroSchedKey, nroSchedObj)).To(Succeed(), "failed to get %q", nroSchedKey.String())

		deployment, err := podlist.With(e2eclient.Client).DeploymentByOwnerReference(ctx, nroSchedObj.GetUID())
		Expect(err).ToNot(HaveOccurred(), "failed to get the scheduler deployment")
		Expect(deployment).ToNot(BeNil(), "scheduler deployment not found")

		pods, err := podlist.With(e2eclient.Client).ByDeployment(ctx, *deployment)
		Expect(err).ToNot(HaveOccurred(), "failed to get the scheduler pods")
		Expect(pods).ToNot(BeEmpty(), "no scheduler pods found")

		By("probing the scheduler HTTPS endpoint and reading the negotiated curve")
		state, err := intls.ProbeTLSState(e2eclient.K8sClient, &pods[0], schedulerSecurePort)
		Expect(err).ToNot(HaveOccurred(), "TLS handshake failed on scheduler pod %q", pods[0].Name)
		klog.InfoS("negotiated TLS settings",
			"pod", pods[0].Name,
			"version", tls.VersionName(state.Version),
			"cipher", tls.CipherSuiteName(state.CipherSuite),
			"curve", state.CurveID.String())

		if state.CurveID == 0 {
			Skip("the negotiated cipher suite did not use ECDHE; curve preferences do not apply")
		}
		Expect(allowedCurves).To(ContainElement(state.CurveID),
			"negotiated curve %s (id %d) is not allowed by profile groups %v; check --tls-curve-preferences on the scheduler deployment",
			state.CurveID, uint16(state.CurveID), profileSpec.Groups)
	})
```

Notes:

- Built-in profiles allow `4588, 29, 23, 24`, and `4588` is the Go client's
  first choice, so the negotiated curve is normally `X25519MLKEM768`. Never
  hardcode `X25519` (29) in the assertion.
- Skipping on an empty group list is deliberate: without groups the operands
  carry no curve flag and Go defaults apply.
- Skipping on `CurveID == 0` is deliberate too: a legacy RSA key exchange is
  not evidence about curve policy. The cipher/version positive spec
  (`90744`) remains responsible for catching a wrong negotiated cipher.
- The scheduler may run multiple replicas; probing `pods[0]` matches the
  existing specs. Iterate over all pods if HA schedulers are part of the
  supported matrix.

### 9.7 Non-disruptive E2E: negative handshake curve

How it works:

1. The client offers exactly one curve: `CurvePreferences = []tls.CurveID{25}`.
2. The server's curve list comes from `--tls-curve-preferences`
   (`4588,29,23,24` for the built-in profiles).
3. TLS 1.3 server: `preferredGroups = serverCurves ∩ clientCurves` is empty,
   so it sends `alertHandshakeFailure` (`handshake_server_tls13.go`). TLS 1.2
   server: `generateServerKeyExchange` finds no common curve and the server
   sends the same alert.
4. The client sees `remote error: tls: handshake failure`, i.e. a
   `tls.AlertError`, which `wrapTLSHandshakeError` maps to
   `ErrTLSServerRejected`.

Why this proves enforcement: with no flag, Go's server defaults include P-521,
so pinning 25 would succeed. A rejection therefore means the server's allowed
set excludes P-521, which is precisely the operator-applied flag.

Helper — only return curves the Go client can actually offer:

```go
var goClientCurves = []tls.CurveID{
	tls.CurveP521,
	tls.CurveP256,
	tls.CurveP384,
	tls.X25519,
}

func FindDisallowedCurve(allowed []tls.CurveID) (tls.CurveID, error) {
	allowedSet := make(map[tls.CurveID]bool, len(allowed))
	for _, id := range allowed {
		allowedSet[id] = true
	}
	for _, id := range goClientCurves {
		if !allowedSet[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("every curve the Go client can offer is allowed: %v", allowed)
}
```

```go
It("[test_id:TBD] should reject a curve not allowed by the cluster profile",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		allowed := intls.CurveIDsFromProfile(profileSpec)
		if len(allowed) == 0 {
			Skip("profile defines no groups; there is no curve restriction to verify")
		}
		disallowed, err := intls.FindDisallowedCurve(allowed)
		if err != nil {
			Skip(err.Error())
		}
		klog.InfoS("probing with a disallowed curve",
			"curve", disallowed.String(), "id", uint16(disallowed), "allowed", allowed)

		nroSchedObj := &nropv1.NUMAResourcesScheduler{}
		Expect(e2eclient.Client.Get(ctx, objects.NROSchedObjectKey(), nroSchedObj)).To(Succeed())
		deployment, err := podlist.With(e2eclient.Client).DeploymentByOwnerReference(ctx, nroSchedObj.GetUID())
		Expect(err).ToNot(HaveOccurred())
		pods, err := podlist.With(e2eclient.Client).ByDeployment(ctx, *deployment)
		Expect(err).ToNot(HaveOccurred())
		Expect(pods).ToNot(BeEmpty())

		state, err := intls.ProbeTLSCurve(e2eclient.K8sClient, &pods[0], schedulerSecurePort, disallowed)
		Expect(err).To(HaveOccurred(),
			"scheduler accepted curve %s (id %d) which the profile does not allow; negotiated=%s",
			disallowed, uint16(disallowed), state.CurveID)
		Expect(errors.Is(err, intls.ErrTLSServerRejected)).To(BeTrue(),
			"expected the scheduler to enforce its curve list, got: %v", err)
	})
```

Reading a failure:

- Handshake succeeds → the operand ignored or never received the flag.
- `ErrTLSClientConfigIncompatible` → the client could not offer the pinned
  curve; with `FindDisallowedCurve` this should not happen, so treat it as a
  bug in the selector.
- `ErrTLSServerRejected` → expected outcome.
- EOF, reset, timeout → infrastructure, not policy.

For RTE, run the same probe on port `2112` for every pod returned by
`getRTEPodsFromNRO`. Do not select `4587` or `4589`: RTE v0.25.4 rejects them
at argument parsing, and they are outside the client's default curve set.

### 9.8 Non-disruptive E2E: operator metrics curve probes

Operator metrics has no curve argument, so both specs go straight to a live
handshake on `8080`. The full walkthrough and line-by-line helper explanations
are in
[`nrop_tls_curves_automation.md#49-operator-metrics-endpoint-layer`](nrop_tls_curves_automation.md#49-operator-metrics-endpoint-layer).

```go
const operatorMetricsPort = "8080"

It("[test_id:TBD] should negotiate an allowed curve on operator metrics",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		allowed := intls.CurveIDsFromProfile(profileSpec)
		if len(allowed) == 0 {
			Skip("profile defines no groups; the operator server uses Go defaults")
		}

		nropObj := &nropv1.NUMAResourcesOperator{}
		Expect(e2eclient.Client.Get(ctx, objects.NROObjectKey(), nropObj)).To(Succeed())

		var operatorPod *corev1.Pod
		Eventually(func() error {
			operatorPod, err = deploy.FindNUMAResourcesOperatorPod(ctx, e2eclient.Client, nropObj)
			return err
		}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())

		state, err := intls.ProbeTLSState(e2eclient.K8sClient, operatorPod, operatorMetricsPort)
		Expect(err).ToNot(HaveOccurred())
		Expect(state.CurveID).ToNot(BeZero())
		Expect(allowed).To(ContainElement(state.CurveID))
	})

It("[test_id:TBD] should reject a disallowed curve on operator metrics",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		allowed := intls.CurveIDsFromProfile(profileSpec)
		if len(allowed) == 0 {
			Skip("profile defines no groups; no curve can be disallowed")
		}
		disallowed, err := intls.FindDisallowedCurve(allowed)
		if err != nil {
			Skip(err.Error())
		}

		nropObj := &nropv1.NUMAResourcesOperator{}
		Expect(e2eclient.Client.Get(ctx, objects.NROObjectKey(), nropObj)).To(Succeed())
		operatorPod, err := deploy.FindNUMAResourcesOperatorPod(ctx, e2eclient.Client, nropObj)
		Expect(err).ToNot(HaveOccurred())

		err = intls.ProbeTLSCurve(e2eclient.K8sClient, operatorPod, operatorMetricsPort, disallowed)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue())
	})
```

Why `Eventually` around discovery: `FindNUMAResourcesOperatorPod` requires
exactly one matching Pod. During a manager rollout there can briefly be zero
or two, which is transient rather than a test failure.

Two mistakes to avoid in this shape:

- declare the variable as `var operatorPod *corev1.Pod`. A value declaration
  (`operatorPod corev1.Pod`) does not compile: the helper returns
  `*corev1.Pod` (test/internal/deploy/find.go:33) and `ProbeTLSState` takes
  `*corev1.Pod` (test/internal/tls/tls.go:129), so a value form needs a copy
  (`*found`) plus `&operatorPod` at the call site;
- resolve the Pod inside the `It` or in `BeforeEach`, not in `BeforeAll`. A TLS
  profile change restarts the manager (the profile watcher cancels the manager
  context), so a Pod captured once can be gone by the time the spec probes it.

Do not replace test `85769`. That test remains the cheap availability check;
these specs add the policy assertion that `curl -k` cannot provide.

### 9.9 Disruptive serial E2E: restricted and empty groups

This test is expensive: every APIServer TLS profile change triggers a
MachineConfigPool rollout and node reboots. It should carry `Slow`, `Reboot`,
`Tier2`, and `feature:tlscompliance`.

Recommended flow:

1. Fetch `APIServer/cluster` and save the original profile.
2. Check `tlsGroupPreferencesEnabled`. Skip if false.
3. Update to a Custom profile with the Intermediate minimum version and
   ciphers, plus `groups: [X25519, secp256r1]`.
4. Immediately register `DeferCleanup` to restore the original profile and
   wait for MCPs.
5. Re-read the APIServer and verify the groups persisted. If they did not,
   skip after cleanup.
6. Wait for all MCPs (`Updating` then `Updated`) and verify node config.
7. Build `expected := objtls.NewSettings(cfg)` and assert both RTE and
   scheduler flags equal `29,23`.
8. Update to another Custom profile with no groups, still with valid
   minimum/ciphers.
9. Wait for MCPs again, then assert both operands have no curve flag.
10. Cleanup restores the original profile and waits for MCPs.

Example skeleton:

```go
It("[test_id:TBD] should reconcile TLS curve arguments for restricted and empty groups",
	Label(label.Tier2, label.Slow, label.Reboot, "feature:tlscompliance"),
	func(ctx context.Context) {
		fxt.IsRebootTest = true

		apiServerKey := client.ObjectKey{Name: ctrltls.APIServerName}
		apiServer := &configv1.APIServer{}
		Expect(e2eclient.Client.Get(ctx, apiServerKey, apiServer)).To(Succeed())
		originalSpec := apiServer.Spec.DeepCopy()

		enabled, err := tlsGroupPreferencesEnabled(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())
		if !enabled {
			Skip("TLSGroupPreferences feature gate is not enabled")
		}

		waitForMCPsAndVerifyNodes := func(ctx context.Context, reason string) {
			e2efixture.By("waiting for all MCPs to get updated")
			eg := errgroup.Group{}
			allMCPs := &machineconfigv1.MachineConfigPoolList{}
			Expect(e2eclient.Client.List(ctx, allMCPs)).To(Succeed())
			for i := range allMCPs.Items {
				mcp := allMCPs.Items[i]
				eg.Go(func() error {
					err := waitForMCPConditionWithRetry(ctx, &mcp,
						machineconfigv1.MachineConfigPoolUpdating,
						40*time.Minute, 20*time.Second)
					if err != nil {
						return err
					}
					return waitForMCPConditionWithRetry(ctx, &mcp,
						machineconfigv1.MachineConfigPoolUpdated,
						40*time.Minute, 20*time.Second)
				})
			}
			Expect(eg.Wait()).To(Succeed(), "failed while waiting for MCP update")

			e2efixture.By("verifying per-node MachineConfig alignment %s", reason)
			for i := range allMCPs.Items {
				Expect(verifyNodesMatchMCPConfig(ctx, &allMCPs.Items[i])).To(Succeed())
			}
		}

		restore := func(ctx context.Context) {
			Eventually(func(g Gomega) {
				current := &configv1.APIServer{}
				g.Expect(e2eclient.Client.Get(ctx, apiServerKey, current)).To(Succeed())
				current.Spec = *originalSpec
				g.Expect(e2eclient.Client.Update(ctx, current)).To(Succeed())
			}).WithTimeout(10*time.Minute).WithPolling(10*time.Second).Should(Succeed())
			waitForMCPsAndVerifyNodes(ctx, "after TLS curve rollback")
		}
		DeferCleanup(restore)

		updateProfile := func(ctx context.Context, profile *configv1.TLSSecurityProfile) {
			Eventually(func(g Gomega) {
				current := &configv1.APIServer{}
				g.Expect(e2eclient.Client.Get(ctx, apiServerKey, current)).To(Succeed())
				current.Spec.TLSSecurityProfile = profile
				g.Expect(e2eclient.Client.Update(ctx, current)).To(Succeed())
			}).WithTimeout(10*time.Minute).WithPolling(10*time.Second).Should(Succeed())
		}

		intermediate := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		restricted := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
			Custom: &configv1.CustomTLSProfile{
				TLSProfileSpec: configv1.TLSProfileSpec{
					MinTLSVersion: intermediate.MinTLSVersion,
					Ciphers:       append([]string(nil), intermediate.Ciphers...),
					Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
				},
			},
		}

		e2efixture.By("setting a restricted custom TLS group list")
		updateProfile(ctx, restricted)

		persisted := &configv1.APIServer{}
		Expect(e2eclient.Client.Get(ctx, apiServerKey, persisted)).To(Succeed())
		if persisted.Spec.TLSSecurityProfile == nil ||
			persisted.Spec.TLSSecurityProfile.Custom == nil ||
			!slices.Equal(persisted.Spec.TLSSecurityProfile.Custom.Groups, restricted.Custom.Groups) {
			Skip("the API server dropped the custom TLS groups; TLSGroupPreferences is not active")
		}

		waitForMCPsAndVerifyNodes(ctx, "after restricted groups")

		apply, _ := ctrltls.NewTLSConfigFromProfile(restricted.Custom.TLSProfileSpec)
		cfg := &tls.Config{}
		apply(cfg)
		expected := objtls.NewSettings(cfg)
		Expect(expected.CurvePreferences).To(Equal("29,23"))

		Eventually(func(g Gomega) {
			g.Expect(intls.CheckRTEDaemonSetTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
			g.Expect(intls.CheckSchedulerDeploymentTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())

		e2efixture.By("removing the custom TLS group list")
		emptyGroups := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
			Custom: &configv1.CustomTLSProfile{
				TLSProfileSpec: configv1.TLSProfileSpec{
					MinTLSVersion: intermediate.MinTLSVersion,
					Ciphers:       append([]string(nil), intermediate.Ciphers...),
				},
			},
		}
		updateProfile(ctx, emptyGroups)
		waitForMCPsAndVerifyNodes(ctx, "after empty groups")

		apply, _ = ctrltls.NewTLSConfigFromProfile(emptyGroups.Custom.TLSProfileSpec)
		cfg = &tls.Config{}
		apply(cfg)
		expected = objtls.NewSettings(cfg)
		Expect(expected.CurvePreferences).To(BeEmpty())

		Eventually(func(g Gomega) {
			g.Expect(intls.CheckRTEDaemonSetTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
			g.Expect(intls.CheckSchedulerDeploymentTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())
	})
```

The example inlines `waitForMCPsAndVerifyNodes` for readability; in production
code, factor the body out of test 88383 into a package-level helper. If the
team prefers minimal changes, keep both tests in the same `Context` and use one
shared closure. A package-level helper is easier to test and reuse.

### 9.10 Why the serial test needs both phases

A restricted-groups-only test proves that a non-empty curve list is propagated.
It does not prove that a transition from non-empty to empty removes the old
flag. The empty phase is the regression guard for this code:

```go
if metricsTLS.CurvePreferences != "" {
	flags.SetOption("--metrics-tls-curve-preferences", metricsTLS.CurvePreferences)
} else {
	flags.Delete("--metrics-tls-curve-preferences")
}
```

Without the empty phase, a future change could leave the stale flag in place
and all current tests would still pass.

### 9.11 Splitting into two specs: options and cost

The two phases are causally linked: the empty phase is only a regression guard
if a curve list existed immediately before it. Any split must preserve that,
and each APIServer update costs a full MCP rollout (tens of minutes) in the
serial lane.

**Option A - two independent specs (simple, one extra rollout)**

- `It("should apply the restricted curve list ...")`: capture the original
  profile, set `groups`, assert `29,23`, restore in `DeferCleanup`.
- `It("should delete the curve flags when groups are cleared")`: capture the
  original profile, set `groups: nil`, assert the flags are absent, restore.
- Before the second spec, assert the operands currently carry a non-empty curve
  flag. If the original profile has no groups, skip with a clear message;
  otherwise the delete assertion can pass without ever exercising deletion.
- Cost: four rollouts instead of three. Each distinct APIServer spec change
  re-renders every pool and rolls it; MCO does not deduplicate. The shared
  design performs `restricted -> empty -> original` (3), the independent design
  performs `restricted -> original -> empty -> original` (4). The extra rollout
  is the restore that separates the two specs. Restoring is not the same as
  clearing groups: it re-applies the saved original profile, which on a normal
  cluster is Intermediate and therefore still carries
  `4588,29,23,24`.

**Option B - Ordered context with shared setup (no extra rollout)**

```go
Context("[tlscompliance]RTE and scheduler comply with restricted TLS profile modifications",
	Label("curve"), Label(label.Reboot, label.Slow, label.Tier2), Ordered, func() {
		BeforeAll(func(ctx context.Context) {
			fxt.IsRebootTest = true
			// feature gate check, NROS check, capture originalSpec
			// DeferCleanup(restore) runs after the last spec in the container
		})
		It("[test_id:TBD] should apply the restricted curve list", func(ctx context.Context) { /* phase A */ })
		It("[test_id:TBD] should delete the curve flags when groups are cleared", func(ctx context.Context) { /* phase B */ })
	})
```

- Same three rollouts: apply, clear, restore.
- Ordered semantics: if the first spec fails, the second is skipped, which is
  correct because a broken apply phase makes the delete phase meaningless.
- Focus still works: with Ginkgo v2.28, `--ginkgo.focus='should delete the
  curve flags'` selects only that spec, and the container `BeforeAll` still
  runs. Focused alone it becomes the weaker "empty profile produces no flags"
  test.
- `fxt.IsRebootTest` belongs in `BeforeAll` so the fixture tolerates reboot
  drift for both specs.

Recommendation: Option B when the motivation is per-phase reporting and precise
titles; keep the single `It` with `By` steps when no structural change is
wanted. Option A only makes sense if the specs must be independently runnable
against different clusters, because it adds a rollout.

### 9.12 Reproducing the serial curve spec by hand

Preconditions: `TLSGroupPreferences` in `status.featureGates`, and the
`numaresourcesoperator` / `numaresourcesscheduler` CRs installed.

```bash
oc get featuregate cluster -o jsonpath='{range .status.featureGates[*].enabled[*]}{.name}{"\n"}{end}' | grep -x TLSGroupPreferences

# save the original profile; empty output means the field was unset
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile}' > /tmp/tls-original.json

# baseline generations, to see the rollout start
oc get mcp -o json | jq -r '.items[] | "\(.metadata.name) generation=\(.metadata.generation)"'
```

Phase A, restricted groups (min version and ciphers copied from the
Intermediate profile, groups `X25519,secp256r1` = curve IDs `29,23`):

```bash
oc patch apiserver cluster --type merge -p '{"spec":{"tlsSecurityProfile":{"type":"Custom","custom":{"minTLSVersion":"VersionTLS12","ciphers":["TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-CHACHA20-POLY1305","ECDHE-RSA-CHACHA20-POLY1305"],"groups":["X25519","secp256r1"]}}}}'
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile.custom.groups}{"\n"}'
```

Empty groups in the response means the API server pruned the field and the spec
would `Skip()`.

NROP reacts within seconds; the MCP rollout is unrelated to the operand args:

```bash
ref=$(oc get numaresourcesoperator numaresourcesoperator -o jsonpath='{range .status.nodeGroups[*]}{.daemonset.namespace}/{.daemonset.name}{"\n"}{end}')
for x in $ref; do ns=${x%/*}; name=${x#*/}; echo "== $ns/$name";
  oc get ds -n "$ns" "$name" -o jsonpath='{range .spec.template.spec.containers[?(@.name=="resource-topology-exporter")]}{.args}{"\n"}{end}' | tr ',' '\n' | grep -E 'tls|curve'; done

ref=$(oc get numaresourcesscheduler numaresourcesscheduler -o jsonpath='{.status.deployment.namespace}/{.status.deployment.name}')
ns=${ref%/*}; name=${ref#*/}
oc get deploy -n "$ns" "$name" -o jsonpath='{range .spec.template.spec.containers[?(@.name=="secondary-scheduler")]}{.args}{"\n"}{end}' | tr ',' '\n' | grep -E 'tls|curve'
```

Expect `--metrics-tls-curve-preferences=29,23` on every RTE DaemonSet and
`--tls-curve-preferences=29,23` on the scheduler Deployment.

Watch the rollout with:

```bash
watch -n 15 "oc get mcp -o custom-columns='NAME:.metadata.name,GEN:.metadata.generation,OBS:.status.observedGeneration,MACHINES:.status.machineCount,UPDATED:.status.updatedMachineCount,READY:.status.readyMachineCount'"
```

Phase B, clear the groups (`null` removes the field in a merge patch):

```bash
oc patch apiserver cluster --type merge -p '{"spec":{"tlsSecurityProfile":{"custom":{"groups":null}}}}'
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile.custom.groups}{"\n"}'
```

Re-run the two operand checks: the curve flags must be gone, while min version
and cipher flags remain.

Four rules that trip people up here:

- `custom` is inlined: `groups` sits directly under
  `spec.tlsSecurityProfile.custom`, next to `minTLSVersion` and `ciphers`.
  There is no `custom.tlsProfileSpec` level in the wire format, even though the
  Go type wraps the inline `TLSProfileSpec` struct.
- `groups: []` is rejected (`MinItems=1`). Absence of the key is the only way
  to express "no group restriction".
- Do not delete the whole `custom` block while keeping `type: Custom`: the
  operator fails at startup with `ErrCustomProfileNil`. Keep `minTLSVersion`
  and `ciphers`.
- `type: Intermediate` is **not** equivalent to "empty groups". For any
  non-Custom type, `GetTLSProfileSpec` returns
  `configv1.TLSProfiles[type]` from the compile-time table in the vendored
  `openshift/api`, and in this API version `Intermediate` carries
  `Groups: [X25519MLKEM768, X25519, secp256r1, secp384r1]`. The operator would
  keep `--metrics-tls-curve-preferences` / `--tls-curve-preferences` and only
  change the values to `4588,29,23,24`, while also flipping the min version and
  cipher flags. That is the `[test_id:88383]` scenario, not the
  delete-on-empty path this spec covers.

### 9.12.1 Back to the default profile

Clearing the field is the default. An unset `spec.tlsSecurityProfile` means "no
opinion" and every component falls back to Intermediate, which is exactly what
`GetTLSProfileSpec` does with a `nil` profile. The merge patch with `null` is
idempotent, so it also works when the field is already absent and it does not
need a prior read:

```bash
oc patch apiserver cluster --type merge -p '{"spec":{"tlsSecurityProfile":null}}'
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile}{"\n"}'
```

Expect an empty line. `type: Intermediate` also lands on the default profile,
but the explicit value looks like a deliberate non-default choice on later
reads.

Do not confuse the three states:

- removing the whole `tlsSecurityProfile` (or the `null` patch above) rebuilds
  the default Intermediate profile;
- `type: ""` is not a valid value, the discriminator enum is
  `Old;Intermediate;Modern;Custom`;
- deleting only `groups` from a `Custom` profile is *not* the default, it is the
  third state where `type` stays `Custom` and the operands' curve flags are
  deleted.

Default does **not** mean "no curve restrictions". The resulting operand state
depends only on the resolved `TLSProfileSpec`:

| APIServer spec | Min version flag | Curve flag on both operands |
| --- | --- | --- |
| unset (default) / `Intermediate` | `VersionTLS12` | `4588,29,23,24` |
| `Old` | `VersionTLS10` | `4588,29,23,24` |
| `Modern` | `VersionTLS13` | `4588,29,23,24` |
| `Custom` + `groups: [X25519, secp256r1]` | per spec | `29,23` |
| `Custom` without `groups` | per spec | flag deleted |

So only the last row tests delete-on-empty; every built-in profile carries the
four default groups in this vendored API. After the patch the operator restarts,
re-renders both operands, and the MCPs roll because the kubelet config follows
the same profile.

Restore:

```bash
if [ -s /tmp/tls-original.json ] && [ "$(cat /tmp/tls-original.json)" != "null" ]; then
  oc patch apiserver cluster --type=json -p "[{\"op\":\"add\",\"path\":\"/spec/tlsSecurityProfile\",\"value\":$(cat /tmp/tls-original.json)}]"
else
  oc patch apiserver cluster --type=json -p '[{"op":"remove","path":"/spec/tlsSecurityProfile"}]'
fi
```

That is three APIServer mutations and three rollouts: restricted, empty,
restore. The per-node check the helper performs compares each node's
`machineconfiguration.openshift.io/currentConfig` annotation with the MCP's
`status.configuration.name`.

---

## 10. Additional example programs

### 10.1 Print the cluster profile and derived operand settings

This is useful before writing a test because it shows exactly what the
operator will put on the command line.

```go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"

	configv1 "github.com/openshift/api/config/v1"
	ctrltls "github.com/openshift/controller-runtime-common/pkg/tls"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	objtls "github.com/openshift-kni/numaresources-operator/pkg/objectupdate/tls"
)

func main() {
	ctx := context.Background()
	cfg, err := config.GetConfig()
	if err != nil {
		panic(err)
	}
	if err := configv1.Install(scheme.Scheme); err != nil {
		panic(err)
	}
	cli, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		panic(err)
	}

	profile, err := ctrltls.FetchAPIServerTLSProfile(ctx, cli)
	if err != nil {
		panic(err)
	}
	apply, unsupported := ctrltls.NewTLSConfigFromProfile(profile)
	tlsCfg := &tls.Config{}
	apply(tlsCfg)
	settings := objtls.NewSettings(tlsCfg)

	fmt.Fprintf(os.Stdout, "profile ciphers: %v\n", profile.Ciphers)
	fmt.Fprintf(os.Stdout, "profile groups:  %v\n", profile.Groups)
	fmt.Fprintf(os.Stdout, "min version:    %s\n", settings.MinVersion)
	fmt.Fprintf(os.Stdout, "ciphers:        %s\n", settings.CipherSuites)
	fmt.Fprintf(os.Stdout, "curves:         %s\n", settings.CurvePreferences)
	fmt.Fprintf(os.Stdout, "unsupported:    %v\n", unsupported)
}
```

Run it with a kubeconfig pointing at the test cluster. It does not mutate
anything.

### 10.2 Standalone handshake inspector

After port-forwarding the scheduler or RTE port from another terminal, this
program prints the negotiated version, cipher, and curve:

```go
package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	addr := "127.0.0.1:10259"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // debugging only; the port-forward name does not match the cert
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "handshake failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Printf("version: %s\n", tls.VersionName(state.Version))
	fmt.Printf("cipher:  %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("curve:   %s (%d)\n", state.CurveID.String(), uint16(state.CurveID))
}
```

Run:

```bash
oc -n <nrop-namespace> port-forward pod/<scheduler-pod> 10259:10259
go run ./path/to/inspector.go 127.0.0.1:10259
```

For RTE, forward port `2112` instead.

### 10.3 Table-driven group mapping test

```go
func TestTLSGroupsToCurveIDs(t *testing.T) {
	tests := []struct {
		name     string
		group    configv1.TLSGroup
		wantID   tls.CurveID
		wantOK   bool
	}{
		{name: "P-256", group: configv1.TLSGroupSecP256r1, wantID: tls.CurveP256, wantOK: true},
		{name: "P-384", group: configv1.TLSGroupSecP384r1, wantID: tls.CurveP384, wantOK: true},
		{name: "P-521", group: configv1.TLSGroupSecP521r1, wantID: tls.CurveP521, wantOK: true},
		{name: "X25519", group: configv1.TLSGroupX25519, wantID: tls.X25519, wantOK: true},
		{name: "PQ X25519", group: configv1.TLSGroupX25519MLKEM768, wantID: tls.X25519MLKEM768, wantOK: true},
		{name: "PQ P-256", group: configv1.TLSGroupSecP256r1MLKEM768, wantID: tls.SecP256r1MLKEM768, wantOK: true},
		{name: "PQ P-384", group: configv1.TLSGroupSecP384r1MLKEM1024, wantID: tls.SecP384r1MLKEM1024, wantOK: true},
		{name: "unknown", group: configv1.TLSGroup("not-a-group"), wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := libgocrypto.TLSGroupToCurveID(tt.group)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.wantID {
				t.Fatalf("id = %d, want %d", got, tt.wantID)
			}
		})
	}
}
```

### 10.4 Parse and assert one operand's flags

This is the same pattern used by the test helpers:

```go
func assertCurveFlag(t *testing.T, args []string, expected string) {
	t.Helper()
	flags := flagcodec.ParseArgvKeyValue(args, flagcodec.WithFlagNormalization)
	value, found := flags.GetFlag("--tls-curve-preferences")
	if expected == "" {
		if found && value.Data != "" {
			t.Fatalf("expected no curve flag, got %q", value.Data)
		}
		return
	}
	if !found || value.Data != expected {
		t.Fatalf("curve flag = %q (found=%v), want %q", value.Data, found, expected)
	}
}
```

### 10.5 `oc` debugging commands

```bash
# Active profile
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile}{"\n"}'

# Derived group names, when the profile is Custom
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile.custom.groups}{"\n"}'

# Scheduler deployment TLS args
oc get deploy -A -l app=secondary-scheduler \
  -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{.spec.template.spec.containers[0].args}{"\n"}{end}'

# RTE DaemonSet TLS args
oc get ds -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{.spec.template.spec.containers[0].args}{"\n"}{end}' \
  | grep -E 'resource-topology-exporter|tls'

# Feature gates reported by the cluster
oc get featuregate cluster -o jsonpath='{range .status.featureGates[*]}{.version}: {.enabled[*].name}{"\n"}{end}'
```

---

## 11. Troubleshooting

### The curve flag is absent but the profile has groups

Check, in order:

1. Is the operator running code that includes curve support?
2. Did `FetchAPIServerTLSProfile` return groups? Some API versions drop the
   field when the feature gate is disabled.
3. Did `NewTLSConfigFromProfile` report unsupported groups in the operator log?
4. Is the test reading the correct container? Scheduler:
   `secondary-scheduler`; RTE: `resource-topology-exporter`.
5. Is the DaemonSet/Deployment reconciled by NROP, or is it a stale manually
   edited object?

### The flag exists but the handshake curve differs

This is expected. Go ignores the order in `CurvePreferences` and selects a
group using its internal preference order. Assert membership in the allowed
set, not the first list element.

### `state.CurveID` is zero

Zero means no group was negotiated, typically because a legacy RSA key
exchange was selected. This should not happen with the normal OpenShift
profiles, but a Custom profile with only RSA cipher suites can produce it.
In a positive curve test, fail when the profile contains ECDHE cipher suites
(the operand should have negotiated a curve) and skip when it does not.

### Negative curve probe fails with `no supported elliptic curves for ECDHE`

The Go client refused before sending ClientHello, so the server was never
asked. This happens when the pinned curve is filtered out of
`Config.curvePreferences` (see §9.3.2): group `4587`, an unknown ID, `X25519`
under FIPS, or `X25519MLKEM768` with `GODEBUG=tlsmlkem=0`. Pick the negative
curve with `FindDisallowedCurve`, which only returns curves the client can
offer, and assert `ErrTLSServerRejected` so this situation cannot pass as
server enforcement.

### RTE crashes with `unsupported curve ID 4587` or `4589`

The pinned RTE version does not support those two PQ hybrid IDs even though
the OpenShift API and library-go know about them. Restrict the test profile to
the IDs supported by RTE, or track the RTE upgrade as a prerequisite.

### TLS 1.3 cipher assertions fail

TLS 1.3 cipher suites are fixed in Go and are not configurable. The operator
correctly leaves `CipherSuites` empty for a Modern profile. Version/cipher
tests must skip cipher assertions when the negotiated version is TLS 1.3.

### Serial `BeforeSuite` fails: `Not enough nodes with "single-numa-node" topology`

This failure happens in `BeforeSuite`, before any spec is selected to run, so
nothing is wrong with your `--ginkgo.focus` or `--ginkgo.label-filter` (look
for `Will run N of 161 specs` above the failure). `CheckNodesTopology` lists
`NodeResourceTopology` objects, keeps the ones whose `topologyManagerPolicy`
attribute equals `single-numa-node`, and requires at least
`minNumberOfNodesWithSameTopology = 2`
(`test/e2e/serial/config/config.go:54`).

Inspect what the cluster reports:

```bash
oc get nrt -o json | jq -r '.items[] | .metadata.name + "\t" +
  ((.attributes[] | select(.name=="topologyManagerPolicy") | .value) // "missing")'
```

The serial suite expects a pre-configured TAS cluster: at least two workers
with `topologyManagerPolicy: single-numa-node`, selected by an NRO
`NodeGroup`, with RTE running so each publishes an NRT. After this check
passes, `validateNRTAvailability` still requires an NRT for every worker and
`validateSMTAlignmentDisabled` requires SMT alignment to be disabled.

The `E2E_NROP_DEVICE_TYPE_*` errors printed before the failure are
informational. If you cannot get a TAS cluster, use `test/e2e/tls` for curve
handshake work; only the serial spec mutates `APIServer/cluster` and rolls
MCPs.

### Can the serial curve spec run with a single worker?

Not with the binary as it stands. The gate is unconditional and not
configurable:

- `BeforeSuite` runs `CheckNodesTopology` before focus or label filtering can
  help; there is no `--ginkgo` flag that skips setup nodes.
- The threshold is a constant: `minNumberOfNodesWithSameTopology = 2`
  (`test/e2e/serial/config/config.go:54`). No environment variable overrides it.
- Relaxing just that number is not enough: `Setup()` still assumes a full TAS
  fixture. `waitResourcesAvailable` waits for numacell resources on every NRT,
  `LabelNodes` labels the Kubernetes Node behind every NRT, and `SetupFixture`
  requires the NRO and NROS objects to exist.

Options, in order of preference:

1. Move the spec to `test/e2e/tls`, whose `BeforeSuite` only asserts that
   clients are available. Nothing in the curve spec body touches nodes; only
   `fxt.IsRebootTest = true`, `e2efixture.By`, and four helpers in
   `configuration.go:2370-2466` (`tlsGroupPreferencesEnabled`,
   `waitForMCPConditionWithRetry`, `verifyNodesMatchMCPConfig`,
   `waitForMCPsAndVerifyNodes`) need to come along. This is the durable fix and
   also removes the false requirement for future maintainers.
2. Point a second worker at `topologyManagerPolicy: single-numa-node`. The
   check only reads the NRT attribute, and a node with a single NUMA cell
   satisfies it, so no special NUMA hardware is needed.
3. Synthesize a second NRT plus a matching Node object on a disposable
   cluster. This can get past the count, but it is brittle: the synthetic NRT
   must claim numacell resources, the synthetic Node must carry the worker
   role, and NRO node-group discovery may then include it. Never use this in
   CI.

### Serial `BeforeSuite` fails: `NRT data missing` for a plain worker

Seeing `NRT data missing` / `failed to find NRT for "<node>"` means the
two-node count now passes (this check runs after it) but one node with the
`node-role.kubernetes.io/worker` label has no `NodeResourceTopology`. The
suite decides "worker" purely by that label:

```go
workers, _ := nodes.GetWorkers(...)      // label selector, Ready is irrelevant
for _, node := range workers {
    e2enrt.FindFromList(nrtList.Items, node.Name)   // must exist
}
```

Typical cause: RTE runs only where the NRO `nodeGroups` point. With a
`worker-cnf` pool plus a plain `worker` pool, only the `worker-cnf` nodes have
RTE pods and therefore NRTs.

Inspect the mismatch:

```bash
oc get nodes -l node-role.kubernetes.io/worker
oc get nrt -o json | jq -r '.items[] | .metadata.name'
oc get numaresourcesoperator -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.spec.nodeGroups}{"\n"}{end}'
oc get mcp
```

Fix it by covering the plain pool in the operator CR, keeping the existing
group and adding the missing pool name:

```yaml
spec:
  nodeGroups:
  - poolName: worker-cnf
  - poolName: worker
```

Then wait for the new RTE DaemonSet and the NRT to appear. That node becomes
TAS-enabled too, so the kubelet checks apply to it: its NRT
`topologyManagerPolicy`/`topologyManagerScope` attributes must match its
kubelet config (`none`/`container` by default) and `full-pcpus-only` must not
be `true`. The `Topology Manager Scope not set in kubeletconfig, fixing`
messages are informational.

On a lab cluster only, removing the role label instead is reversible:

```bash
oc label node <plain-worker> node-role.kubernetes.io/worker-
```

That stops the suite from treating the node as a worker but may affect other
workload scheduling, so do not do it in CI.

### Serial `BeforeSuite` fails: `SMT alignment enabled for node`

This is the last of the four `CheckNodesTopology` gates. Required value:
`false`, or leave the option unset. `true` fails. This is a test-suite
requirement only; NROP itself never reads this setting, so production clusters
may use `true` if the workload wants SMT-aligned allocations.

When the kubelet config is owned by a PerformanceProfile, PAO sets
`full-pcpus-only: true` by default, so the option is never absent and "leave it
unset" is not available. Set `spec.cpu.full-pcpus-only: false` on the
PerformanceProfile instead; patching the generated `KubeletConfig` directly is
liable to be reconciled away. The suite reads the MCO `KubeletConfig` CRs
(`nrovalidate/validator/kubeletconfig.go:96`), not the PerformanceProfile, so
verify the generated object, not just the CR you edited.

If the check still fails after setting `false`, inspect the exact object the
suite reads:

```bash
oc get kubeletconfig -o json | jq -r '.items[] |
  [.metadata.name,
   (.spec.machineConfigPoolSelector.matchLabels | tostring),
   ((.spec.kubeletConfig.cpuManagerPolicyOptions // {}) | tostring)] | @tsv'
oc get performanceprofile <name> -o jsonpath='{.metadata.annotations}{"\n"}'
oc get mcp
```

The usual causes, in order:

- PAO has not reconciled yet: the `performance-*` KubeletConfig still carries
  `"full-pcpus-only":"true"` until the MCP finishes rolling.
- A `kubeletconfig.experimental` annotation on the PerformanceProfile sets the
  option again; annotations are applied on top of `spec.cpu.full-pcpus-only`.
- The patched PerformanceProfile is not the one whose KubeletConfig selects the
  TAS pool (check the `machineConfigPoolSelector` column).
- The `KubeletConfig` was patched directly and PAO reverted it.

For every TAS-enabled node the suite reads its kubelet config and fails when
`cpuManagerPolicyOptions["full-pcpus-only"]` parses as `true`:

```go
v, ok := kconfig.CPUManagerPolicyOptions["full-pcpus-only"]
if !ok { continue }                 // absent means SMT alignment disabled
enable, _ := strconv.ParseBool(v)
if enable { ... "SMT alignment enabled for node" }
```

The suite needs it off because its CPU accounting assumes per-CPU (not
per-physical-core) allocation; its own configuration specs write
`"cpuManagerPolicyOptions": {"full-pcpus-only": "false"}` when they edit a
PerformanceProfile (`configuration.go:637,679`).

Find who owns the setting:

```bash
oc get kubeletconfig -o yaml | grep -B6 -A6 cpuManagerPolicyOptions
oc get performanceprofile -o yaml | grep -B4 -A4 full-pcpus
```

Set it to `"false"` (or remove the option, since absence passes) in the
PerformanceProfile (`spec.cpu.full-pcpus-only: false` or the
`kubeletconfig.experimental` annotation) or in the `KubeletConfig` CR, then
expect the owning MCP to roll and reboot its nodes once.

### Curve spec times out after 40 minutes: `failed while waiting for mcp update`

Symptom: after `Setting a restricted custom TLS group list (...)`, the log
repeats `mcp: "worker" conditionType: "Updating" status is: "False"` every 20
seconds for 40 minutes, then fails in the spec and again in `DeferCleanup`.
The TLS assertions never run.

Cause: `waitForMCPsAndVerifyNodes` requires every MCP to pass through
`Updating=True` before it waits for `Updated=True`. Two situations break that
contract:

- A pool with `status.machineCount: 0` never enters `Updating`; it re-renders
  and stays `Updated=True`. Typical when a `worker` MCP still exists but all
  nodes were moved into `worker-cnf`.
- Even a non-empty pool can finish rolling faster than the 20 second poll, so
  the transient `Updating=True` window is missed. This is a real race, not just
  an empty-pool corner case.

A third variant looks different in the log: you see
`verifying per-node MachineConfig alignment ...` followed by
`all nodes match MCP config`, and then a new `waiting for all MCPs to get
updated` that prints nothing. That is a duplicate wait: the previous call
already completed the rollout, so the new call is waiting for an `Updating`
transition that cannot happen again. `waitForMCPConditionWithRetry` only logs
when the MCP resourceVersion changes and the condition is still `False`, so a
settled pool produces no output for the full 40 minute budget. Keep exactly one
wait per APIServer mutation.

The silence has a second layer worth knowing:
`Waiter.ForMachineConfigPoolCondition` (internal/wait/mcp.go:45) takes the MCP
object from the list call made when the helper started and refuses to evaluate
the condition at all while the live object still has that same
`resourceVersion`. A settled pool therefore never even reaches the
`conditionType ... status is False` log line, so an extra wait looks like a
hang at 100% of the budget with no output whatsoever.

Because klog prefixes every line with `file.go:NNN`, a stale binary is easy to
spot: compare the reported line number with the same statement in the working
copy. In this revision `all nodes match MCP config` lives at
configuration.go:2445; a run that prints 2447 was built from a source with two
extra lines above it, which is exactly one `waitForMCPsAndVerifyNodes` call plus
its blank line. Rebuild before drawing conclusions:

```bash
grep -n "waitForMCPsAndVerifyNodes" test/e2e/serial/tests/configuration.go
make binary-e2e-serial
```

The curve spec must show three calls in its body - rollback cleanup, restricted
groups, empty groups - plus the function definition. A fourth call means the
duplicate is still in the source the binary was built from.

Diagnose:

```bash
oc get mcp -o custom-columns='NAME:.metadata.name,GEN:.metadata.generation,OBS:.status.observedGeneration,MACHINES:.status.machineCount,UPDATED:.status.updatedMachineCount,READY:.status.readyMachineCount'
oc get mcp worker -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}'
```

`MachineCount:0` with `Updated=True` and `Updating=False` is the failure
signature. Swapping `Updating` for `Updated` is **not** enough: right after the
APIServer patch every pool still reports the previous `Updated=True`, so the
wait would return before the rollout starts. A baseline captured before the
mutation is required.

#### Step 1: snapshot the pools before changing the profile

```go
type mcpRenderState struct {
	generation int64
	rendered   string
}

func snapshotMCPRenderState(ctx context.Context) map[string]mcpRenderState {
	GinkgoHelper()
	mcps := &machineconfigv1.MachineConfigPoolList{}
	Expect(e2eclient.Client.List(ctx, mcps)).To(Succeed())
	state := make(map[string]mcpRenderState, len(mcps.Items))
	for i := range mcps.Items {
		mcp := &mcps.Items[i]
		state[mcp.Name] = mcpRenderState{
			generation: mcp.Generation,
			rendered:   mcp.Spec.Configuration.Name,
		}
	}
	return state
}
```

The MCO writes the rendered MachineConfig reference into `spec.configuration`,
so every re-render bumps `metadata.generation`. That bump is the signal that
the pool reacted to the profile change at all.

#### Step 2: wait on a terminal predicate

```go
func waitForMCPsAndVerifyNodes(ctx context.Context, reason string, baseline map[string]mcpRenderState) {
	GinkgoHelper()
	const (
		mcpUpdateTimeout = 40 * time.Minute
		mcpUpdatePolling = 10 * time.Second
	)

	e2efixture.By("waiting for all MCPs to roll out the new rendered config")
	Eventually(func(g Gomega) {
		mcps := &machineconfigv1.MachineConfigPoolList{}
		g.Expect(e2eclient.Client.List(ctx, mcps)).To(Succeed())
		for i := range mcps.Items {
			mcp := &mcps.Items[i]

			g.Expect(mcp.Spec.Paused).To(BeFalse(),
				"MCP %q is paused; its rollout cannot complete", mcp.Name)
			g.Expect(mcp.Generation).To(BeNumerically(">", baseline[mcp.Name].generation),
				"MCP %q did not re-render after the profile change (still %q, generation %d)",
				mcp.Name, mcp.Spec.Configuration.Name, mcp.Generation)
			g.Expect(mcp.Status.ObservedGeneration).To(Equal(mcp.Generation),
				"MCP %q has not observed generation %d", mcp.Name, mcp.Generation)
			g.Expect(mcp.Status.Configuration.Name).To(Equal(mcp.Spec.Configuration.Name),
				"MCP %q has not published the rendered config", mcp.Name)

			updated := metahelper.FindStatusCondition(mcp.Status.Conditions, string(machineconfigv1.MachineConfigPoolUpdated))
			g.Expect(updated).ToNot(BeNil(), "MCP %q has no Updated condition", mcp.Name)
			g.Expect(updated.Status).To(Equal(corev1.ConditionTrue), "MCP %q is not Updated", mcp.Name)
			g.Expect(mcp.Status.UpdatedMachineCount).To(Equal(mcp.Status.MachineCount),
				"MCP %q updated %d/%d machines", mcp.Name, mcp.Status.UpdatedMachineCount, mcp.Status.MachineCount)

			if degraded := metahelper.FindStatusCondition(mcp.Status.Conditions, string(machineconfigv1.MachineConfigPoolDegraded)); degraded != nil {
				g.Expect(degraded.Status).To(Equal(corev1.ConditionFalse),
					"MCP %q is Degraded: %s", mcp.Name, degraded.Message)
			}
		}
	}).WithContext(ctx).WithTimeout(mcpUpdateTimeout).WithPolling(mcpUpdatePolling).Should(Succeed())

	e2efixture.By("verifying per-node MachineConfig alignment %s", reason)
	final := &machineconfigv1.MachineConfigPoolList{}
	Expect(e2eclient.Client.List(ctx, final)).To(Succeed())
	for i := range final.Items {
		Expect(verifyNodesMatchMCPConfig(ctx, &final.Items[i])).To(Succeed(),
			"node config mismatch for MCP %q", final.Items[i].Name)
	}
}
```

Why each assertion exists:

| Assertion | Purpose |
|---|---|
| `Paused == false` | a paused pool never rolls; fail with a clear message instead of a 40 minute timeout |
| `Generation > baseline` | proves this change caused a re-render; replaces the `Updating` heuristic |
| `ObservedGeneration == Generation` | the MCO has processed the new render |
| `status.configuration == spec.configuration` | the rendered config has been published |
| `Updated == True` | every node applied that render |
| `UpdatedMachineCount == MachineCount` | names the lagging pool in the failure message |
| `Degraded == False` | a broken rollout is reported in the aggregated error |

Note the status types: MCP conditions use `corev1.ConditionStatus`, not
`metav1.ConditionStatus`.

#### Step 3: pass a baseline from every call site

There are six call sites (`configuration.go:1874,1877,1921,1933,1959,1986`).
Take the snapshot immediately before the APIServer update, never after it:

```go
updateProfile := func(ctx context.Context, profile *configv1.TLSSecurityProfile) bool {
	current := &configv1.APIServer{}
	Expect(e2eclient.Client.Get(ctx, apiServerKey, current)).To(Succeed())
	if reflect.DeepEqual(current.Spec.TLSSecurityProfile, profile) {
		return false
	}
	Eventually(func(g Gomega) {
		obj := &configv1.APIServer{}
		g.Expect(e2eclient.Client.Get(ctx, apiServerKey, obj)).To(Succeed())
		obj.Spec.TLSSecurityProfile = profile
		g.Expect(e2eclient.Client.Update(ctx, obj)).To(Succeed())
	}).WithTimeout(10 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
	return true
}

baseline := snapshotMCPRenderState(ctx)
if updateProfile(ctx, restricted) {
	waitForMCPsAndVerifyNodes(ctx, "after restricted groups", baseline)
}
```

The boolean return keeps the no-op case (profile already identical) from
waiting for a generation bump that will never happen. The rollback needs the
same treatment inside `DeferCleanup`, with the cleanup context:

```go
DeferCleanup(func(cleanupCtx context.Context) {
	current := &configv1.APIServer{}
	Expect(e2eclient.Client.Get(cleanupCtx, apiServerKey, current)).To(Succeed())
	if reflect.DeepEqual(current.Spec, *originalSpec) {
		return
	}
	baseline := snapshotMCPRenderState(cleanupCtx)
	Eventually(func(g Gomega) {
		obj := &configv1.APIServer{}
		g.Expect(e2eclient.Client.Get(cleanupCtx, apiServerKey, obj)).To(Succeed())
		obj.Spec = *originalSpec
		g.Expect(e2eclient.Client.Update(cleanupCtx, obj)).To(Succeed())
	}).WithTimeout(10 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
	waitForMCPsAndVerifyNodes(cleanupCtx, "after TLS curve rollback", baseline)
})
```

When doing this, also delete the duplicated waits in the curve spec: today
`updateProfile` ends with a wait labelled "after TLS Curve rollback" and the
spec then waits again with the correct reason, so phase A waits twice and the
first wait carries a misleading label. Keep exactly one wait per mutation and
check that the API server persisted `groups` **before** starting the 40 minute
wait, so a dropped field skips in seconds.

#### Why this fixes both failure modes

- Zero-machine pool: `worker` re-renders (`Generation` bumps) but has nothing
  to drain, so `Updated` stays true and `updatedMachineCount(0) ==
  machineCount(0)`. The predicate is satisfied without ever observing
  `Updating`.
- Fast roll: there is no transient window to catch. The predicate is evaluated
  against the terminal state, so a roll that finishes between two polls is
  still observed through `Generation`/`ObservedGeneration`.

Trade-offs: one `List` per poll instead of one watcher goroutine per MCP, and
one aggregated error instead of the first goroutine's error. The strict
`Generation > baseline` check assumes the change re-renders every pool, which
holds for an APIServer TLS profile change (in `test.out` all of `master`,
`worker-cnf` and the empty `worker` pool re-rendered). If a future wait targets
a change that affects only some pools, scope the wait to the affected pools by
node selector rather than relaxing the predicate.

#### Minimal fix to ship

If CI never produces an empty pool, the full redesign above is not needed for
the lane. The smallest change that removes the false failure is a guard in the
existing loop:

```go
for i := range allMCPs.Items {
	mcp := &allMCPs.Items[i]
	if mcp.Status.MachineCount == 0 {
		klog.InfoS("skipping MCP with no machines", "mcp", mcp.Name)
		continue
	}
	eg.Go(func() error {
		// unchanged two-phase Updating then Updated wait
	})
}
```

Commit message rationale: a pool with `status.machineCount: 0` re-renders and
settles without ever setting `Updating=True`, so the two-phase wait can only
time out. Every pool in CI has machines, so CI behaviour is unchanged and the
guard only makes the suite runnable on real deployments where all workers live
in a custom pool.

Two adjacent cleanups belong in the same commit because they are unambiguous
bugs, not design changes:

- `updateProfile` ends with `waitForMCPsAndVerifyNodes(ctx, "after TLS Curve
  rollback")`, and the spec then waits again with the correct reason. Delete
  the inner wait; one wait per mutation, correct label.
- `verifyNodesMatchMCPConfig` is safe for a zero-machine pool (its node list is
  empty), so it needs no guard.

Defer the baseline/`ObservedGeneration` design until a fast-roll flake is
actually observed. It is strictly more correct, but it changes the helper
signature and six call sites, which is a harder review for a CI-only lane.

#### Is this an NROP bug?

Not in the operator. The failing code is test automation, and the operator
neither owns MCP membership nor waits on MCP transitions for the TLS path:

- `pkg/objectstate/rte/machineconfigpool.go` only reads MCPs; its
  `IsMachineConfigPoolUpdated` treats `Updated != False` as done, which is true
  for a zero-machine pool.
- `internal/machineconfigpools` and `internal/nodegroups` only resolve node
  groups from existing MCPs.
- NROP never creates, updates or deletes `MachineConfigPool` objects and never
  writes node role labels; it only labels its own `MachineConfig`.
- The TLS profile is read from `APIServer/cluster` (`cmd/main.go:326`) and
  converted into operand arguments; that path does not depend on any MCP.

A quick way to see the separation: during the 40 minute wait the RTE DaemonSet
and scheduler Deployment already carry the new curve flags, because NROP
reconciles them directly from the APIServer object. The MCP wait is only the
suite letting the cluster settle before probing endpoints, so an empty `worker`
pool is a cluster-shape fact the suite must tolerate.

#### Does NROP create NRT data for a pool with no nodes?

No. `NodeResourceTopology` is a per-node, cluster-scoped object written by the
RTE process running on that node, and NROP never creates or deletes NRTs. The
operator only reads them (`internal/wait/nrts.go`) and resolves node groups
from MCPs (`internal/machineconfigpools`, `internal/nodegroups`).

Three different objects get confused here:

| Object | Scope | Written by | With an empty pool |
|---|---|---|---|
| `NodeResourceTopology` | one per node | RTE on that node | none: no pod, no NRT |
| RTE `DaemonSet` | one per node group/pool | NROP | exists, `DESIRED 0 / READY 0` |
| `MachineConfigPool` | cluster | OCP installer / MCO | still exists, `machineCount: 0` |

Check what actually exists:

```bash
oc get nrt                                    # names must match live node names
oc get ds -A | grep numaresourcesoperator     # one per managed pool
oc get numaresourcesoperator -o jsonpath='{range .items[0].status.daemonsets[*]}{.name}{"\n"}{end}'
```

Keeping the per-pool DaemonSet is deliberate: the pool is the unit of
configuration (kubelet config, RTE config, node selector), so a pool that later
gains nodes is managed without editing the NRO CR, and an empty DaemonSet costs
nothing. If a pool should not be managed at all, remove it from
`spec.nodeGroups` (or the corresponding `NodeGroup` CR) and NROP deletes that
DaemonSet.

An NRT whose name is not a live node is an orphan from an abrupt node deletion:
RTE had no chance to delete its own object, and NROP does not garbage-collect
it. Remove it with `oc delete nrt <node-name>`.

Cluster-side workaround with no code change: delete the empty pool
(`oc delete mcp worker`) only when no node carries
`machineconfiguration.openshift.io/role=worker`. It is safe for the MCO, but a
node that later gains that role would be unmanaged.

The restore patch runs before the failing wait, so the profile is normally back
even though the spec failed. Confirm:

```bash
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile}{"\n"}'
```

### Serial test times out during MCP rollout

Changing the APIServer TLS profile triggers MachineConfig changes and node
reboots. Check:

- at least one schedulable worker is available;
- PodDisruptionBudgets do not block drains;
- `E2E_NROP_MCP_UPDATE_TIMEOUT` and interval are appropriate;
- `verifyNodesMatchMCPConfig` reports a real mismatch rather than a transient
  API error.

The node-drain and PDB analysis in `learn/nrop_tls.md` explains the topology
traps in detail.

### Port-forward probe fails immediately

- Ensure the pod is Running and the port is the secure serving port.
- The scheduler secure port is `10259`, not its metrics port.
- RTE metrics uses `2112` only when `--metrics-mode=httptls` is present.
- The probes intentionally skip certificate verification; a certificate error
  therefore indicates a connection/port problem, not a trust problem.

### Test IDs

Do not invent test IDs. Allocate them from the project's test-management
range. Until then, use `[test_id:TBD]` in draft code, matching the convention
already used in `learn/nrop_tls.md`'s test plan.

---

## 12. Glossary

| Term | Meaning |
|---|---|
| NROP | NUMA Resources Operator. |
| RTE | Resource Topology Exporter; a DaemonSet that publishes NRT data and serves metrics. |
| NRT | NodeResourceTopology custom resource. |
| TAS | Topology-aware scheduling. |
| TLS profile | Cluster-wide OpenShift policy for minimum TLS version, ciphers, and groups. |
| Group / curve | Key-exchange mechanism used during a TLS handshake. |
| Curve ID | Decimal IANA identifier for a group, for example 23 for P-256. |
| Operand | Workload managed by NROP; here RTE and the secondary scheduler. |
| Non-disruptive | Test that only reads cluster state or opens connections; no reboots. |
| Serial/disruptive | Test that owns the cluster and may mutate/reboot it. |
| MCP | MachineConfigPool; changing the TLS profile triggers its rollout. |

---

## 13. Related files and documentation

- `learn/nrop_tls_curves_todo.md`: working checklist for the remaining helper
  refactor, sentinel, unit tests, curve specs and doc sync, with the code to
  apply.
- `learn/nrop_tls.md`: TLS architecture, endpoint details, certificate trust,
  existing TLS test plan, and node-drain/PDB analysis.
- `learn/nrop_e2e_guide.md`: general NROP E2E suite layout and helper usage.
- `learn/nrop_tls_curves_automation.md`: first-week onboarding path,
  line-by-line function reference, test-level guidance, and copy-paste helper
  and E2E examples.
- `learn/nrop_tls_objectupdate_controller_common_reference.md`: exhaustive
  reference for every function and variable in `pkg/objectupdate/tls` and
  `controller-runtime-common/pkg/tls`, including tests, call sites, and edge
  cases.
- `test/e2e/tls/tls_test.go`: non-disruptive TLS specs.
- `test/e2e/serial/tests/configuration.go`: serial TLS profile mutation spec.
- `test/internal/tls/tls.go`: shared TLS helpers.
- `test/internal/tls/tls_test.go`: unit tests for TLS helpers.
- `pkg/objectupdate/tls/tls.go`: settings conversion and curve CSV formatting.
- `pkg/objectupdate/rte/rte.go`: RTE argument reconciliation.
- `pkg/objectupdate/sched/sched.go`: scheduler argument reconciliation.
- `cmd/main.go`: profile fetch and initial `objtls.Settings` construction.
- `internal/controller/numaresourcesoperator_controller.go`: RTE TLS wiring.
- `internal/controller/numaresourcesscheduler_controller.go`: scheduler TLS wiring.
- `internal/api/features/_topics.json`: `tlscompliance` topic registration.



