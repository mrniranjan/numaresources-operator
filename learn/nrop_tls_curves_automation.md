# NROP TLS Curves Automation Reference

This document is the hands-on companion to
[`nrop_tls_curves_e2e_guide.md`](nrop_tls_curves_e2e_guide.md). That guide
explains the suites, the design, the coverage gaps, and the scenarios. This
document explains **how to automate them**: which functions you must
understand, what each function does line by line in plain English, how to test
each one, and how to assemble the helpers, unit tests, non-disruptive E2E
specs, and serial E2E spec.

NROP in one line: NROP is a Kubernetes/OpenShift operator that deploys the
Resource Topology Exporter (RTE) and an optional NUMA-aware scheduler so
workloads can be placed using NUMA topology data.

The document was verified against commit `6b76dcedb` on branch
`tls_learning`. Paths written as `@test/serial` mean `test/e2e/serial`;
`@test/internal/tls` means `test/internal/tls`.

### How to use this document

| If you need to... | Read... |
|---|---|
| Understand the whole flow before writing code | Sections 1-3 |
| Implement or review one helper | Section 4 |
| Decide which test level to use | Section 5 |
| Copy working test/helper code | Section 6 |
| Map a required scenario to functions | Section 7 |
| Debug a failure | Section 8 |
| Look up a function quickly | Section 9 |

Related documents:

- [`nrop_tls_curves_e2e_guide.md`](nrop_tls_curves_e2e_guide.md): TLS curve
  concepts, current coverage, missing coverage, and the 21-scenario catalog.
- [`nrop_tls_objectupdate_controller_common_reference.md`](nrop_tls_objectupdate_controller_common_reference.md):
  complete reference for every function and variable in
  `pkg/objectupdate/tls` and the vendored controller-runtime-common TLS
  packages.
- [`nrop_tls.md`](nrop_tls.md): how TLS works for NROP endpoints.
- [`nrop_e2e_guide.md`](nrop_e2e_guide.md): general NROP E2E suite patterns.

---

## 0. New contributor onboarding path

This section is written for someone who has just joined the team, has been
assigned "add E2E coverage for TLS curves", and has never seen NROP test
automation. Follow it in order. Do not start by editing the serial suite.

### 0.1 What you are building

You are not implementing TLS in NROP. TLS curve propagation already exists in
production code. The work has three TLS surfaces and five things to prove:

- **RTE metrics (`2112`)**: has `--metrics-tls-curve-preferences`.
- **Scheduler secure serving (`10259`)**: has `--tls-curve-preferences`.
- **Operator metrics (`8080`)**: has no flag; the manager sets
  `CurvePreferences` directly through `metricsserver.Options.TLSOpts`.

1. The cluster profile's group list is converted to the expected numeric CSV.
2. RTE and the scheduler receive that CSV in their command-line arguments.
3. The operator passes the resulting config to its metrics server.
4. All three live TLS servers negotiate a curve from the allowed set.
5. All three reject a curve outside the allowed set, and the operands remove
   their flag when the profile has no groups.

The admission webhook (`9443`) is disabled by default and is out of scope.

### 0.2 First-day checklist

Do these before changing code:

```bash
make help
make test-unit
```

Then read, in this order:

1. `test/internal/tls/tls.go` from top to bottom. You do not need to memorize
   it; notice that it has four groups of functions: profile helpers, argument
   assertions, TLS probes, and metrics fetching.
2. `test/e2e/tls/tls_test.go`. This is the non-disruptive suite. Read tests
   90743, 90744, 88380, 88381, and 88382.
3. `test/e2e/serial/tests/configuration.go` around test 88383. Read only that
   `Context`; ignore the rest of the file on day one.
4. `pkg/objectupdate/tls/tls.go`, `pkg/objectupdate/rte/rte.go` around
   `DaemonSetArgs`, and `pkg/objectupdate/sched/sched.go` around
   `DeploymentTLSSettings`.
5. `pkg/numaresourcesoperator/flagcodec`, especially
   `ParseArgvKeyValue`, `SetOption`, `Delete`, and `GetFlag`.

### 0.3 A five-session learning plan

**Session 1: run what exists.**

```bash
go test ./pkg/objectupdate/tls/... ./pkg/objectupdate/rte/... ./pkg/objectupdate/sched/... ./test/internal/tls/...
make build-e2e-tls
bin/e2e-nrop-tls.test --ginkgo.v --ginkgo.label-filter='feature:tlscompliance'
```

If you do not have a cluster, stop after the unit tests and `make
build-e2e-tls`. Read the test output and locate each `It()` by test ID.

**Session 2: understand the settings pipeline.**

Trace one value by hand:

```text
configv1.TLSProfiles[Intermediate].Groups
  -> libgocrypto.TLSGroupsToCurveIDs
  -> objtls.NewSettings
  -> "4588,29,23,24"
```

Write a temporary unit test or a small `go test` case that prints the CSV.
Do not commit the print test; it is a learning aid.

**Session 3: understand operand arguments.**

Read `DaemonSetArgs` and `DeploymentTLSSettings`. Then use a fake DaemonSet or
Deployment and verify that calling the updater twice does not duplicate the
curve flag. This teaches you the set-or-delete and idempotency requirements
without needing a cluster.

**Session 4: understand live probes.**

Read `PortForwardToPodByNames`, `tlsHandshake`, `ProbeTLSState` (proposed), and
`ProbeTLSCurve` (proposed). Draw the path:

```text
test -> port-forward -> net.Conn -> tls.Client -> server
```

The important idea is that the test does not use `curl`; it uses Go's TLS
client so it can offer a specific curve and read `ConnectionState.CurveID`.

**Session 5: understand serial tests.**

Read test 88383. Pay attention to `DeferCleanup`, the MCP waits, and the
per-node config verification. A serial TLS profile change reboots nodes; never
run it on a shared cluster.

### 0.4 Your first change, in order

Make these changes one at a time and run the matching test after each:

1. Confirm the curve assertion in `CheckRTEDaemonSetTLSFlags` (already present).
2. Review the fake-client unit tests for curve match, curve mismatch, and stale
   curve when expected empty.
3. Add fake-client tests for the existing `CheckSchedulerDeploymentTLSFlags`.
4. Add `ProbeTLSState` and one non-disruptive scheduler positive-curve spec.
5. Add `ProbeTLSCurve`, `FindDisallowedCurve`, and one negative-curve spec.
6. Add the serial restricted-to-empty transition only after all of the above
   pass.

This order keeps every step reviewable and gives you a working test at each
stage.

### 0.5 What you do not need to learn first

You do not need to understand certificate issuance, the service CA, OLM
webhook certificates, kubelet topology discovery, or scheduler scoring to add
curve coverage. You do need to understand:

- the difference between a profile's OpenSSL cipher names and Go cipher IDs;
- the difference between an OpenShift TLS **group** and a Go **curve**;
- that the operand flag is decimal CSV;
- that empty groups mean "delete the flag and use Go defaults".

### 0.6 30-minute Ginkgo and Gomega primer

The smallest useful NROP spec looks like this:

```go
var _ = Describe("TLS curves", func() {
	It("[test_id:TBD] describes one behavior", func(ctx context.Context) {
		By("reading the cluster profile")
		_, profile, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		By("asserting the profile has groups")
		Expect(profile.Groups).ToNot(BeEmpty())
	})
})
```

Line by line:

1. `Describe` groups related specs and appears in the report.
2. `It` is one test. The context parameter is supplied by Ginkgo and is
   cancelled when the spec times out.
3. `By` adds a progress step; it does not assert anything.
4. `Expect(actual).To(matcher)` is the assertion. `ToNot` negates it.
5. `HaveOccurred()` is a Gomega matcher for a non-nil error.
6. `Eventually` retries an assertion until timeout; use it for asynchronous
   operator writes.
7. `Skip("reason")` marks the spec skipped; use it only for a documented
   environment precondition.

Run a single spec by focus:

```bash
bin/e2e-nrop-tls.test --ginkgo.v --ginkgo.focus='TLS curves'
```

### 0.7 How to read the rest of this document

- If you are implementing a helper, jump to the function in Section 4.
- If you are deciding where a test belongs, read Section 5.
- If you want working code, copy from Section 6.
- If review asks "which scenario does this cover?", use Section 7.
- If a test fails, use Section 8 before changing code.

---

## 1. Automation architecture and build order

TLS curve automation is a pipeline. A failure at any stage can look like a
curve failure, so build and test it in this order.

```text
APIServer/cluster.spec.tlsSecurityProfile
  |
  | 1. FetchAPIServerTLSProfile + GetTLSProfileSpec
  v
configv1.TLSProfileSpec{Groups, Ciphers, MinTLSVersion}
  |
  | 2. TLSGroupsToCurveIDs
  v
[]tls.CurveID
  |
  | 3. NewTLSConfigFromProfile + objtls.NewSettings
  v
objtls.Settings{MinVersion, CipherSuites, CurvePreferences}
  |
  +--> 4a. rteupdate.DaemonSetArgs
  |         --metrics-tls-curve-preferences=4588,29,23,24
  |
  +--> 4b. schedupdate.DeploymentTLSSettings
  |         --tls-curve-preferences=4588,29,23,24
  |
  +--> 4c. cmd/main.go metricsserver.Options{TLSOpts: []func(*tls.Config){tlsConfig}}
            no operand flag; inspect the live handshake on :8080
  |
  | 5. Discover operands and parse their argv
  v
flagcodec.Flags
  |
  | 6. matchTLSFlag / Check*TLSFlags
  v
configuration assertion
  |
  | 7. Port-forward + TLS handshake
  v
runtime assertion on ConnectionState.CurveID
  |
  | 8. Serial profile mutation + MCP rollout + cleanup
  v
transition and rollback assertion
```

### 1.1 The ten implementation steps

1. **Read the profile.** Use `ctrltls.FetchAPIServerTLSProfile`. It resolves
   omitted profiles to Intermediate and handles Custom profiles.
2. **Map OpenShift groups to Go curve IDs.** Use
   `libgocrypto.TLSGroupsToCurveIDs`. NROP does not maintain its own mapping.
3. **Build a `tls.Config`.** Use `ctrltls.NewTLSConfigFromProfile`. It sets
   `MinVersion`, conditional cipher suites, and non-empty curve preferences.
4. **Format operand strings.** Use `objtls.NewSettings`. Curves become decimal
   CSV such as `4588,29,23,24`.
5. **Write TLS configuration.** RTE uses `rteupdate.DaemonSetArgs`; the
   scheduler uses `schedupdate.DeploymentTLSSettings`; the operator passes the
   same callback to `metricsserver.Options.TLSOpts` in `cmd/main.go`.
6. **Discover generated objects.** RTE DaemonSets come from
   `NUMAResourcesOperator.status.nodeGroups`; the scheduler Deployment is
   found from the `NUMAResourcesScheduler` owner UID.
7. **Parse and assert argv.** Use `flagcodec.ParseArgvKeyValue` and
   `matchTLSFlag`. Always assert absence when the expected value is empty.
8. **Probe the runtime.** Port-forward to scheduler `10259`, RTE `2112`, or
   the manager Pod `8080`, do a real handshake, and inspect
   `ConnectionState.CurveID`.
9. **Exercise transitions serially.** Mutate `APIServer/cluster`, wait for
   every MachineConfigPool, assert both operands, then restore the profile in
   `DeferCleanup`.
10. **Run the cheapest test first.** Pure unit tests, then fake-client helper
    tests, then non-disruptive E2E, then one serial test.

### 1.2 What each stage proves

| Stage | What it proves | What it does not prove |
|---|---|---|
| Profile fetch | NROP read the intended profile | NROP honors the group list |
| Group mapping | OpenShift names map to expected IDs | IDs reach an operand |
| Settings formatting | CSV format is correct | Operand args contain it |
| Operand args | Reconciler wrote the expected flag | The server enforces it |
| Operator metrics config | Manager wired `TLSOpts` | The metrics server honors it |
| Positive handshake | Negotiated curve is allowed | Disallowed curves are rejected |
| Negative handshake | Server rejects an outside curve | All transitions are correct |
| Serial mutation | Real profile changes reconcile | FIPS/PQ policy on other lanes |

This is why a single E2E test cannot cover the feature. The minimum credible
set has argument propagation, positive runtime, negative runtime, and the
delete-on-empty transition.

### 1.3 Files you will touch

| File | Change |
|---|---|
| `test/internal/tls/tls.go` | Curve assertion already present; add curve probes |
| `test/internal/tls/tls_test.go` | Add unit tests for the new helper logic |
| `test/e2e/tls/tls_test.go` | Add non-disruptive arg and handshake specs |
| `test/e2e/serial/tests/configuration.go` | Add disruptive transition spec |
| `learn/*.md` | Keep the design and automation notes current |

No production change is required to test existing behavior. The production
code already writes curve flags. The missing pieces are test helpers and test
specs.

---

## 2. Environment, commands, and conventions

### 2.1 Prerequisites

- A built and installed NROP on an OpenShift cluster for E2E tests.
- `oc` logged in to that cluster.
- Go available through the repository toolchain; do not assume `go` is on
  `PATH` in every environment.
- For controller tests, the envtest binaries installed by the Makefile.
- For serial tests, exclusive access to the cluster. The suite reboots nodes.

### 2.2 Preferred commands

Always prefer Makefile targets:

```bash
make help
make test-unit
make test-controllers
make build-e2e-tls
make binary-e2e-serial
```

Focused package tests while iterating:

```bash
go test ./pkg/objectupdate/tls/...
go test ./pkg/objectupdate/rte/...
go test ./pkg/objectupdate/sched/...
go test ./test/internal/tls/...
```

Run only the non-disruptive TLS suite:

```bash
bin/e2e-nrop-tls.test \
  --ginkgo.v \
  --ginkgo.label-filter='feature:tlscompliance'
```

Run only the curve specs you add:

```bash
bin/e2e-nrop-tls.test \
  --ginkgo.v \
  --ginkgo.focus='curve'
```

Run the existing serial TLS test:

```bash
bin/e2e-nrop-serial.test \
  --ginkgo.v \
  --ginkgo.focus='88383' \
  --ginkgo.label-filter='feature:tlscompliance'
```

### 2.3 Import aliases used in the repository

| Alias | Package |
|---|---|
| `ctrltls` | `github.com/openshift/controller-runtime-common/pkg/tls` |
| `libgocrypto` | `github.com/openshift/library-go/pkg/crypto` |
| `objtls` | `github.com/openshift-kni/numaresources-operator/pkg/objectupdate/tls` |
| `rteupdate` | `github.com/openshift-kni/numaresources-operator/pkg/objectupdate/rte` |
| `schedupdate` | `github.com/openshift-kni/numaresources-operator/pkg/objectupdate/sched` |
| `k8swgobjupdate` | `github.com/openshift-kni/numaresources-operator/pkg/numaresourcesoperator/objectupdate` |
| `intls` | `github.com/openshift-kni/numaresources-operator/test/internal/tls` |
| `e2eclient` | `github.com/openshift-kni/numaresources-operator/test/internal/clients` |
| `podlist` | `github.com/openshift-kni/numaresources-operator/internal/podlist` |
| `flagcodec` | `github.com/openshift-kni/numaresources-operator/pkg/numaresourcesoperator/flagcodec` |

Use the same aliases as the surrounding file. Mixed aliases make review
harder.

### 2.4 Test-level convention

| Level | Location | Speed | Cluster needed | Use for |
|---|---|---|---|---|
| Pure unit | package `_test.go` | milliseconds | no | mapping, formatting, flag parsing |
| Fake-client helper | `test/internal/tls/tls_test.go` | fast | no | object discovery, argv assertions |
| Controller | `internal/controller/*_test.go` | seconds | envtest | reconciler writes the flag |
| Non-disruptive E2E | `test/e2e/tls/tls_test.go` | seconds to minutes | yes | installed operands, real handshake |
| Serial E2E | `test/e2e/serial/tests/configuration.go` | tens of minutes | yes, exclusive | profile transitions and rollouts |

### 2.5 Labels and test IDs

- Add `feature:tlscompliance` to every TLS curve spec.
- Use `label.Tier0` for non-disruptive checks.
- Use `label.Tier2`, `label.Slow`, and `label.Reboot` for serial profile
  changes.
- Request a real test ID from the team; until then use `[test_id:TBD]`.
- Keep one behavior per `It()` so failures identify the broken stage.

### 2.6 Client choice

- `e2eclient.Client` is the controller-runtime client used for typed objects
  such as `APIServer`, `NUMAResourcesOperator`, `Deployment`, and `Pod`.
- `e2eclient.K8sClient` is the client-go client used by port-forward and exec
  helpers.

Passing the wrong one is a common compile error. Discovery and assertions use
`Client`; `intls.Probe*` functions take `K8sClient`.

---

## 3. Function map

| Layer | Function | Source | Test level |
|---|---|---|---|
| Profile | `ctrltls.FetchAPIServerTLSProfile` | vendored `controller-runtime-common/pkg/tls` | fake client, E2E read |
| Profile | `ctrltls.GetTLSProfileSpec` | same | pure unit |
| Profile | `ctrltls.NewTLSConfigFromProfile` | same | pure unit |
| Mapping | `libgocrypto.TLSGroupToCurveID` | vendored `library-go/pkg/crypto` | pure unit |
| Mapping | `libgocrypto.TLSGroupsToCurveIDs` | same | pure unit |
| Mapping | `libgocrypto.ValidTLSGroups` | same | pure unit |
| Formatting | `objtls.NewSettings` | `pkg/objectupdate/tls/tls.go` | pure unit |
| Formatting | `objtls.curveIDsToString` | same | indirect unit |
| Formatting | `objtls.Settings.String` | same | pure unit |
| RTE args | `rteupdate.DaemonSetArgs` | `pkg/objectupdate/rte/rte.go` | pure unit, controller |
| Scheduler args | `schedupdate.DeploymentTLSSettings` | `pkg/objectupdate/sched/sched.go` | pure unit, controller |
| Arg codec | `flagcodec.ParseArgvKeyValue` | `pkg/numaresourcesoperator/flagcodec` | pure unit |
| Arg codec | `Flags.SetOption`, `Delete`, `GetFlag`, `Argv` | same | pure unit |
| Container lookup | `k8swgobjupdate.FindContainerByName` | `pkg/numaresourcesoperator/objectupdate/find.go` | indirect unit |
| Test profile | `intls.GetClusterTLSProfile` | `test/internal/tls/tls.go` | fake client, E2E |
| Test settings | `intls.RTESettingsFromClusterProfile` | same | fake client |
| Test args | `intls.CheckRTEDaemonSetTLSFlags` | same | fake client, E2E |
| Test args | `intls.CheckRTEDaemonSetTLSFlagsMatchClusterProfile` | same | E2E |
| Test args | `intls.matchTLSFlag` | same | pure unit through callers |
| Test args | `intls.CheckSchedulerDeploymentTLSFlags` (implemented) | same | fake client, E2E |
| Discovery | `podlist.With` | `internal/podlist/find.go` | indirect |
| Discovery | `DeploymentByOwnerReference` | `internal/podlist/deployment.go` | fake client |
| Discovery | `ByDeployment` | same | fake client, E2E |
| Discovery | `ByDaemonset` | `internal/podlist/daemonset.go` | fake client, E2E |
| Operator discovery | `deploy.FindNUMAResourcesOperatorPod` | `test/internal/deploy/find.go` | fake client, E2E |
| Operator exec | `remoteexec.CommandOnPod` | `internal/remoteexec/command.go` | E2E |
| Operator exec | `remoteexec.CommandOnPodByNames` | same | E2E |
| Operator metrics | `fetchMetricsFromPod` | `test/e2e/serial/tests/metrics.go` | E2E |
| Port-forward | `remoteexec.PortForwardToPod` | `internal/remoteexec/command.go` | E2E |
| Port-forward | `PortForwardToPodByNames` | same | E2E |
| TLS probe | `intls.tlsHandshake` | `test/internal/tls/tls.go` | local test/E2E |
| TLS probe | `intls.wrapTLSHandshakeError` | same | pure unit |
| TLS probe | `intls.ProbeMaxTLSVersion` | same | E2E |
| TLS probe | `intls.ProbeTLSCipher` | same | E2E |
| TLS probe | `intls.ProbeTLSSettings` | same | E2E |
| TLS probe | `intls.ProbeTLSState` (proposed) | same | E2E |
| TLS probe | `intls.ProbeTLSCurve` (proposed) | same | E2E |
| TLS probe | `intls.FindDisallowedCurve` (proposed) | same | pure unit |
| Helpers | `intls.OpenSSLCipherToGoID` | same | pure unit |
| Helpers | `intls.FindDisallowedCipher` | same | pure unit |
| Helpers | `intls.TLSVersionBelow` | same | pure unit |
| Metrics | `intls.FetchMetrics` | same | E2E |
| Serial | `tlsGroupPreferencesEnabled` (proposed) | serial test file | fake client/E2E |
| Serial | `waitForMCPConditionWithRetry` | `configuration.go` | serial E2E |
| Serial | `isTransientMCPError` | same | pure unit |
| Serial | `verifyNodesMatchMCPConfig` | same | serial E2E |

---

## 4. Function reference: plain-English, line by line

Each entry uses the same structure:

- **Signature and location** so you can open the source.
- **Inputs and outputs** in one sentence.
- **Line by line** in execution order. These are not paraphrases of comments;
  they describe what the Go statements actually do.
- **Failure modes** you will see in tests.
- **How to test** at the cheapest level that can catch the bug.
- **Curve relevance** explaining why a TLS curve author cares.

### 4.1 Profile fetch and resolution layer

#### `ctrltls.APIServerName`

```go
const APIServerName = "cluster"
```

This is the name of the singleton OpenShift `APIServer` object. Every profile
read and write uses this key. A test that fetches the wrong name gets
`NotFound` and should fail immediately, not skip.

How to test: in a fake-client test, create `configv1.APIServer` with
`ObjectMeta.Name = ctrltls.APIServerName`; then verify the helper finds it.
At E2E level, `oc get apiserver cluster` must succeed before the suite runs.

#### `ctrltls.FetchAPIServerTLSProfile`

```go
func FetchAPIServerTLSProfile(ctx context.Context, k8sClient client.Client) (configv1.TLSProfileSpec, error)
```

Location: vendored
`github.com/openshift/controller-runtime-common/pkg/tls/tls.go`.

Input: a controller-runtime client and context. Output: the resolved profile
spec, or an error. The spec contains `MinTLSVersion`, `Ciphers`, and the curve
list in `Groups`.

Line by line:

1. It creates an empty `&configv1.APIServer{}` to receive the API object.
2. It builds `client.ObjectKey{Name: APIServerName}`; the namespace is empty
   because `APIServer` is cluster-scoped.
3. It calls `k8sClient.Get(ctx, key, apiServer)`.
4. If the read fails, it returns an empty spec and an error that includes the
   object key. Common causes are missing OpenShift APIs, expired credentials,
   or a fake client without the OpenShift scheme.
5. It calls `GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)`.
6. If resolution fails, it wraps the error with the APIServer key. The most
   common error is a Custom profile with a nil `custom` block.
7. It returns the resolved spec unchanged. It does not copy the Groups slice,
   so callers should treat the returned slices as read-only.

Failure modes:

- `failed to get APIServer "cluster"` means the API read failed.
- `failed to get TLS profile from APIServer "cluster"` means the object was
  read but the profile block was invalid.
- A fake-client unit test often sees "no kind is registered for the type
  APIServer"; call `configv1.AddToScheme` or `nropv1.AddToScheme` first.

How to test:

- Unit: fake client with an `APIServer` whose `Spec.TLSSecurityProfile` is nil;
  expect the Intermediate spec. Repeat with Old, Modern, Custom, and Custom
  with nil `Custom`.
- E2E: this is the read half of tests 90743, 90744, 88380, and any new curve
  spec. It is already exercised indirectly by `intls.GetClusterTLSProfile`.

Curve relevance: this is the only production source of `profile.Groups`.
Everything downstream is deterministic once this value is correct.

#### `ctrltls.GetTLSProfileSpec`

```go
func GetTLSProfileSpec(profile *configv1.TLSSecurityProfile) (configv1.TLSProfileSpec, error)
```

Input: the optional `spec.tlsSecurityProfile` pointer. Output: a concrete
profile spec.

Line by line:

1. It copies the built-in Intermediate profile from
   `configv1.TLSProfiles[TLSProfileIntermediateType]` into `defaultProfile`.
   Copying avoids returning a pointer to the global map value.
2. If the input pointer is nil or its `Type` is empty, it returns the
   Intermediate copy. This implements OpenShift's omitted-profile default.
3. It reads `profileType := profile.Type`.
4. If the type is not `Custom`, it looks up the type in `configv1.TLSProfiles`.
5. If the lookup succeeds, it returns the pointed-to built-in spec.
6. If the type is unknown, it returns the Intermediate default rather than an
   error. Tests should document this fallback; it is easy to mistake for a
   successful named profile.
7. If the type is `Custom` and `profile.Custom` is nil, it returns
   `ErrCustomProfileNil`.
8. Otherwise it returns `profile.Custom.TLSProfileSpec` exactly as supplied.
   It does not validate that the custom groups are recognized.

Failure modes:

- A Custom profile without `custom:` is a user error and must fail.
- An unknown named type silently falls back to Intermediate. Do not write a
  test that expects an error for an unknown enum.
- A Custom profile can contain an unknown `TLSGroup` string; validation happens
  later during mapping, not here.

How to test:

```go
func TestGetTLSProfileSpec(t *testing.T) {
	spec, err := ctrltls.GetTLSProfileSpec(nil)
	if err != nil || spec.MinTLSVersion != configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion {
		t.Fatalf("nil profile must resolve to Intermediate: %+v %v", spec, err)
	}

	custom := &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS12,
				Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
				Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519},
			},
		},
	}
	got, err := ctrltls.GetTLSProfileSpec(custom)
	if err != nil || !slices.Equal(got.Groups, custom.Custom.Groups) {
		t.Fatalf("custom groups were not preserved: %+v %v", got, err)
	}

	_, err = ctrltls.GetTLSProfileSpec(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType})
	if !errors.Is(err, ctrltls.ErrCustomProfileNil) {
		t.Fatalf("expected ErrCustomProfileNil, got %v", err)
	}
}
```

Curve relevance: built-in profiles are the normal E2E input. Custom profiles
are the only way to prove that NROP honors a group list different from the
built-in defaults.

#### `ctrltls.NewTLSConfigFromProfile`

```go
func NewTLSConfigFromProfile(profile configv1.TLSProfileSpec) (tlsConfig func(*tls.Config), unsupported []string)
```

Input: a resolved profile spec. Output: a callback that mutates a
`*tls.Config`, plus a list of unsupported cipher/group names. The function
itself does the conversions; it does not mutate a config until the callback is
called.

Line by line:

1. It converts `profile.MinTLSVersion` from a string such as `VersionTLS12`
   to the numeric constant with `libgocrypto.TLSVersionOrDie`. An invalid
   value panics; production only passes API-validated values.
2. It converts the OpenSSL cipher names to Go cipher IDs with the private
   `cipherCodes` helper. Unsupported ciphers are returned in a second slice.
3. It converts `profile.Groups` to `[]tls.CurveID` with
   `libgocrypto.TLSGroupsToCurveIDs`. Unrecognized groups are returned in a
   second slice.
4. It builds the combined `unsupported` slice: first unsupported ciphers,
   then unsupported group names converted to strings.
5. It returns a closure. The closure captures `minVersion`, `curvePrefs`, and
   `cipherSuites`.
6. When the closure runs, it always assigns `tlsConf.MinVersion`.
7. If `curvePrefs` is non-empty, it assigns `tlsConf.CurvePreferences`. If the
   group list was empty or every group was unrecognized, the field stays nil,
   which means "use Go defaults".
8. If the minimum version is not TLS 1.3, it assigns `tlsConf.CipherSuites`.
   TLS 1.3 cipher suites are not configurable in Go, so the field is left
   untouched for a TLS-1.3-only profile.
9. It returns the callback and the unsupported list.

Failure modes:

- An invalid minimum version panics through `TLSVersionOrDie`; tests should
  not feed arbitrary strings to this function.
- Unknown groups are silently skipped from `CurvePreferences` but reported in
  `unsupported`. A test must assert the recognized groups still survive.
- Empty groups leave `CurvePreferences` nil. Do not assert an empty non-nil
  slice.

How to test:

```go
func TestNewTLSConfigFromProfileCurves(t *testing.T) {
	spec := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
		Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
	}
	apply, unsupported := ctrltls.NewTLSConfigFromProfile(spec)
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported entries: %v", unsupported)
	}
	cfg := &tls.Config{}
	apply(cfg)
	if !slices.Equal(cfg.CurvePreferences, []tls.CurveID{tls.X25519, tls.CurveP256}) {
		t.Fatalf("curve preferences = %v", cfg.CurvePreferences)
	}
	if cfg.MinVersion != tls.VersionTLS12 || len(cfg.CipherSuites) == 0 {
		t.Fatalf("version/ciphers not applied: %+v", cfg)
	}
}
```

Add two more cases: a profile with an unknown group plus a known group, and a
TLS 1.3 profile where `CipherSuites` must remain empty.

Curve relevance: this is the only bridge from OpenShift group names to Go
curve constants. A bug here either drops curves or panics the operator.

#### `libgocrypto.TLSGroupToCurveID`

```go
func TLSGroupToCurveID(group configv1.TLSGroup) (tls.CurveID, bool)
```

Input: one OpenShift `TLSGroup`. Output: the Go `tls.CurveID` and whether the
name is known.

Line by line:

1. It looks up `group` in the package-level `tlsGroupToCurveID` map.
2. It returns the mapped ID plus the map's boolean. Unknown names return
   `(0, false)`; ID 0 is never a valid curve in this map.

Current map entries:

| OpenShift group | Go constant | Decimal |
|---|---|---:|
| `X25519` | `tls.X25519` | 29 |
| `secp256r1` | `tls.CurveP256` | 23 |
| `secp384r1` | `tls.CurveP384` | 24 |
| `secp521r1` | `tls.CurveP521` | 25 |
| `X25519MLKEM768` | `tls.X25519MLKEM768` | 4588 |
| `SecP256r1MLKEM768` | `tls.SecP256r1MLKEM768` | 4587 |
| `SecP384r1MLKEM1024` | `tls.SecP384r1MLKEM1024` | 4589 |

How to test: table-drive all seven entries and one invalid value. Assert the
decimal form with `uint16(id)` because that is what the operand flag carries.

Curve relevance: this is the authoritative translation. If a new OpenShift
group is added and this map is not updated, NROP reports it as unsupported and
silently drops it.

#### `libgocrypto.TLSGroupsToCurveIDs`

```go
func TLSGroupsToCurveIDs(groups []configv1.TLSGroup) ([]tls.CurveID, []configv1.TLSGroup)
```

Input: an ordered group list. Output: mapped IDs in the same order, plus the
unrecognized names.

Line by line:

1. It declares a nil `curves` slice and a nil `unrecognized` slice.
2. It loops over `groups` in API order.
3. It calls `TLSGroupToCurveID` for each name.
4. On failure, it appends the original name to `unrecognized` and continues.
5. On success, it appends the numeric ID to `curves`.
6. After the loop it returns both slices.

Properties you can rely on:

- Known groups preserve input order, including duplicates. NROP does not sort
  or de-duplicate the CSV.
- Unknown groups do not abort conversion; they are filtered.
- An all-unknown list returns `(nil, unknownList)`. Empty and all-unknown both
  produce an empty curve flag.

How to test:

```go
func TestTLSGroupsToCurveIDs(t *testing.T) {
	ids, unknown := libgocrypto.TLSGroupsToCurveIDs([]configv1.TLSGroup{
		configv1.TLSGroupX25519MLKEM768,
		configv1.TLSGroupX25519,
		"future-group",
		configv1.TLSGroupSecP256r1,
	})
	want := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	if !slices.Equal(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	if !slices.Equal(unknown, []configv1.TLSGroup{"future-group"}) {
		t.Fatalf("unknown = %v", unknown)
	}
}
```

Curve relevance: this loop is where unsupported groups disappear. Always test
the mixed known/unknown case, not only all-known.

#### `libgocrypto.ValidTLSGroups`

```go
func ValidTLSGroups() []configv1.TLSGroup
```

Input: none. Output: all known group names, sorted alphabetically.

Line by line:

1. It allocates a slice with capacity equal to the map size.
2. It ranges over `tlsGroupToCurveID` and appends each key.
3. It sorts with `slices.SortFunc` and `strings.Compare`.
4. It returns the sorted slice.

How to test: assert the slice is sorted with `slices.IsSorted`, contains all
seven current names, and has no duplicates. Treat the exact count as a
version-sensitive fact; update the test when library-go adds a group.

Curve relevance: useful in a precondition or diagnostic test. It is not on
the NROP reconcile path.

#### `libgocrypto.TLSVersionOrDie`

```go
func TLSVersionOrDie(versionName string) uint16
```

Line by line:

1. It calls `TLSVersion(versionName)`.
2. `TLSVersion` returns the default version when the name is empty.
3. Otherwise it looks the name up in `goTLSVersions`.
4. An unknown name returns an error.
5. `TLSVersionOrDie` panics on that error instead of returning it.
6. On success it returns the numeric `tls.VersionTLSxx` constant.

Why "OrDie": `NewTLSConfigFromProfile` is called at operator startup with an
API-validated profile. An invalid name is a programming or API-contract error,
not a recoverable request error. Tests should only pass valid names.

How to test: table for `VersionTLS10` through `VersionTLS13`, empty string
(default), and an invalid name if you want to assert the panic with
`defer recover()`.

#### `libgocrypto.TLSVersionToNameOrDie`

```go
func TLSVersionToNameOrDie(intVal uint16) string
```

Line by line:

1. It allocates a `matches` slice.
2. It ranges over the `goTLSVersions` name-to-number map.
3. It appends every name whose number equals `intVal`.
4. If there are no matches, it panics; the number is not a known version.
5. If there is more than one name for the number, it panics; the map would be
   ambiguous.
6. Otherwise it returns the single name.

`objtls.NewSettings` uses this to produce the operand's
`VersionTLS12`-style string. A wrong numeric version in a test therefore
panics rather than silently producing an empty flag.

How to test: table for each numeric version and a recover assertion for zero.

#### `libgocrypto.OpenSSLToIANACipherSuites`

```go
func OpenSSLToIANACipherSuites(ciphers []string) []string
```

Line by line:

1. It allocates an IANA-name slice with capacity for every input cipher.
2. It loops over the OpenSSL names.
3. It looks each name up in `openSSLToIANACiphers`.
4. If found, it appends the IANA name.
5. If not found, it logs at verbosity 4 that the cipher is being dropped.
6. It continues with the remaining names.
7. It returns the IANA names in input order.

This function is used by `OpenSSLCipherToGoID` and by TLS 1.2 cipher
assertions. Unsupported ciphers are silently omitted, so a test that only
checks `len(result)` can pass with zero results; always assert the expected
name.

How to test: known OpenSSL names, a mix of known and unknown, and an empty
input. Assert order and omission behavior.

#### `tls.CipherSuiteName`

```go
func CipherSuiteName(id uint16) string
```

Line by line:

1. Go searches `tls.CipherSuites()` for a matching ID.
2. If found, it returns the IANA name.
3. If not found, it searches `tls.InsecureCipherSuites()`.
4. If still not found, it returns a hexadecimal string such as `0xC02F`.

`objtls.NewSettings` uses this for every configured cipher ID. If a profile
contains a cipher Go does not know, the result is a hex string rather than an
error, which may later fail operand parsing. Tests should assert the expected
IANA name and not merely non-empty output.

How to test: known secure cipher, known insecure cipher, and unknown ID
(assert `0x` prefix).

#### `tls.VersionName`

```go
func VersionName(version uint16) string
```

Line by line:

1. Go looks up the numeric version in its known version table.
2. If found, it returns a name such as `TLS 1.2`.
3. If not found, it returns a hexadecimal string such as `0x0304`.

The probes use it only for logging. It is not part of the assertion path, but
it makes a failed handshake readable in the Ginkgo report. In a test message,
prefer `libgocrypto.TLSVersionToNameOrDie` when you need the exact
`VersionTLS12` operand spelling; `tls.VersionName` produces the display form.

How to test: table for each known version and one unknown value.

#### `intls.GetClusterTLSProfile`

```go
func GetClusterTLSProfile(ctx context.Context, cli client.Client) (uint16, configv1.TLSProfileSpec, error)
```

Location: `test/internal/tls/tls.go`.

Input: controller-runtime client. Output: numeric minimum TLS version, the raw
profile spec, and an error.

Line by line:

1. It calls `ctrltls.FetchAPIServerTLSProfile(ctx, cli)`.
2. On error, it returns `0`, an empty spec, and a wrapped error that names the
   API Server source.
3. It calls `tlsConfigFromProfileSpec(profileSpec)` to apply the profile to a
   Go config.
4. It logs the numeric minimum version using `tls.VersionName`.
5. It returns `cfg.MinVersion`, the original `profileSpec`, and nil.

Why it returns both: some assertions need the numeric version (`>=` checks),
while curve and cipher assertions need the OpenSSL names and `Groups` list.

How to test: fake client with an `APIServer` object. Assert the numeric version
matches the profile's `MinTLSVersion`, and that `Groups` is not modified.

Curve relevance: every new non-disruptive spec starts with this helper to get
the allowed group list.

#### `intls.tlsConfigFromProfileSpec`

```go
func tlsConfigFromProfileSpec(profileSpec configv1.TLSProfileSpec) *tls.Config
```

Line by line:

1. It calls `ctrltls.NewTLSConfigFromProfile(profileSpec)` and receives the
   callback plus `unsupportedCiphers` (the slice also contains unsupported
   groups).
2. If the unsupported list is non-empty, it logs the list at info level. It
   does not fail the test; that is intentional, because unsupported entries
   are a valid API-skew condition.
3. It allocates an empty `&tls.Config{}`.
4. It invokes the callback on that config.
5. It returns the config.

How to test: call it directly with a known profile and assert `MinVersion`,
`CipherSuites`, and `CurvePreferences`. Add a mixed known/unknown group case
and assert that the known IDs remain.

Curve relevance: this is the test-side mirror of the production conversion
path. If production and test call different functions, assertions can lie.

### 4.2 Settings formatting layer

#### `objtls.Settings`

```go
type Settings struct {
	MinVersion       string
	CipherSuites     string
	CurvePreferences string
}
```

This is the operand-facing representation. Every field is already a string.
`CurvePreferences` is a comma-separated decimal ID list such as
`4588,29,23,24`; it is not a Go slice.

Why strings: the values are written directly into container `args`. Keeping
them preformatted avoids repeated conversion during every reconcile and makes
the desired object deterministic.

How to test: use it as the expected value in helper tests. For an empty profile
use `objtls.Settings{}`; do not use `"[]"` or `"0"`.

#### `objtls.Settings.String`

```go
func (s Settings) String() string
```

Line by line:

1. It formats `MinVersion` and `CipherSuites` into
   `MinVersion: <v>, CipherSuites: <v>`.
2. If `CurvePreferences` is non-empty, it appends
   `, CurvePreferences: <csv>`.
3. It returns the result.

It is a logging helper, not an assertion format. Do not parse its output in
tests; compare fields directly.

How to test: one case with curves and one without. The existing
`TestSettings_String` covers both.

#### `objtls.NewSettings`

```go
func NewSettings(cfg *tls.Config) Settings
```

Input: an initialized Go TLS config. Output: the string settings used by both
operands.

Line by line:

1. It allocates `cipherNames` with capacity for every configured cipher ID.
2. It loops over `cfg.CipherSuites`.
3. For each ID it calls `tls.CipherSuiteName(id)` and appends the IANA name.
4. It builds `Settings.MinVersion` with
   `libgocrypto.TLSVersionToNameOrDie(cfg.MinVersion)`. This produces values
   such as `VersionTLS12`.
5. It joins `cipherNames` with commas into `Settings.CipherSuites`.
6. If `cfg.CurvePreferences` is non-empty, it sets
   `Settings.CurvePreferences` using `curveIDsToString`.
7. It returns the settings.

Important behavior: an empty `cfg.CipherSuites` produces an empty string, not
an empty element. A TLS 1.3 profile therefore has no cipher flag value, which
matches the production closure that intentionally leaves the field nil.

Failure modes:

- Calling it with a zero `tls.Config` produces `MinVersion: VersionTLS10`
  semantics from the conversion helper, not an error. Always initialize the
  config from a profile in tests.
- Curves are not sorted; the order is the input order.

How to test: table-driven cases for each curve family, empty curves, only PQ,
and only FIPS curves. The existing `TestNewSettings_WithCurvePreferences`
covers `29,23,24`, `4588,29,23`, `4588`, `23,24,25`, and empty.

Curve relevance: this is where numeric IDs become the exact CSV string that
the operand receives. Any mismatch here breaks argument tests even when
mapping is correct.

#### `objtls.curveIDsToString`

```go
func curveIDsToString(ids []tls.CurveID) string
```

Line by line:

1. It creates a `strings.Builder`, which avoids repeated string allocations.
2. It loops over `ids` with index `i`.
3. When `i > 0`, it writes a comma before the next value.
4. It converts each ID with `strconv.Itoa(int(id))` and writes it.
5. It returns the builder's string.

Why decimal: the operand flags are parsed as integers by RTE and the
scheduler. Names such as `X25519` are not accepted on the command line.

How to test: indirect tests through `NewSettings` are enough, but a direct
test can cover empty, one, and many IDs. The function is unexported, so the
test must live in package `tls` (the production package), not `tls_test`.

Curve relevance: a comma or formatting bug produces a flag that the operand
cannot parse, which usually appears as a CrashLoopBackOff rather than a test
failure.

### 4.3 Flag codec and operand argument layer

#### `flagcodec.Val`

```go
type Val struct {
	Kind int
	Data string
}
```

`Kind` is `FlagToggle` or `FlagOption`. `Data` is the value for an option and
empty for a toggle. `GetFlag` returns this type, so curve assertions use
`val.Data`.

#### `flagcodec.ParseArgvKeyValue`

```go
func ParseArgvKeyValue(args []string, opts ...Option) *Flags
```

Input: container `args` where each element is either `--flag` or
`--flag=value`. Output: a `*Flags` map plus insertion order.

Line by line:

1. It allocates `Flags` with an empty `args` map.
2. It initializes `processFlagName` to an identity function, so no
   normalization happens by default.
3. It applies each option in `opts`; `WithFlagNormalization` replaces the
   name processor.
4. It loops over the input `args` slice.
5. For each element it calls `strings.SplitN(arg, "=", 2)`, so only the first
   `=` splits. Values containing `=` remain intact.
6. If there is no `=`, it treats the element as a toggle and calls
   `SetToggle`.
7. Otherwise it treats the two fields as name and value and calls `SetOption`.
8. It returns the populated `Flags`.

This parser deliberately does **not** support the two-element form
`["--flag", "value"]`. NROP container args are generated in the
`--flag=value` form. If you pass a two-element form, `value` is recorded as a
toggle, and the assertion fails.

How to test:

```go
func TestParseArgvCurve(t *testing.T) {
	flags := flagcodec.ParseArgvKeyValue([]string{
		"--metrics-mode=httptls",
		"--metrics-tls-curve-preferences=4588,29,23,24",
	}, flagcodec.WithFlagNormalization)
	val, ok := flags.GetFlag("--metrics-tls-curve-preferences")
	if !ok || val.Data != "4588,29,23,24" {
		t.Fatalf("curve flag not parsed: %+v %v", val, ok)
	}
}
```

#### `flagcodec.WithFlagNormalization` and `normalizeFlagName`

```go
func WithFlagNormalization(fl *Flags) *Flags
```

Line by line:

1. `WithFlagNormalization` replaces `fl.processFlagName` with
   `normalizeFlagName`.
2. `normalizeFlagName` checks whether the name is exactly three bytes and
   starts with `--`.
3. If so, it drops one leading dash, turning `--v` into `-v`.
4. Every other name is returned unchanged.

Why it matters: pflag accepts both `-v` and `--v`, but the flagcodec map treats
them as different keys unless normalization is on. All NROP operand checks use
it.

How to test: parse `--v=3` and assert `GetFlag("-v")` finds it. Parse
`--metrics-tls-curve-preferences` and assert normalization does not change it.

#### `Flags.SetOption`

```go
func (fl *Flags) SetOption(name, data string)
```

Line by line:

1. It normalizes the flag name.
2. It calls `recordFlag`, which appends the name to the ordered `keys` slice
   only if the map does not already contain it.
3. It stores a `Val{Kind: FlagOption, Data: data}` in the map.

Consequence: setting the same option twice updates the value but does not
duplicate the key. This is essential for idempotent reconciliation.

How to test: call `SetOption` twice with different values; assert `Argv()`
contains one element with the last value.

#### `Flags.Delete`

```go
func (fl *Flags) Delete(name string)
```

Line by line:

1. It normalizes the name.
2. It calls `forgetFlag`, which rebuilds the ordered key slice without that
   name.
3. It deletes the name from the map.

Deleting a missing flag is a no-op. This is exactly what the operand updater
needs when a profile has no groups.

How to test: set a curve flag, delete it, assert `GetFlag` returns false and
`Argv` omits it. Delete again and assert no panic.

#### `Flags.GetFlag`

```go
func (fl *Flags) GetFlag(name string) (Val, bool)
```

Line by line:

1. It normalizes the requested name.
2. It looks up the map.
3. On a hit, it returns the stored `Val` and true.
4. On a miss, it returns a zero `Val` and false.

`matchTLSFlag` distinguishes "not found" from "found with empty data"; both
matter for delete-on-empty semantics.

#### `Flags.Args` and `Flags.Argv`

```go
func (fl *Flags) Args() []string
func (fl *Flags) Argv() []string
```

Line by line:

1. `Args` allocates a slice.
2. It walks `keys` in insertion order.
3. It converts each entry with `toString`: toggles become the name; options
   become `name=data`.
4. `Argv` calls `Args`.
5. If `command` is empty, it returns the args directly.
6. Otherwise it prepends the command.

Operand containers normally store only args, not the command, so `Argv` is
used directly after parsing.

How to test: order preservation, toggle rendering, option rendering, and the
empty command case.

#### `Flags.recordFlag`

```go
func (fl *Flags) recordFlag(name string)
```

Line by line:

1. It checks whether `name` already exists in the `args` map.
2. If it does not exist, it appends `name` to the ordered `keys` slice.
3. If it already exists, it does nothing.

The map answers "what is the value"; the slice answers "in what order do I
write the argv". Recording only on first insertion is what prevents duplicate
flags during repeated reconciliation.

#### `Flags.forgetFlag`

```go
func (fl *Flags) forgetFlag(name string)
```

Line by line:

1. It allocates a new `keys` slice with nil value.
2. It ranges over the existing keys.
3. It skips the key equal to `name`.
4. It appends every other key.
5. It assigns the new slice back to `fl.keys`.

It does not touch the `args` map; `Delete` does that separately. This split
keeps ordering and value storage consistent.

#### `toString`

```go
func toString(name string, val Val) string
```

Line by line:

1. If `val.Kind == FlagToggle`, it returns the name alone.
2. Otherwise it formats `name=val.Data`.

This is the exact rendering that makes a curve flag appear as
`--metrics-tls-curve-preferences=4588,29,23,24` in the container args.

#### `rteupdate.DaemonSetArgs`

```go
func DaemonSetArgs(ds *appsv1.DaemonSet, conf nropv1.NodeGroupConfig, metricsTLS objtls.Settings) error
```

Location: `pkg/objectupdate/rte/rte.go`.

Input: an RTE DaemonSet, node-group config, and the precomputed TLS settings.
Output: the DaemonSet is mutated in place, or an error is returned.

Line by line, focused on TLS:

1. It finds the container named `rteupdate.MainContainerName`
   (`resource-topology-exporter`).
2. If the container is absent, it returns `cannot find container data`.
3. It parses the container args with normalization.
4. If parsing returns nil, it returns an error. In practice the parser never
   returns nil, but the guard protects future changes.
5. It forces `--metrics-mode=httptls`.
6. If `metricsTLS.MinVersion` is non-empty, it sets
   `--metrics-tls-min-version`; otherwise it deletes that flag.
7. If `metricsTLS.CipherSuites` is non-empty, it sets
   `--metrics-tls-cipher-suites`; otherwise it deletes it.
8. If `metricsTLS.CurvePreferences` is non-empty, it sets
   `--metrics-tls-curve-preferences`; otherwise it deletes it.
9. It continues with unrelated RTE flags such as `--no-publish` and then
   assigns `cnt.Args = flags.Argv()`.

The curve branch is:

```go
if metricsTLS.CurvePreferences != "" {
	flags.SetOption("--metrics-tls-curve-preferences", metricsTLS.CurvePreferences)
} else {
	flags.Delete("--metrics-tls-curve-preferences")
}
```

Failure modes:

- Missing or renamed main container: `cannot find container data`.
- Wrong flag name: the operand ignores the flag or exits.
- Missing else/delete branch: stale curves persist after switching to a
  profile with no groups.
- Setting instead of deleting when empty: operand receives
  `--metrics-tls-curve-preferences=` and may fail to parse.

How to test: unit-test `DaemonSetArgs` with a minimal DaemonSet. Cover:
with curves, replacing an old curve list, and removing a curve flag when the
expected CSV is empty. The existing `TestDaemonSetArgs/TLS with curve
preferences` covers the positive case; add the stale/remove case.

Controller test: set `reconciler.RTEMetricsTLS` to a settings value with
`CurvePreferences: "29,23,24"` and assert the generated DaemonSet contains the
flag. Existing `numaresourcesoperator_controller_test.go` already has a curve
case; extend it with the empty transition.

E2E: compare the live DaemonSet args with
`intls.CheckRTEDaemonSetTLSFlags`.

Curve relevance: this function is the only production writer of the RTE curve
flag.

#### `schedupdate.DeploymentTLSSettings`

```go
func DeploymentTLSSettings(dp *appsv1.Deployment, tlsSettings objtls.Settings) error
```

Location: `pkg/objectupdate/sched/sched.go`.

Input: scheduler Deployment and settings. Output: mutated Deployment or error.

Line by line:

1. It finds the container named `schedupdate.MainContainerName`.
2. If absent, it returns `cannot find container`.
3. It parses container args with normalization.
4. If parsing returns nil, it returns an error.
5. It sets or deletes `--tls-min-version`.
6. It sets or deletes `--tls-cipher-suites`.
7. It sets or deletes `--tls-curve-preferences`.
8. It assigns `cnt.Args = flags.Argv()`.
9. It logs the three settings at verbosity 3.
10. It returns nil.

Failure modes and testing mirror the RTE function. The existing
`TestDeploymentTLSSettings` covers positive curves, replacement, empty
removal, and repeated calls. The controller test covers
`reconciler.TLSSettings` reaching the Deployment.

Curve relevance: this is the only production writer of the scheduler curve
flag.

#### `k8swgobjupdate.FindContainerByName`

```go
func FindContainerByName(conts []corev1.Container, name string) *corev1.Container
```

Line by line:

1. It loops by index, not by value, so the returned pointer points into the
   original slice.
2. It takes `&conts[idx]`.
3. It compares `cont.Name` to the requested name.
4. It returns the first match immediately.
5. If the loop ends, it returns nil.

Mutating the returned pointer mutates the container in the slice, which is how
the operand updaters work. Returning a pointer to a range variable would be a
bug; this implementation avoids it.

How to test: table with first, middle, last, missing, and duplicate names.
Assert pointer identity for the first duplicate.

#### Controller wiring points

These are not functions to call from tests, but you must understand where the
settings enter reconciliation.

`cmd/main.go` startup:

1. `FetchAPIServerTLSProfile(ctx, k8sClient)` reads the cluster profile.
2. `NewTLSConfigFromProfile` builds the callback and unsupported list.
3. A `tls.Config` is allocated and the callback applied.
4. `objtls.NewSettings(tlsCfg)` produces one immutable settings value.
5. The value is assigned to `NUMAResourcesOperatorReconciler.RTEMetricsTLS`
   and `NUMAResourcesSchedulerReconciler.TLSSettings`.

The operator restarts when the profile changes because a
`SecurityProfileWatcher` triggers graceful shutdown. Do not expect a running
operator to hot-reload the profile.

`NUMAResourcesOperatorReconciler.RTEMetricsTLS` is read in
`reconcilePerTreeDaemonSet` and passed to `daemonsetUpdater`, which eventually
calls `rteupdate.DaemonSetArgs`.

`NUMAResourcesSchedulerReconciler.TLSSettings` is passed to
`schedupdate.DeploymentTLSSettings` in the scheduler reconcile path.

### 4.4 Object discovery layer

#### `podlist.With`

```go
func With(cli client.Client) Finder
```

Line by line:

1. It returns a `Finder` struct with the supplied controller-runtime client
   embedded.
2. The embedded client promotes `List` and `Get` onto `Finder`.

This is a fluent constructor: `podlist.With(cli).ByDeployment(...)`. It does
no I/O itself.

How to test: it is exercised by every discovery test. No dedicated test is
needed.

#### `Finder.DeploymentByOwnerReference`

```go
func (fnd Finder) DeploymentByOwnerReference(ctx context.Context, uid types.UID) (*appsv1.Deployment, error)
```

Input: owner UID, usually `nroSchedObj.GetUID()`. Output: the first Deployment
whose owner references contain that UID.

Line by line:

1. It allocates an empty `DeploymentList`.
2. It lists all Deployments visible to the client. There is no namespace
   filter and no label filter.
3. If the list fails, it returns a wrapped error.
4. It loops over the returned items by value.
5. For each Deployment, it loops over `GetOwnerReferences()`.
6. If an owner UID matches, it returns `&deploy` and nil immediately. The
   pointer points to the range copy, which is fine for read-only callers.
7. If no match is found, it returns an error that includes the UID.

Failure modes:

- RBAC that allows reading one namespace but not listing all Deployments
  causes a forbidden error.
- A just-created scheduler may not have a Deployment yet; wrap the call in
  `Eventually` in E2E.
- Owner references can be missing if an object was created manually rather
  than by the scheduler reconciler.

How to test: fake client with two Deployments, only one carrying the target
owner reference. Assert the right one is returned; then remove the reference
and assert the error. Add a list-error test by using an interceptor or a client
without the apps scheme.

Curve relevance: it locates the scheduler Deployment whose pod exposes port
`10259`. Argument and handshake tests both depend on it.

#### `Finder.ByDeployment`

```go
func (fnd Finder) ByDeployment(ctx context.Context, deployment appsv1.Deployment) ([]corev1.Pod, error)
```

Line by line:

1. It allocates an empty `PodList`.
2. It converts `deployment.Spec.Selector` to a label selector with
   `metav1.LabelSelectorAsSelector`.
3. If the selector is malformed, it returns the conversion error.
4. It lists Pods in `deployment.Namespace` with that selector.
5. If the list fails, it returns the error.
6. It returns all matching Pods.

It does not wait for readiness and does not filter terminating Pods. A live
E2E should either wait for the Deployment to be available or choose a Running
Pod. Existing tests take `pods[0]`; a robust curve probe should prefer a
Running Pod:

```go
var pod *corev1.Pod
for i := range pods {
	if pods[i].DeletionTimestamp == nil && pods[i].Status.Phase == corev1.PodRunning {
		pod = &pods[i]
		break
	}
}
Expect(pod).ToNot(BeNil(), "no running scheduler pod")
```

How to test: fake client with matching and non-matching Pods in two
namespaces. Assert only matching Pods in the Deployment namespace are
returned.

#### `Finder.ByDaemonset`

```go
func (fnd Finder) ByDaemonset(ctx context.Context, ds appsv1.DaemonSet) ([]corev1.Pod, error)
```

Line by line:

1. It allocates a `PodList`.
2. It converts `ds.Spec.Selector` to a selector.
3. It returns the conversion error if the selector is invalid.
4. It lists Pods with that selector, without a namespace restriction.
5. If listing fails, it returns the error.
6. It returns all matching Pods.

Because it has no namespace, this relies on labels being specific enough. RTE
labels are managed by NROP and are unique in practice.

How to test: fake client with one RTE Pod per node group and an unrelated Pod
with a different label. Assert only RTE Pods are returned. Add a test with a
malformed selector.

Curve relevance: scenario 13 requires probing **every** RTE pod, not only the
first. `getRTEPodsFromNRO` loops node groups and calls this method once per
DaemonSet.

#### `objects.NROObjectKey` and `objects.NROSchedObjectKey`

```go
func NROObjectKey() client.ObjectKey
func NROSchedObjectKey() client.ObjectKey
```

Line by line:

1. `NROObjectKey` returns `{Name: objectnames.DefaultNUMAResourcesOperatorCrName}`.
2. `NROSchedObjectKey` returns `{Name: objectnames.DefaultNUMAResourcesSchedulerCrName}`.
3. Both leave Namespace empty because the CRs are cluster-scoped.

Using these helpers avoids hard-coded names and keeps tests aligned with
production constants.

### 4.5 Argument assertion layer

#### `intls.matchTLSFlag`

```go
func matchTLSFlag(rteFlags *flagcodec.Flags, flagName, expected, dsName string) error
```

Input: parsed flags, flag name, expected string, and an object name used in
errors. Output: nil on a match, otherwise a descriptive error.

Line by line:

1. It calls `rteFlags.GetFlag(flagName)` and receives `val, found`.
2. If `expected == ""`, it enters the absence branch.
3. In the absence branch, if the flag was found **and** `val.Data != ""`, it
   returns `should be absent or empty`.
4. If the flag was not found, or was found with empty data, it returns nil.
5. If `expected != ""`, it enters the presence branch.
6. If the flag was not found, or `val.Data != expected`, it builds a `got`
   string (empty when not found) and returns a mismatch error.
7. Otherwise it returns nil.

This comparator is already correct for delete-on-empty:

| Expected | Live flag | Result |
|---|---|---|
| `""` | absent | pass |
| `""` | `--flag=` | pass (lenient) |
| `""` | `--flag=23` | fail |
| `29,23` | absent | fail |
| `29,23` | `--flag=23,29` | fail |

Order matters because the operand argument is a literal value. NROP preserves
profile group order, so expected and actual must be generated by the same
mapping path in E2E.

How to test: call it through `CheckRTEDaemonSetTLSFlags` or add a direct table
test in package `tls`. A direct test is cheap and covers all five rows above.

Curve relevance: if you compare only flag presence and not value, scenario 3
passes even when NROP writes a hard-coded default.

#### `intls.CheckRTEDaemonSetTLSFlags`

```go
func CheckRTEDaemonSetTLSFlags(ctx context.Context, cli client.Client, expected objtls.Settings) error
```

Input: controller-runtime client and expected settings. Output: nil only when
every RTE DaemonSet matches.

Line by line:

1. It allocates an empty `NUMAResourcesOperator`.
2. It gets the object named `objectnames.DefaultNUMAResourcesOperatorCrName`.
3. If the get fails, it returns `failed to get NUMAResourcesOperator`.
4. If `Status.NodeGroups` is empty, it returns an error. This distinguishes a
   broken operator from a vacuously successful check.
5. It loops over every node group.
6. For each group it gets the DaemonSet named in
   `ng.DaemonSet.Namespace/Name`.
7. If the get fails, it returns a wrapped `failed to get DaemonSet` error.
8. It finds the `resource-topology-exporter` container with
   `FindContainerByName`.
9. If absent, it returns `main container not found` with the DaemonSet name.
10. It parses the container args with normalization.
11. It calls `matchTLSFlag` for `--metrics-tls-min-version`.
12. It calls `matchTLSFlag` for `--metrics-tls-cipher-suites`. The comment
    notes that TLS 1.3 leaves this empty because Go does not allow configuring
    TLS 1.3 ciphers.
13. It calls `matchTLSFlag` for `--metrics-tls-curve-preferences`.
    `matchTLSFlag` treats an expected-empty value as “flag must be absent or
    empty”, which implements delete-on-empty semantics for profiles with no
    groups.

The implemented third call is:

```go
if err := matchTLSFlag(rteFlags, "--metrics-tls-curve-preferences", expected.CurvePreferences, ds.Name); err != nil {
	return err
}
```

Failure modes:

- NROP not found: usually wrong suite setup or a missing CR.
- No node groups: operator not reconciled yet; E2E should use `Eventually`.
- DaemonSet not found: status references a deleted or not-yet-created object.
- Stale curves: the curve assertion now detects a non-empty flag when the profile expects no curves.

How to test:

- Existing fake-client test `TestCheckRTEDaemonSetTLSFlags` covers missing
  NROP, no node groups, missing DaemonSet, missing container, matching flags,
  min-version/cipher/curve mismatch, stale curve when expected empty, and
  multiple node groups.
- A multi-node-group case where only the second group has a wrong curve flag
  is also covered.
- E2E: call it inside `Eventually` because the operator may still be updating.

#### `intls.RTESettingsFromClusterProfile`

```go
func RTESettingsFromClusterProfile(ctx context.Context, cli client.Client) (objtls.Settings, error)
```

Line by line:

1. It calls `GetClusterTLSProfile`.
2. If that fails, it returns empty settings and the error.
3. It calls `objtls.NewSettings(tlsConfigFromProfileSpec(profileSpec))`.
4. It returns the resulting settings.

Despite the name, the result is operand-agnostic. The same settings apply to
the scheduler. A better future name is `SettingsFromClusterProfile`, but do
not rename it in a minimal change.

How to test: fake client with an `APIServer`; assert `CurvePreferences` equals
the expected CSV. Build the expectation from the same profile rather than
hard-coding unless you are deliberately testing pinned values.

#### `intls.CheckRTEDaemonSetTLSFlagsMatchClusterProfile`

```go
func CheckRTEDaemonSetTLSFlagsMatchClusterProfile(ctx context.Context, cli client.Client) error
```

Line by line:

1. It derives expected settings with `RTESettingsFromClusterProfile`.
2. If derivation fails, it returns the error without checking any operand.
3. It calls `CheckRTEDaemonSetTLSFlags` with those settings.

This is the convenience entry point used by test 88380. In a new curve spec,
prefer calling the two steps separately so a failure message tells you whether
profile derivation or argument comparison failed.

How to test: E2E inside `Eventually`. A fake-client test is covered by the
underlying functions; add one only if you want to assert error propagation.

#### `intls.TLSVersionBelow`

```go
func TLSVersionBelow(v uint16) (uint16, error)
```

Line by line:

1. It switches on the numeric version.
2. TLS 1.3 maps to TLS 1.2.
3. TLS 1.2 maps to TLS 1.1.
4. TLS 1.1 maps to TLS 1.0.
5. Any other value, including TLS 1.0 and zero, returns an error.

How to test: table with all four supported inputs and two errors. Existing
`TestTLSVersionBelow` covers them.

Curve relevance: the negative version probe needs a version below the profile
minimum. The negative **curve** probe does not use this helper; it offers a
single disallowed curve.

#### `intls.CheckSchedulerDeploymentTLSFlags` (implemented)

The scheduler argument helper exists in the current code. Review it and add
fake-client tests; it mirrors the RTE helper:

```go
func CheckSchedulerDeploymentTLSFlags(ctx context.Context, cli client.Client, expected objtls.Settings) error
```

Line by line:

1. Get `NUMAResourcesScheduler` by
   `objectnames.DefaultNUMAResourcesSchedulerCrName`.
2. Find its Deployment with
   `podlist.With(cli).DeploymentByOwnerReference(ctx, nroSchedObj.GetUID())`.
3. Fail if the Deployment is nil.
4. Find `schedupdate.MainContainerName` in the Deployment containers.
5. Fail if the container is absent.
6. Parse its args with normalization.
7. Compare `--tls-min-version`.
8. Compare `--tls-cipher-suites`.
9. Compare `--tls-curve-preferences`.
10. Return nil only if all three match.

How to test:

- Fake client: create the scheduler CR with a UID, a Deployment with that
  owner reference, and a container named `secondary-scheduler`. Cover matches,
  each mismatch, missing CR, missing Deployment, and missing container.
- E2E: combine with the RTE helper in one `Eventually` so both operands are
  checked under the same profile snapshot.

Curve relevance: without this helper, scheduler curve propagation is only
covered by a controller-test substring assertion, not by a live-cluster
assertion.

#### `intls.CurveIDsFromProfile` (proposed)

```go
func CurveIDsFromProfile(profileSpec configv1.TLSProfileSpec) []tls.CurveID
```

Line by line:

1. Call `libgocrypto.TLSGroupsToCurveIDs(profileSpec.Groups)`.
2. Discard the unrecognized slice. For a positive assertion this is acceptable
   because "allowed" means recognized and enforced.
3. Return the IDs.

For stricter tests, return both slices and assert that unrecognized is empty
when the API accepted the profile.

How to test: table with a built-in profile and Custom groups; assert order and
values.

Curve relevance: handshake assertions compare `state.CurveID` to this set.

### 4.6 Port-forward and TLS probe layer

#### `remoteexec.PortForwardToPod`

```go
func PortForwardToPod(c kubernetes.Interface, pod *corev1.Pod, podPort string, fn func(conn net.Conn) error) error
```

Line by line:

1. It delegates to `PortForwardToPodByNames` using `pod.Namespace` and
   `pod.Name`.
2. It passes the port and callback unchanged.

It is a convenience wrapper; all logic is in the `ByNames` variant. A new
contributor can read every probe below as "open this pod port, then run my
callback on a connection that behaves like a TCP socket".

#### `remoteexec.PortForwardToPodByNames`

```go
func PortForwardToPodByNames(c kubernetes.Interface, podNamespace, podName, podPort string, fn func(conn net.Conn) error) error
```

This is the most failure-prone helper in the probe path. Understand it before
debugging a handshake test.

Line by line:

1. It builds an SPDY dialer with `portForwardDialer(c, namespace, name)`.
2. If dialer creation fails, it returns `port-forward dialer creation failed`.
3. It dials the port-forward subprotocol with
   `dialer.Dial(utilportforward.PortForwardV1Name)`.
4. If dialing fails, it returns `port-forward dial to ns/pod:port failed`.
5. It defers closing the SPDY connection and logs a close error; a close
   failure does not override the test result.
6. It builds HTTP headers for the kubelet error stream:
   `StreamTypeError`, `PortHeader=podPort`, and
   `PortForwardRequestIDHeader=0`.
7. It creates the error stream. Failure returns
   `port-forward error stream creation failed`.
8. It defers closing the error stream.
9. It creates a buffered error channel of size one, so the goroutine cannot
   block forever if nobody reads.
10. It starts a goroutine that reads the entire error stream.
11. If the read fails, the goroutine sends the read error.
12. If the read succeeds with non-empty bytes, it sends an error containing the
    kubelet message.
13. If the read succeeds with no bytes, it sends nil.
14. It switches the same header set to `StreamTypeData`.
15. It creates the data stream. Failure returns
    `port-forward data stream creation failed`.
16. It wraps the stream in `streamConn` so it satisfies `net.Conn`.
17. It invokes your callback with that connection.
18. It closes the forwarded data connection immediately after the callback
    returns.
19. If the callback returned an error, it returns that error. The error-stream
    goroutine may still finish in the background; the SPDY defer closes it.
20. Otherwise it waits on the error channel and returns any kubelet error.

Why the explicit data-stream close matters: the server only finishes the
port-forward and closes the error stream after the data stream closes. If the
callback returns without closing and the code waits on the error channel
first, `io.ReadAll` can block forever. The close-before-wait order prevents a
deadlock.

Failure modes and what they mean:

| Error fragment | Likely cause |
|---|---|
| `dialer creation failed` | no kubeconfig, bad REST config, SPDY setup failure |
| `dial to ns/pod:port failed` | pod missing, wrong port, kubelet refuses port-forward |
| `error stream creation failed` | API server/SPDY stream limit or connection loss |
| `data stream creation failed` | port-forward rejected after setup |
| kubelet message from error stream | port not listening inside the pod |
| callback error | TLS handshake failed, which may be the expected result |

How to test:

- Unit testing the full function requires a fake SPDY server and is not worth
  it in this repository.
- E2E is the real test: probe a known-open port (`10259` or `2112`) and
  assert a successful handshake.
- For a negative port test, use a port that is not open and assert the
  port-forward error path separately from the TLS error.

#### `remoteexec.portForwardDialer`

```go
func portForwardDialer(c kubernetes.Interface, podNamespace, podName string) (httpstream.Dialer, error)
```

Line by line:

1. It creates a POST request through the typed REST client for
   `pods/<name>/portforward` in the namespace.
2. It obtains the REST config with `config.GetConfig()`. This reads the
   in-cluster config or kubeconfig and can fail outside a cluster.
3. It builds an SPDY round tripper and upgrader.
4. It creates an SPDY dialer with an HTTP client and the request URL.
5. It returns the dialer.

How to test: E2E only. A missing `KUBECONFIG` is the usual local failure.

#### `remoteexec.streamConn`

```go
type streamConn struct{ stream httpstream.Stream }
```

Line by line:

1. `Read` delegates to `stream.Read`.
2. `Write` delegates to `stream.Write`.
3. `Close` delegates to `stream.Close`.
4. `LocalAddr` and `RemoteAddr` return a stub with network `"spdy"` and
   address `"port-forward"`.
5. All three deadline setters return nil without doing anything.

The no-op deadlines are important: if the peer stops responding, a handshake
can hang until the Ginkgo timeout or process timeout. E2E specs should use
`--ginkgo.timeout` and avoid unbounded loops. A future improvement is to
implement deadlines through the SPDY stream if the library supports them.

#### `intls.tlsHandshake`

```go
func tlsHandshake(conn net.Conn, cfg *tls.Config) (*tls.ConnectionState, error)
```

Line by line:

1. It wraps the existing connection with `tls.Client(conn, cfg)`. It does not
   dial; the port-forward has already produced a live connection.
2. It calls `tlsConn.Handshake()` and waits for the full handshake.
3. On error, it returns nil and the raw error. Wrapping is the caller's job.
4. It defers `tlsConn.Close()` and logs a close error.
5. It reads `tlsConn.ConnectionState()` into a value.
6. It returns a pointer to that value.

The returned state includes `Version`, `CipherSuite`, `CurveID`, certificates,
and the negotiated protocol. `CurveID` is the field curve tests need.

How to test:

- Unit-test the failure path with `net.Pipe` and a client config with
  incompatible min/max versions; assert an error.
- Unit-test a successful handshake by starting a local `tls.Server` on a
  `net.Pipe` with a generated self-signed certificate. This is more setup than
  the value it adds; the E2E probes already exercise the success path against
  real servers.
- At minimum, test that `wrapTLSHandshakeError` classifies the errors produced
  by bad configs.

#### `intls.wrapTLSHandshakeError`

```go
func wrapTLSHandshakeError(err error) error
```

Line by line:

1. If `err` is nil, it returns nil.
2. It declares a `tls.AlertError`.
3. It uses `errors.As` to detect a TLS alert from the server. If found, it
   wraps it with `ErrTLSServerRejected`, which itself wraps
   `ErrTLSHandshakeRejected`.
4. Otherwise, if the error text contains `handshake failure` or
   `protocol version`, it classifies it as server rejection.
5. If the text contains `no supported versions` or `no ciphers available`, it
   classifies it as client configuration incompatibility.
6. If none match, it returns the original error unchanged.

Why two categories: a server rejection proves the server enforced policy; a
client config error means the test itself asked for an impossible
combination. Tests must assert `ErrTLSHandshakeRejected` so that a broken test
does not look like a successful rejection.

How to test: the exact table already exists in `TestWrapTLSHandshakeError`:
nil, `tls.AlertError(40)`, handshake-failure string, protocol-version string,
no-supported-versions string, no-ciphers string, and an unrelated connection
error.

#### `intls.ProbeMaxTLSVersion`

```go
func ProbeMaxTLSVersion(cli kubernetes.Interface, pod *corev1.Pod, podPort string, maxVersion uint16) error
```

Line by line:

1. It builds `key := client.ObjectKeyFromObject(pod)` for logging.
2. It logs the pod, port, and `tls.VersionName(maxVersion)`.
3. It calls `remoteexec.PortForwardToPod`.
4. Inside the callback it calls `tlsHandshake` with `InsecureSkipVerify: true`,
   `MinVersion: maxVersion`, and `MaxVersion: maxVersion`.
5. It returns `wrapTLSHandshakeError(err)` from the callback.
6. It returns the port-forward result.

`InsecureSkipVerify` is intentional: the test asserts protocol policy, not
certificate trust. Certificates are checked by other tests.

How to test: E2E negative. If the profile minimum is TLS 1.2, pass TLS 1.1 and
assert `errors.Is(err, intls.ErrTLSHandshakeRejected)`. If the profile minimum
is TLS 1.3, pass TLS 1.2. Use `TLSVersionBelow` to compute the value.

#### `intls.ProbeTLSCipher`

```go
func ProbeTLSCipher(cli kubernetes.Interface, pod *corev1.Pod, podPort string, cipher string) error
```

Line by line:

1. It converts the OpenSSL cipher name to a Go ID with
   `OpenSSLCipherToGoID`. An unknown name returns an error before any
   connection is opened.
2. It logs the pod, port, cipher name, and numeric ID.
3. It port-forwards to the pod.
4. Inside the callback it calls `tlsHandshake` with
   `InsecureSkipVerify: true`, `MaxVersion: tls.VersionTLS12`, and
   `CipherSuites: []uint16{cipherID}`.
5. It returns the wrapped handshake error.

The TLS 1.2 cap is required because `CipherSuites` has no effect on TLS 1.3.
Callers must skip this probe when the profile minimum is TLS 1.3.

How to test: E2E negative with `FindDisallowedCipher`; unit-test the conversion
failure via an unknown name.

#### `intls.ProbeTLSSettings`

```go
func ProbeTLSSettings(cli kubernetes.Interface, pod *corev1.Pod, podPort string) (version uint16, cipherSuite uint16, err error)
```

Line by line:

1. It builds a pod key for logging.
2. It port-forwards to the pod.
3. Inside the callback it performs a default handshake with
   `InsecureSkipVerify: true`.
4. On error, it returns the raw error.
5. On success, it assigns `state.Version` to the named return `version`.
6. It assigns `state.CipherSuite` to the named return `cipherSuite`.
7. It logs both names.
8. It returns nil from the callback.
9. It returns the captured values and the port-forward error.

It discards `state.CurveID`. That is the main gap for curve tests. Do not
change its signature in a minimal patch; add `ProbeTLSState` and optionally
refactor this function to call it.

How to test: E2E positive. For TLS 1.2, assert the version is at least the
profile minimum and the cipher is allowed. For TLS 1.3, cipher assertions are
not meaningful.

#### `intls.ProbeTLSState` (proposed)

```go
func ProbeTLSState(cli kubernetes.Interface, pod *corev1.Pod, podPort string) (*tls.ConnectionState, error)
```

Line by line:

1. Declare a `*tls.ConnectionState` variable.
2. Port-forward to the pod.
3. In the callback, call `tlsHandshake` with `InsecureSkipVerify: true`.
4. Assign the returned state to the outer variable.
5. Return the handshake error so port-forward can propagate it.
6. After port-forward returns, return the state and error.

Because the callback runs synchronously before port-forward returns, the outer
variable is safe without a mutex.

How to test: E2E positive against scheduler and RTE. Assert `CurveID != 0`
and that it is in the profile-derived allowed set. Skip when `CurveID == 0`
because a legacy RSA key exchange does not use a curve.

#### `intls.ProbeTLSCurve` (proposed)

```go
func ProbeTLSCurve(cli kubernetes.Interface, pod *corev1.Pod, podPort string, curveID tls.CurveID) error
```

Line by line:

1. Port-forward to the pod.
2. In the callback, call `tlsHandshake` with `InsecureSkipVerify: true` and
   `CurvePreferences: []tls.CurveID{curveID}`.
3. This offers exactly one key-exchange group.
4. Wrap and return the handshake error.

If the server does not allow that group, the handshake fails. If the server
allows it, the handshake succeeds and the test should fail because it expected
rejection.

How to test: E2E negative. Use a curve known to be outside the profile, such
as `tls.CurveP521` (25) for the built-in profiles. Assert both that an error
occurred and that `errors.Is(err, intls.ErrTLSHandshakeRejected)` is true.

#### `intls.FindDisallowedCurve` (proposed)

```go
func FindDisallowedCurve(allowed []tls.CurveID) (tls.CurveID, error)
```

Line by line:

1. Build a `map[tls.CurveID]bool` from `allowed`.
2. Declare a fixed ordered list of Go-supported curves.
3. Walk the list in a deterministic order.
4. Return the first ID not present in the allowed set.
5. If every supported ID is allowed, return an error so the test can skip with
   a clear reason.

Use a fixed list rather than ranging over Go internals; tests must be
deterministic and readable. Current list: P-256, P-384, P-521, X25519,
X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024.

How to test: pure unit table. Allowed empty returns P-256. Allowed all returns
an error. Allowed `{P256, P384}` returns P-521.

#### `intls.OpenSSLCipherToGoID`

```go
func OpenSSLCipherToGoID(opensslName string) (uint16, error)
```

Line by line:

1. It calls `libgocrypto.OpenSSLToIANACipherSuites` with a one-element slice.
2. If the result is empty, it returns `unknown OpenSSL cipher`.
3. It takes the first IANA name. The OpenSSL-to-IANA mapping is one-to-one for
   the names used here.
4. It walks `tls.CipherSuites()` and returns the ID of the matching IANA name.
5. If not found there, it walks `tls.InsecureCipherSuites()`.
6. If still not found, it returns an error that includes both names.

How to test: existing `TestOpenSSLCipherToGoID` covers a known cipher, a known
insecure cipher, and an unknown name. Add a TLS 1.3 IANA name if you want to
document that conversion works but is not usable for policy assertions.

#### `intls.FindDisallowedCipher`

```go
func FindDisallowedCipher(allowed []string) string
```

Line by line:

1. It builds a set from the allowed OpenSSL names.
2. It reads the Old profile's cipher list, the broadest built-in list.
3. It skips names beginning with `TLS_`; those are IANA TLS 1.3 names and are
   not individually configurable.
4. It returns the first OpenSSL-name cipher not in the allowed set.
5. If all are allowed, it returns the empty string.

How to test: existing tests cover Old (empty), Intermediate (non-empty),
nil allowed (returns a TLS 1.2 cipher), and the skip-TLS-1.3 rule.

#### `intls.FetchMetrics`

```go
func FetchMetrics(cli kubernetes.Interface, pod *corev1.Pod, podPort string) ([]byte, error)
```

Line by line:

1. It declares `body []byte`.
2. It port-forwards to the pod.
3. In the callback it calls `doMetricsRequestOverConnection(conn, podPort)`.
4. It assigns the returned bytes to `body`.
5. It returns the request error to the port-forward helper.
6. After port-forward, it returns nil and the port-forward error if any.
7. Otherwise it returns `body`.

This proves the TLS listener is usable, not merely accepting handshakes.

#### `intls.doMetricsRequestOverConnection`

```go
func doMetricsRequestOverConnection(conn net.Conn, podPort string) ([]byte, error)
```

Line by line:

1. It builds an HTTP client bound to the supplied connection.
2. It defers `CloseIdleConnections`; keep-alives are disabled anyway.
3. It calls `executeMetricsRequest`.

#### `intls.buildMetricsHTTPClient`

```go
func buildMetricsHTTPClient(conn net.Conn) *http.Client
```

Line by line:

1. It declares `usedConn := false` in the closure.
2. It creates an `http.Transport` with a TLS config that skips certificate
   verification, because trust is not the assertion.
3. It defines `DialContext` to return the single port-forwarded connection on
   the first call.
4. On a second dial attempt it returns an explicit error instead of hanging or
   opening a new network connection.
5. It disables keep-alives.
6. It returns a client using that transport.

The single-dial guard is essential: the port-forward callback owns exactly one
stream, and retries cannot create another.

#### `intls.executeMetricsRequest`

```go
func executeMetricsRequest(httpCli *http.Client, podPort string) ([]byte, error)
```

Line by line:

1. It builds a GET request for `https://127.0.0.1/metrics`.
2. It sets `req.Host` to `127.0.0.1:<podPort>` so TLS SNI and the HTTP Host
   header use the forwarded port.
3. It executes the request.
4. On error it returns `failed HTTPS Get /metrics`.
5. It defers closing the response body.
6. It reads the full body.
7. It returns an error if reading fails.
8. It requires HTTP 200 and returns an error with the status and trimmed body
   otherwise.
9. It returns the body.

How to test: E2E only; existing 88381 checks a known metric name.

### 4.7 Serial/disruptive orchestration layer

Serial tests are different from the non-disruptive suite. They change
cluster-wide configuration, trigger MachineConfigPool rollouts, and may reboot
nodes. A new contributor should not start here. First make the helper and
non-disruptive specs pass, then add one serial transition.

#### `tlsGroupPreferencesEnabled` (proposed)

```go
func tlsGroupPreferencesEnabled(ctx context.Context, cli client.Client) (bool, error)
```

Input: controller-runtime client. Output: whether the `TLSGroupPreferences`
feature gate is enabled, plus a read error.

Line by line:

1. Allocate `&configv1.FeatureGate{}`.
2. `Get` the cluster-scoped object named `cluster`.
3. If the read fails, return `false` and the error. Do not treat a read error
   as "disabled"; that hides RBAC and API problems.
4. Loop over `fg.Status.FeatureGates`, which is grouped by payload version.
5. Within each version, loop over `Enabled`.
6. Compare `enabled.Name` to `"TLSGroupPreferences"`.
7. Return `true` on the first match.
8. Return `false` after all loops.

The gate is required only for writing a Custom profile with explicit `groups`.
Reading the built-in profiles already works. Even when the gate appears
enabled, re-read the `APIServer` after an update and verify the groups
persisted; some APIs silently drop gated fields instead of rejecting them.

How to test:

- Fake client with a `FeatureGate` containing the enabled entry; expect true.
- Fake client without the entry; expect false.
- Fake client without the object; expect an error, not false.
- E2E: call before mutating; `Skip` with a clear message if false.

#### `waitForMCPConditionWithRetry`

```go
func waitForMCPConditionWithRetry(ctx context.Context, mcp *machineconfigv1.MachineConfigPool, condType machineconfigv1.MachineConfigPoolConditionType, timeout, interval time.Duration) error
```

Location: `test/e2e/serial/tests/configuration.go`.

Line by line:

1. It computes `deadline := time.Now().Add(timeout)`.
2. It declares `lastErr`.
3. It starts an infinite loop.
4. It computes `remaining := time.Until(deadline)`.
5. If remaining is zero or negative, it returns a timeout error. If a previous
   transient error exists, it wraps that error so the log shows the last
   cause.
6. It calls `wait.With(e2eclient.Client).Timeout(remaining).Interval(interval).ForMachineConfigPoolCondition(ctx, mcp, condType)`.
7. If that returns nil, the condition was observed and it returns nil.
8. If the error is not transient, it returns it immediately.
9. Otherwise it saves the error as `lastErr` and logs it.
10. It waits for either context cancellation or `interval`.
11. If the context is cancelled, it returns `ctx.Err()`.
12. Otherwise it loops and tries again with the remaining deadline.

Why the wrapper is necessary: during a rollout, the API server may return
timeouts or stream errors. Retrying transient transport errors prevents a
healthy rollout from failing the test. Real errors, such as a missing MCP or a
forbidden request, are returned immediately.

How to test:

- Unit-test `isTransientMCPError` separately.
- E2E is the practical test for this function; a fake poll loop would duplicate
  the Kubernetes wait package.
- In a serial spec, always pass a bounded timeout shorter than the Ginkgo
  timeout, and always use it in cleanup too.

Known limitation: `ForMachineConfigPoolCondition` ignores the MCP if its
resource version has not changed from the supplied object. If a rollout starts
and finishes between two observations, the `Updating` wait can time out even
though the rollout succeeded. When adding a new serial test, consider
refreshing the MCP before the `Updating` wait or treating
`Updated`-already-true as success. Do not change existing test 88383 behavior
unless the team agrees.

#### `isTransientMCPError`

```go
func isTransientMCPError(err error) bool
```

Line by line:

1. It declares a `*url.Error`.
2. If `errors.As` finds one, it returns true. URL errors cover transport-level
   failures.
3. It returns true for Kubernetes API timeout, server timeout, and service
   unavailable errors.
4. It returns true if the error text contains `stream error` or
   `INTERNAL_ERROR`; those are API transport hiccups seen during control-plane
   churn.
5. Otherwise it returns false.

How to test: pure table with each category plus a plain validation error that
must return false. This is deterministic and cheap.

#### `verifyNodesMatchMCPConfig`

```go
func verifyNodesMatchMCPConfig(ctx context.Context, mcp *machineconfigv1.MachineConfigPool) error
```

Line by line:

1. Allocate an empty `MachineConfigPool`.
2. Re-read the MCP by its object key into `updatedMCP`.
3. If the read fails, return a wrapped error.
4. Read `renderedConfig := updatedMCP.Status.Configuration.Name`.
5. If it is empty, return an error. An empty rendered config means the MCP has
   not produced a configuration yet.
6. If `updatedMCP.Spec.NodeSelector` is nil, return an error.
7. Allocate an empty `NodeList`.
8. List nodes matching `updatedMCP.Spec.NodeSelector.MatchLabels`.
9. If listing fails, return a wrapped error.
10. Loop over every node.
11. Read the `machineconfiguration.openshift.io/currentConfig` annotation.
12. If it differs from `renderedConfig`, return an error naming the node, its
    current config, the MCP, and the expected config.
13. If all nodes match, log the MCP, config, and node count.
14. Return nil.

Why this is stronger than `Updated=True`: the MCP condition is cluster-level.
This check proves every selected node actually reports the rendered config.

How to test: serial E2E only. A fake test can cover the empty-config and
missing-selector errors, but real node annotations require a cluster.

#### Serial-test closures

The serial example uses four closures. They are not package functions, but a
new contributor will spend most of their debugging time inside them.

**`updateProfile(ctx, profile)`**

Line by line:

1. Start an `Eventually` block because `APIServer` updates conflict under
   concurrent controllers.
2. Re-read the latest `APIServer` inside the retry block.
3. Assign only `current.Spec.TLSSecurityProfile`; this preserves unrelated
   spec fields written by other controllers.
4. Call `Update`.
5. Retry the read-modify-write until it succeeds or the 10-minute timeout
   expires.

Never call `Update` on the stale object captured before the test started. That
causes a resource-version conflict and can overwrite another controller's
change.

**`waitForMCPsAndVerifyNodes(ctx, reason)`**

Line by line:

1. List all MachineConfigPools.
2. Start an `errgroup.Group` so MCPs are waited on concurrently.
3. For each MCP, capture the item by index.
4. In the goroutine, wait for `MachineConfigPoolUpdating=True`, then
   `MachineConfigPoolUpdated=True`.
5. Wait for all goroutines and fail if any returns an error.
6. Re-read each MCP and verify every selected node's `currentConfig`
   annotation matches the rendered config.

The `reason` string is only for log clarity, such as "after restricted groups"
or "after rollback". Keeping it makes a timeout report understandable.

**`restore(ctx)`**

Line by line:

1. Use `Eventually` to retry the read-modify-write of the saved original spec.
2. Assign the saved `*APIServerSpec` wholesale.
3. Update the object.
4. Call `waitForMCPsAndVerifyNodes` for the rollback.

This closure is registered with `DeferCleanup` before the first mutation. It
must be safe to run when the spec failed halfway through, so it should not
depend on variables that are only set later.

**`expectOperands(g Gomega, expected)`**

Line by line:

1. Assert the RTE helper succeeds.
2. Read `NUMAResourcesScheduler`.
3. If it is not found, return from the assertion closure; the scheduler is
   optional.
4. Fail on any other read error.
5. Assert the scheduler helper succeeds.

Using `Gomega` (the `g` parameter) inside `Eventually` lets the whole pair be
retried as one unit. Using the global `Expect` would abort on the first
transient mismatch instead of retrying.

### 4.8 Test suite plumbing functions

#### `getRTEPodsFromNRO`

```go
func getRTEPodsFromNRO(ctx context.Context) []corev1.Pod
```

Location: `test/e2e/tls/tls_test.go`.

Line by line:

1. `GinkgoHelper()` marks the function as a helper so failures point at the
   caller.
2. Allocate `&nropv1.NUMAResourcesOperator{}`.
3. Build the key from `objectnames.DefaultNUMAResourcesOperatorCrName`.
4. `Get` the object; fail the spec immediately if it cannot be read.
5. Require at least one node group in status.
6. Allocate an empty `rtePods` slice.
7. Loop over every `nodeGroup`.
8. Allocate an empty DaemonSet.
9. Build the key from `nodeGroup.DaemonSet.Namespace/Name`.
10. `Get` the DaemonSet; fail on error.
11. Call `podlist.With(e2eclient.Client).ByDaemonset(ctx, *daemonSet)`.
12. Fail on list error.
13. Require at least one pod for that DaemonSet.
14. Append all pods to the result.
15. After all groups, require a non-empty result and return it.

This is the discovery pattern for RTE tests. It is already used by tests
88381 and 88382. New curve specs should reuse it rather than reimplementing
node-group traversal.

#### `e2eclient.Client` and `e2eclient.K8sClient`

These are package variables, not functions, but a new contributor must know
the difference:

- `Client` is a controller-runtime client. It works with typed OpenShift and
  NROP objects and is used for `Get`, `List`, `Update`, and fake-client
  tests.
- `K8sClient` is a client-go `kubernetes.Interface`. It is required by
  `remoteexec` and the `intls.Probe*` helpers.

If a probe call fails to compile with "cannot use Client as
kubernetes.Interface", you passed the wrong client.

#### `Eventually`, `By`, and `GinkgoHelper`

- `Eventually(func() error { ... }).WithTimeout(...).WithPolling(...)` retries
  an assertion. Use it for anything the operator writes asynchronously:
  DaemonSet args, Deployment args, and status.
- `Eventually(func(g Gomega) { ... })` lets you make multiple assertions in one
  retried block. If one `g.Expect` fails, the block retries from the start.
- `By("...")` writes a progress step into the Ginkgo report. Use it before
  each stage of a multi-step spec.
- `GinkgoHelper()` makes helper assertion failures point at the caller. Add it
  to every helper that calls `Expect` or `Fail`.

#### `DeferCleanup`

`DeferCleanup` registers cleanup that runs even when the spec fails. In a
serial TLS test it must restore the original `APIServer` profile and wait for
the rollout. Register it **immediately after saving the original profile and
before mutating anything**. That ordering is the difference between a failed
test and a contaminated cluster.

### 4.9 Operator metrics endpoint layer

The operator has a third TLS surface in addition to RTE and the scheduler:
its own metrics endpoint on port `8080`. It is different from the operands:

- There is no `--tls-curve-preferences` operand flag to inspect.
- `cmd/main.go` passes the same `tlsConfig` callback to
  `metricsserver.Options{SecureServing: true, CertDir: "/certs",
  TLSOpts: []func(*tls.Config){tlsConfig}}`.
- The callback sets `MinVersion`, `CipherSuites`, and `CurvePreferences` on the
  controller-runtime metrics server.
- Therefore the only way to prove operator curve enforcement is to open a real
  TLS connection to port `8080` and inspect `ConnectionState.CurveID`.

The admission webhook on `9443` is intentionally out of scope for this work:
it is disabled by default in the shipped OLM bundle and is not an exposed
user-facing endpoint. Do not add webhook curve tests to the standard TLS
suite.

#### `deploy.FindNUMAResourcesOperatorPod`

```go
func FindNUMAResourcesOperatorPod(ctx context.Context, cli client.Client, nrop *nropv1.NUMAResourcesOperator) (*corev1.Pod, error)
```

Location: `test/internal/deploy/find.go`.

Line by line:

1. It requires `nrop.Status.DaemonSets` to contain at least one entry. NROP
   places its own Deployment and the RTE DaemonSets in the same namespace, so
   the first DaemonSet namespace is used as the operator namespace.
2. It logs that namespace.
3. It builds a selector for the label `app=numaresources-operator`.
4. It converts the selector with `metav1.LabelSelectorAsSelector`.
5. It lists Pods in the namespace with that selector.
6. It requires exactly one Pod. More than one usually means a rollout is in
   progress or an old ReplicaSet has not terminated.
7. It returns the Pod.

Failure modes:

- `node groups not reported` means the NRO status is not ready.
- `unexpected number of pods found` during a rollout is transient; wrap the
  discovery in `Eventually` in E2E.
- The manager Pod may not yet be Ready; `ProbeTLSState` will fail with a
  connection error if the server is still starting.

How to test: E2E through test 85769 or a new curve spec. A fake-client test can
cover the missing-status and wrong-pod-count branches.

#### `remoteexec.CommandOnPod`

```go
func CommandOnPod(ctx context.Context, c kubernetes.Interface, pod *corev1.Pod, command ...string) ([]byte, []byte, error)
```

Line by line:

1. It delegates to `CommandOnPodByNames`.
2. It uses the Pod namespace and name.
3. It uses `pod.Spec.Containers[0].Name` as the target container.
4. It passes the command variadic unchanged.
5. It returns stdout, stderr, and error.

It assumes the first container is the one with the tool you need. For the
manager Pod, that is the operator container with `curl` available in the test
image.

#### `remoteexec.CommandOnPodByNames`

```go
func CommandOnPodByNames(ctx context.Context, c kubernetes.Interface, podNamespace, podName, cntName string, command ...string) ([]byte, []byte, error)
```

Line by line:

1. It creates two `bytes.Buffer` values for stdout and stderr.
2. It builds a POST request against the Pod `exec` subresource.
3. It sets `PodExecOptions` with the container, command, stdin, stdout,
   stderr, and TTY enabled.
4. It reads the REST config with `config.GetConfig()`.
5. It creates an SPDY executor for the request URL.
6. It streams the command with `StreamWithContext`.
7. It wires `os.Stdin` and the two output buffers.
8. If streaming fails, it returns a wrapped `failed to run command` error.
9. Otherwise it returns stdout, stderr, and nil.

This helper is useful for a quick availability check but is not a TLS policy
probe: it shells out to `curl -k`, which discards the negotiated curve and does
not expose `ConnectionState`.

How to test: E2E only. A missing `curl` in the image is the most common
failure; if the command exits non-zero, inspect stderr before changing the
assertion.

#### `fetchMetricsFromPod`

```go
func fetchMetricsFromPod(ctx context.Context, pod *corev1.Pod, metricsAddress, metricsPort string) string
```

Location: `test/e2e/serial/tests/metrics.go`.

Line by line:

1. It calls `GinkgoHelper()` so failures point at the caller.
2. It joins the address and port with `net.JoinHostPort`.
3. It builds the Pod object key for logging.
4. It logs a `By` step.
5. It constructs `/bin/curl -k https://<address>:<port>/metrics`.
6. It logs the command at verbosity 2.
7. It runs the command with `remoteexec.CommandOnPod`.
8. It fails the test if the exec fails and includes stderr.
9. It fails if stdout is empty.
10. It returns stdout as a string.

This is the helper used by test 85769. It proves that the operator's HTTPS
metrics endpoint serves metrics. It does not assert the profile's minimum
version, cipher, or curve.

#### Existing operator metrics tests

`[test_id:85769]` in `test/e2e/serial/tests/metrics.go`:

1. Finds the manager Pod with `FindNUMAResourcesOperatorPod`.
2. Calls `fetchMetricsFromPod` against `127.0.0.1:8080`.
3. Asserts the body contains operator and scheduler `workqueue_adds_total`
   metrics.

It is a serial `feature:metrics` test, not a `feature:tlscompliance` test. It
is the right baseline for availability but not for curve policy.

`[test_id:85770]` does the same for an RTE Pod on port `2112` and asserts RTE
metric names. The dedicated RTE TLS tests 88381/88382 are stricter and should
be extended for curves; 85770 remains a lightweight metrics availability check.

#### Operator curve probes

Reuse the same probes as RTE and the scheduler:

```go
nropObj := &nropv1.NUMAResourcesOperator{}
Expect(e2eclient.Client.Get(ctx, objects.NROObjectKey(), nropObj)).To(Succeed())
operatorPod, err := deploy.FindNUMAResourcesOperatorPod(ctx, e2eclient.Client, nropObj)
Expect(err).ToNot(HaveOccurred())

state, err := intls.ProbeTLSState(e2eclient.K8sClient, operatorPod, "8080")
Expect(err).ToNot(HaveOccurred())
Expect(allowed).To(ContainElement(state.CurveID))
```

And for the negative case:

```go
err := intls.ProbeTLSCurve(e2eclient.K8sClient, operatorPod, "8080", disallowed)
Expect(err).To(HaveOccurred())
Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue())
```

Because the operator is a single Pod, a positive test probes one endpoint, not
one per node. A negative test is still valuable because it proves the same
controller-runtime-common callback is enforced by the operator process.

---

## 5. Test strategy: how to test every function

### 5.1 Decision tree

Use the cheapest level that can fail for the reason you care about:

```text
Is the code a pure conversion or comparison?
  yes -> package unit test
  no  -> does it read Kubernetes objects with a client?
           yes -> fake-client test in test/internal/tls
           no  -> is it a reconcile path?
                    yes -> controller test with envtest
                    no  -> does it need a live pod port?
                             yes -> non-disruptive E2E
                             no  -> serial E2E for profile transitions
```

Do not write an E2E test to check a comma-joining function. Do not write a unit
test to prove that a real scheduler enforces a curve. The first is slow and
flaky; the second cannot see the server.

### 5.2 Unit-test setup

Most helper tests live in `test/internal/tls/tls_test.go` with `package tls`.
That package name allows access to unexported functions such as `matchTLSFlag`,
`tlsHandshake`, and `tlsConfigFromProfileSpec`.

Minimal fake-client setup:

```go
import (
	"context"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nropv1 "github.com/openshift-kni/numaresources-operator/api/v1"
)

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	utilruntime.Must(nropv1.AddToScheme(scheme.Scheme))
	utilruntime.Must(configv1.AddToScheme(scheme.Scheme))
	return fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(objs...).
		Build()
}
```

Notes for a new contributor:

- `AddToScheme` registers Go types so the fake client knows how to store them.
  Without it, you get "no kind is registered".
- `scheme.Scheme` is a global. Registering the same type twice is safe because
  `AddToScheme` is idempotent in practice, but keep registration in `init()` or
  a helper.
- `fake.NewClientBuilder().WithObjects(...)` copies objects into an in-memory
  store.
- Fake clients do not run controllers. If you need owner-reference discovery,
  create the owner UID explicitly.

### 5.3 Function-to-test matrix

| Function | Assertion | Level | Example |
|---|---|---|---|
| `FetchAPIServerTLSProfile` | nil/Old/Modern/Custom resolution | fake client | create APIServer |
| `GetTLSProfileSpec` | default, named, custom, nil custom | pure unit | table |
| `TLSGroupToCurveID` | all seven mappings + unknown | pure unit | table |
| `TLSGroupsToCurveIDs` | order, duplicates, unknown filtered | pure unit | table |
| `ValidTLSGroups` | sorted and complete | pure unit | `slices.IsSorted` |
| `NewTLSConfigFromProfile` | min, ciphers, curves, unsupported | pure unit | table |
| `NewSettings` | CSV for each group family | pure unit | table |
| `curveIDsToString` | empty, one, many | pure unit | direct |
| `Settings.String` | with/without curves | pure unit | table |
| `DaemonSetArgs` | set/replace/delete curve flag | pure unit | fake DaemonSet |
| `DeploymentTLSSettings` | set/replace/delete curve flag | pure unit | fake Deployment |
| `ParseArgvKeyValue` | option/toggle/two `=` values | pure unit | table |
| `SetOption`/`Delete`/`GetFlag` | idempotency and absence | pure unit | table |
| `FindContainerByName` | first/middle/last/missing | pure unit | table |
| `matchTLSFlag` | five expected/live combinations | pure unit | table |
| `CheckRTEDaemonSetTLSFlags` | all node groups, curves | fake client | table |
| `CheckSchedulerDeploymentTLSFlags` | NROS status Deployment + curves | fake client | table |
| `GetClusterTLSProfile` | version and groups preserved | fake client | APIServer |
| `TLSVersionBelow` | mapping and errors | pure unit | table |
| `wrapTLSHandshakeError` | alert/server/client/other | pure unit | table |
| `OpenSSLCipherToGoID` | known/unknown | pure unit | table |
| `FindDisallowedCipher` | old/intermediate/nil | pure unit | table |
| `FindDisallowedCurve` | deterministic outside curve | pure unit | table |
| `tlsHandshake` | local TLS server curve | unit | `httptest` |
| `Probe*` | real pod port and policy | E2E | port-forward |
| `FindNUMAResourcesOperatorPod` | status guard, selector, pod count | fake client, E2E | fake NRO + Pods |
| `CommandOnPod` / `CommandOnPodByNames` | exec plumbing and error paths | E2E | 85769 availability |
| `fetchMetricsFromPod` | HTTPS body contains metrics | E2E | 85769 |
| Operator metrics curve probe | negotiate allowed curve on `8080` | E2E | `ProbeTLSState` |
| Operator metrics negative probe | reject outside curve on `8080` | E2E | `ProbeTLSCurve` |
| `FetchMetrics` | HTTP 200 and metric name | E2E | RTE 88381 |
| `waitForMCPConditionWithRetry` | rollout wait/retry | serial E2E | 88383 pattern |
| `isTransientMCPError` | categories | pure unit | table |
| `verifyNodesMatchMCPConfig` | per-node annotation | serial E2E | 88383 pattern |

### 5.4 Unit test: the whole conversion pipeline

This single test catches mapping, config, and formatting regressions together:

```go
func TestCurvePipeline(t *testing.T) {
	profile := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
		Groups: []configv1.TLSGroup{
			configv1.TLSGroupX25519MLKEM768,
			configv1.TLSGroupX25519,
			configv1.TLSGroupSecP256r1,
			configv1.TLSGroupSecP384r1,
		},
	}

	apply, unsupported := ctrltls.NewTLSConfigFromProfile(profile)
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported values: %v", unsupported)
	}
	cfg := &cryptotls.Config{}
	apply(cfg)

	settings := objtls.NewSettings(cfg)
	if settings.CurvePreferences != "4588,29,23,24" {
		t.Fatalf("curve CSV = %q", settings.CurvePreferences)
	}
}
```

Add a second case with `Groups: nil` and assert
`settings.CurvePreferences == ""`. That is the delete-on-empty contract.

### 5.5 Unit test: `matchTLSFlag`

```go
func TestMatchTLSFlag(t *testing.T) {
	const flag = "--metrics-tls-curve-preferences"
	tests := []struct {
		name     string
		args     []string
		expected string
		wantErr  bool
	}{
		{name: "absent when empty", args: nil, expected: "", wantErr: false},
		{name: "empty value when empty", args: []string{flag + "="}, expected: "", wantErr: false},
		{name: "stale value when empty", args: []string{flag + "=29,23"}, expected: "", wantErr: true},
		{name: "matching value", args: []string{flag + "=29,23"}, expected: "29,23", wantErr: false},
		{name: "wrong order", args: []string{flag + "=23,29"}, expected: "29,23", wantErr: true},
		{name: "missing non-empty", args: nil, expected: "29,23", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := flagcodec.ParseArgvKeyValue(tt.args, flagcodec.WithFlagNormalization)
			err := matchTLSFlag(flags, flag, tt.expected, "test-object")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
```

### 5.6 Unit test: RTE helper curve cases

The existing tests now cover the curve-match and stale-when-empty cases. Use
these additional cases as hardening references:

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
			"--metrics-tls-curve-preferences=4588,29,23,24",
		),
	},
	expectedTLSSettings: objtls.Settings{
		MinVersion:       "VersionTLS12",
		CipherSuites:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		CurvePreferences: "4588,29,23,24",
	},
	expectedError: "",
},
{
	name: "stale curve when expected empty",
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
		MinVersion:   "VersionTLS12",
		CipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	},
	expectedError: "should be absent or empty",
},
```

The table now also has a multi-node-group case where the second DaemonSet has
a wrong curve list. The expected error proves the helper does not stop after the
first match.

### 5.7 Unit test: scheduler helper

```go
func TestCheckSchedulerDeploymentTLSFlags(t *testing.T) {
	const uid = types.UID("sched-uid")
	nros := &nropv1.NUMAResourcesScheduler{
		ObjectMeta: metav1.ObjectMeta{
			Name: objectnames.DefaultNUMAResourcesSchedulerCrName,
			UID:  uid,
		},
	}
	dp := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "secondary-scheduler",
			OwnerReferences: []metav1.OwnerReference{
				{UID: uid},
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "sched"}},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: schedupdate.MainContainerName,
						Args: []string{
							"--tls-min-version=VersionTLS12",
							"--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
							"--tls-curve-preferences=29,23",
						},
					}},
				},
			},
		},
	}
	cli := newFakeClient(t, nros, dp)
	err := CheckSchedulerDeploymentTLSFlags(context.Background(), cli, objtls.Settings{
		MinVersion:       "VersionTLS12",
		CipherSuites:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		CurvePreferences: "29,23",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

The matching cron job is not required by this test, but when creating objects
through the API, UIDs must be set for owner-reference discovery.

### 5.8 Unit test: local TLS handshake and curve

`tlsHandshake` is unexported, so this test must be in `package tls`:

```go
func TestTLSHandshakeNegotiatesCurve(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &cryptotls.Config{
		MinVersion:       cryptotls.VersionTLS12,
		CurvePreferences: []cryptotls.CurveID{cryptotls.CurveP256},
	}
	srv.StartTLS()
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	state, err := tlsHandshake(conn, &cryptotls.Config{
		InsecureSkipVerify: true,
		CurvePreferences:   []cryptotls.CurveID{cryptotls.CurveP256},
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if state.CurveID != cryptotls.CurveP256 {
		t.Fatalf("curve = %v, want P-256", state.CurveID)
	}
}
```

This does not test `PortForwardToPod`; it tests the TLS/business logic in
isolation. The port-forward path is covered by the E2E specs.

### 5.9 Unit test: transient MCP errors

```go
func TestIsTransientMCPError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "url error", err: &url.Error{Op: "get", URL: "https://api", Err: errors.New("boom")}, want: true},
		{name: "service unavailable", err: apierrors.NewServiceUnavailable("busy"), want: true},
		{name: "server timeout", err: apierrors.NewServerTimeout(schema.GroupResource{}, "get", 1), want: true},
		{name: "stream error", err: errors.New("stream error: INTERNAL_ERROR"), want: true},
		{name: "validation", err: errors.New("invalid configuration"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientMCPError(tt.err); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
```

### 5.10 Running tests while you work

```bash
# Pure conversions and flag codec
go test ./pkg/objectupdate/tls/... ./pkg/objectupdate/rte/... ./pkg/objectupdate/sched/...

# Helper package, including fake-client tests
go test ./test/internal/tls/...

# Controller reconciliation
make test-controllers

# Build and run non-disruptive TLS
make build-e2e-tls
bin/e2e-nrop-tls.test --ginkgo.v --ginkgo.label-filter='feature:tlscompliance'

# Serial, only on an exclusive cluster
make binary-e2e-serial
bin/e2e-nrop-serial.test --ginkgo.v --ginkgo.focus='TLS curve'
```

Test order matters. If a pure unit test fails, do not run E2E; fix the
conversion first.

---

## 6. Automation cookbook

The code in this section is a complete implementation outline. It is written
to be copied into the named files and adapted to the surrounding imports and
style. It deliberately does not implement production changes; production
already writes the curve flags.

### 6.1 Helper changes in `test/internal/tls/tls.go`

#### Step 1: assert the RTE curve flag (already present)

`CheckRTEDaemonSetTLSFlags` already contains this check after the cipher check:

```go
if err := matchTLSFlag(rteFlags, "--metrics-tls-curve-preferences", expected.CurvePreferences, ds.Name); err != nil {
	return err
}
```

Keep this block in mind when reviewing the file; no change to `matchTLSFlag`
is needed. Its empty-value semantics already match
delete-on-empty.

#### Step 2: verify the existing scheduler argument helper

Add to `test/internal/tls/tls.go`:

```go
func CheckSchedulerDeploymentTLSFlags(ctx context.Context, cli client.Client, expected objtls.Settings) error {
	nroSchedObj := &nropv1.NUMAResourcesScheduler{}
	nroSchedKey := client.ObjectKey{Name: objectnames.DefaultNUMAResourcesSchedulerCrName}
	if err := cli.Get(ctx, nroSchedKey, nroSchedObj); err != nil {
		return fmt.Errorf("failed to get NUMAResourcesScheduler %q: %w", nroSchedKey.Name, err)
	}

	deployment, err := podlist.With(cli).DeploymentByOwnerReference(ctx, nroSchedObj.GetUID())
	if err != nil {
		return fmt.Errorf("failed to get scheduler deployment: %w", err)
	}
	if deployment == nil {
		return fmt.Errorf("scheduler deployment not found for %q", nroSchedKey.Name)
	}

	container := k8swgobjupdate.FindContainerByName(
		deployment.Spec.Template.Spec.Containers, schedupdate.MainContainerName)
	if container == nil {
		return fmt.Errorf("scheduler container %q not found in deployment %q",
			schedupdate.MainContainerName, deployment.Name)
	}

	flags := flagcodec.ParseArgvKeyValue(container.Args, flagcodec.WithFlagNormalization)
	if flags == nil {
		return fmt.Errorf("cannot parse scheduler args for deployment %q", deployment.Name)
	}
	if err := matchTLSFlag(flags, "--tls-min-version", expected.MinVersion, deployment.Name); err != nil {
		return err
	}
	if err := matchTLSFlag(flags, "--tls-cipher-suites", expected.CipherSuites, deployment.Name); err != nil {
		return err
	}
	if err := matchTLSFlag(flags, "--tls-curve-preferences", expected.CurvePreferences, deployment.Name); err != nil {
		return err
	}
	return nil
}
```

Add imports if they are missing:

```go
import (
	"github.com/openshift-kni/numaresources-operator/internal/podlist"
	schedupdate "github.com/openshift-kni/numaresources-operator/pkg/objectupdate/sched"
)
```

`objectnames`, `flagcodec`, `k8swgobjupdate`, `nropv1`, `objtls`, and `client`
are already imported by the file.

#### Step 3: add state and single-curve probes

Add:

```go
func ProbeTLSState(cli kubernetes.Interface, pod *corev1.Pod, podPort string) (*tls.ConnectionState, error) {
	var state *tls.ConnectionState
	err := remoteexec.PortForwardToPod(cli, pod, podPort, func(conn net.Conn) error {
		var err error
		state, err = tlsHandshake(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		return err
	})
	return state, err
}

func ProbeTLSCurve(cli kubernetes.Interface, pod *corev1.Pod, podPort string, curveID tls.CurveID) error {
	return remoteexec.PortForwardToPod(cli, pod, podPort, func(conn net.Conn) error {
		_, err := tlsHandshake(conn, &tls.Config{
			InsecureSkipVerify: true,
			CurvePreferences:   []tls.CurveID{curveID},
		})
		return wrapTLSHandshakeError(err)
	})
}
```

#### Step 4: add curve selection helpers

```go
func FindDisallowedCurve(allowed []tls.CurveID) (tls.CurveID, error) {
	allowedSet := make(map[tls.CurveID]bool, len(allowed))
	for _, id := range allowed {
		allowedSet[id] = true
	}
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

func CurveIDsFromProfile(profileSpec configv1.TLSProfileSpec) []tls.CurveID {
	ids, _ := libgocrypto.TLSGroupsToCurveIDs(profileSpec.Groups)
	return ids
}
```

`libgocrypto` and `configv1` are already imported. `tls` here is
`crypto/tls`.

#### Step 5: add the feature-gate helper for serial tests

Add this to the serial test file:

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

It is needed only in the serial suite, before writing a Custom profile with an
explicit `groups` list.

#### Step 6: optionally refactor `ProbeTLSSettings`

Keep the existing signature to avoid touching callers:

```go
func ProbeTLSSettings(cli kubernetes.Interface, pod *corev1.Pod, podPort string) (uint16, uint16, error) {
	state, err := ProbeTLSState(cli, pod, podPort)
	if err != nil {
		return 0, 0, err
	}
	return state.Version, state.CipherSuite, nil
}
```

This is optional. The minimal patch is to leave `ProbeTLSSettings` unchanged
and use `ProbeTLSState` only in new specs.

### 6.2 Unit test additions in `test/internal/tls/tls_test.go`

Add the `matchTLSFlag` table from Section 5.5, the RTE curve cases from
Section 5.6, and the scheduler helper test from Section 5.7.

For the RTE cases, make sure the expected error substrings match the actual
messages:

- stale curve with empty expectation: `"should be absent or empty"`
- curve value mismatch: `"mismatch"`
- missing non-empty curve: `"mismatch"`

Run:

```bash
go test ./test/internal/tls/... -run 'TestMatchTLSFlag|TestCheckRTEDaemonSetTLSFlags|TestCheckSchedulerDeploymentTLSFlags' -v
```

### 6.3 Non-disruptive E2E: argument propagation

Add these specs to `test/e2e/tls/tls_test.go`. Keep them separate so a failure
identifies the operand.

#### RTE argument propagation

```go
It("[test_id:TBD] should align RTE TLS curve arguments with the cluster profile",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		expected, err := intls.RTESettingsFromClusterProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred(), "failed to derive expected TLS settings")

		Eventually(func(g Gomega) {
			g.Expect(intls.CheckRTEDaemonSetTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())
	})
```

This asserts the exact CSV and, because `expected.CurvePreferences` is empty
for a no-group profile, also asserts flag removal.

#### Scheduler argument propagation

```go
It("[test_id:TBD] should align scheduler TLS curve arguments with the cluster profile",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		nroSched := &nropv1.NUMAResourcesScheduler{}
		err := e2eclient.Client.Get(ctx, objects.NROSchedObjectKey(), nroSched)
		if apierrors.IsNotFound(err) {
			Skip("NUMAResourcesScheduler is not deployed in this cluster")
		}
		Expect(err).ToNot(HaveOccurred())

		expected, err := intls.RTESettingsFromClusterProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func(g Gomega) {
			g.Expect(intls.CheckSchedulerDeploymentTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())
	})
```

The skip is honest: a cluster without the optional scheduler cannot test its
Deployment. Do not silently pass the spec.

### 6.4 Non-disruptive E2E: positive handshake

#### Scheduler positive curve

```go
It("[test_id:TBD] should negotiate a curve allowed by the cluster profile on the scheduler",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		allowed := intls.CurveIDsFromProfile(profileSpec)
		if len(allowed) == 0 {
			Skip("profile defines no groups; Go defaults are intentionally used")
		}

		nroSched := &nropv1.NUMAResourcesScheduler{}
		err = e2eclient.Client.Get(ctx, objects.NROSchedObjectKey(), nroSched)
		if apierrors.IsNotFound(err) {
			Skip("NUMAResourcesScheduler is not deployed in this cluster")
		}
		Expect(err).ToNot(HaveOccurred())

		deployment, err := podlist.With(e2eclient.Client).DeploymentByOwnerReference(ctx, nroSched.GetUID())
		Expect(err).ToNot(HaveOccurred())
		Expect(deployment).ToNot(BeNil())

		pods, err := podlist.With(e2eclient.Client).ByDeployment(ctx, *deployment)
		Expect(err).ToNot(HaveOccurred())
		Expect(pods).ToNot(BeEmpty())

		var pod *corev1.Pod
		for i := range pods {
			if pods[i].DeletionTimestamp == nil && pods[i].Status.Phase == corev1.PodRunning {
				pod = &pods[i]
				break
			}
		}
		Expect(pod).ToNot(BeNil(), "no running scheduler pod")

		state, err := intls.ProbeTLSState(e2eclient.K8sClient, pod, schedulerSecurePort)
		Expect(err).ToNot(HaveOccurred())
		if state.CurveID == 0 {
			Skip("legacy RSA key exchange selected; no curve was negotiated")
		}
		klog.InfoS("negotiated curve", "curve", state.CurveID.String(), "id", uint16(state.CurveID))
		Expect(allowed).To(ContainElement(state.CurveID),
			"negotiated curve %v is not allowed by groups %v", state.CurveID, profileSpec.Groups)
	})
```

#### RTE positive curve

```go
It("[test_id:TBD] should negotiate a curve allowed by the cluster profile on every RTE pod",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		allowed := intls.CurveIDsFromProfile(profileSpec)
		if len(allowed) == 0 {
			Skip("profile defines no groups; Go defaults are intentionally used")
		}

		const rteMetricsPort = "2112"
		probed := 0
		rtePods := getRTEPodsFromNRO(ctx)
		for i := range rtePods {
			pod := rtePods[i]
			state, err := intls.ProbeTLSState(e2eclient.K8sClient, &pod, rteMetricsPort)
			Expect(err).ToNot(HaveOccurred(), "pod %q", pod.Name)
			if state.CurveID == 0 {
				klog.InfoS("no curve negotiated", "pod", pod.Name)
				continue
			}
			probed++
			Expect(allowed).To(ContainElement(state.CurveID),
				"pod %q negotiated disallowed curve %v", pod.Name, state.CurveID)
		}
		if probed == 0 {
			Skip("no RTE pod negotiated a curve; all used a non-curve key exchange")
		}
	})
```

Call `getRTEPodsFromNRO(ctx)` once and reuse the slice; it performs several
API reads and a repeated call inside a loop is both slow and inconsistent.

### 6.5 Non-disruptive E2E: negative handshake

#### Scheduler rejects a disallowed curve

```go
It("[test_id:TBD] should reject a curve disallowed by the cluster profile on the scheduler",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		allowed := intls.CurveIDsFromProfile(profileSpec)
		if len(allowed) == 0 {
			Skip("profile defines no groups; Go defaults are intentionally used")
		}
		disallowed, err := intls.FindDisallowedCurve(allowed)
		if err != nil {
			Skip(err.Error())
		}

		nroSched := &nropv1.NUMAResourcesScheduler{}
		err = e2eclient.Client.Get(ctx, objects.NROSchedObjectKey(), nroSched)
		if apierrors.IsNotFound(err) {
			Skip("NUMAResourcesScheduler is not deployed in this cluster")
		}
		Expect(err).ToNot(HaveOccurred())

		deployment, err := podlist.With(e2eclient.Client).DeploymentByOwnerReference(ctx, nroSched.GetUID())
		Expect(err).ToNot(HaveOccurred())
		pods, err := podlist.With(e2eclient.Client).ByDeployment(ctx, *deployment)
		Expect(err).ToNot(HaveOccurred())
		Expect(pods).ToNot(BeEmpty())

		err = intls.ProbeTLSCurve(e2eclient.K8sClient, &pods[0], schedulerSecurePort, disallowed)
		Expect(err).To(HaveOccurred(), "scheduler accepted disallowed curve %v", disallowed)
		Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(),
			"expected TLS rejection, got %v", err)
	})
```

#### RTE rejects a disallowed curve

```go
It("[test_id:TBD] should reject a curve disallowed by the cluster profile on every RTE pod",
	Label(label.Tier0, "feature:tlscompliance"), func(ctx context.Context) {
		_, profileSpec, err := intls.GetClusterTLSProfile(ctx, e2eclient.Client)
		Expect(err).ToNot(HaveOccurred())

		allowed := intls.CurveIDsFromProfile(profileSpec)
		if len(allowed) == 0 {
			Skip("profile defines no groups; Go defaults are intentionally used")
		}
		disallowed, err := intls.FindDisallowedCurve(allowed)
		if err != nil {
			Skip(err.Error())
		}

		const rteMetricsPort = "2112"
		rtePods := getRTEPodsFromNRO(ctx)
		for i := range rtePods {
			pod := &rtePods[i]
			err := intls.ProbeTLSCurve(e2eclient.K8sClient, pod, rteMetricsPort, disallowed)
			Expect(err).To(HaveOccurred(), "pod %q accepted disallowed curve %v", pod.Name, disallowed)
			Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(),
				"pod %q: expected TLS rejection, got %v", pod.Name, err)
		}
	})
```

For the built-in profiles, `FindDisallowedCurve` normally returns P-521
(25). The profiles allow `4588,29,23,24`, so P-521 is outside the set.

### 6.6 Non-disruptive E2E: operator metrics curve probes

The operator metrics endpoint has no curve flag to assert. Add these two specs
next to the RTE and scheduler specs in `test/e2e/tls/tls_test.go`. They prove
that the `tlsConfig` callback in `cmd/main.go` is enforced by the live
controller-runtime metrics server on port `8080`.

Both specs reuse discovery and probes you already need for the operands, so no
new helper is required:

- `deploy.FindNUMAResourcesOperatorPod` finds the single manager Pod.
- `intls.ProbeTLSState` reports the negotiated `CurveID`.
- `intls.ProbeTLSCurve` offers exactly one curve.

#### Operator negotiates an allowed curve

```go
const operatorMetricsPort = "8080"

It("[test_id:TBD] should negotiate a curve allowed by the cluster profile on operator metrics",
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
		}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed(),
			"cannot find the operator manager pod")

		state, err := intls.ProbeTLSState(e2eclient.K8sClient, operatorPod, operatorMetricsPort)
		Expect(err).ToNot(HaveOccurred())
		Expect(state.CurveID).ToNot(BeZero(),
			"operator metrics did not negotiate a curve; check the TLS config")
		Expect(allowed).To(ContainElement(state.CurveID),
			"operator metrics negotiated curve %d outside %v", state.CurveID, allowed)
	})
```

`Eventually` around discovery is deliberate: during a rollout the Deployment
can briefly have zero or two matching Pods, which
`FindNUMAResourcesOperatorPod` treats as an error.

#### Operator rejects a disallowed curve

```go
It("[test_id:TBD] should reject a curve disallowed by the cluster profile on operator metrics",
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
		Expect(err).To(HaveOccurred(), "operator accepted disallowed curve %v", disallowed)
		Expect(errors.Is(err, intls.ErrTLSHandshakeRejected)).To(BeTrue(),
			"expected TLS rejection, got %v", err)
	})
```

#### Why this layer is separate

| Property | RTE | Scheduler | Operator metrics |
|---|---|---|---|
| Curve flag exists | `--metrics-tls-curve-preferences` | `--tls-curve-preferences` | none |
| Argument assertion possible | yes | yes | no |
| Must probe a live handshake | yes, for policy | yes, for policy | yes, only option |
| Endpoint | `2112` | `10259` | `8080` |
| Pod discovery | `getRTEPodsFromNRO` | `DeploymentByOwnerReference` + `ByDeployment` | `FindNUMAResourcesOperatorPod` |
| Scope of positive test | every RTE Pod | scheduler pod | single manager Pod |

Keep the existing `[test_id:85769]` metrics availability test. It proves the
endpoint serves metrics over HTTPS but does not inspect the negotiated curve;
these specs prove the policy. Do not modify or relabel `85769`, and do not add
webhook specs (see Section 4.9).

### 6.7 Serial E2E: restricted to empty groups

This is the only spec that changes the cluster profile. Add it to
`test/e2e/serial/tests/configuration.go` next to test 88383.

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
					if err := waitForMCPConditionWithRetry(ctx, &mcp,
						machineconfigv1.MachineConfigPoolUpdating, 40*time.Minute, 20*time.Second); err != nil {
						return err
					}
					return waitForMCPConditionWithRetry(ctx, &mcp,
						machineconfigv1.MachineConfigPoolUpdated, 40*time.Minute, 20*time.Second)
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

		expectOperands := func(g Gomega, expected objtls.Settings) {
			g.Expect(intls.CheckRTEDaemonSetTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
			nroSched := &nropv1.NUMAResourcesScheduler{}
			err := e2eclient.Client.Get(ctx, objects.NROSchedObjectKey(), nroSched)
			if apierrors.IsNotFound(err) {
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(intls.CheckSchedulerDeploymentTLSFlags(ctx, e2eclient.Client, expected)).To(Succeed())
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

		updateProfile(ctx, restricted)
		persisted := &configv1.APIServer{}
		Expect(e2eclient.Client.Get(ctx, apiServerKey, persisted)).To(Succeed())
		if persisted.Spec.TLSSecurityProfile == nil ||
			persisted.Spec.TLSSecurityProfile.Custom == nil ||
			!slices.Equal(persisted.Spec.TLSSecurityProfile.Custom.Groups, restricted.Custom.Groups) {
			Skip("the API server dropped the custom TLS groups")
		}
		waitForMCPsAndVerifyNodes(ctx, "after restricted groups")

		apply, _ := ctrltls.NewTLSConfigFromProfile(restricted.Custom.TLSProfileSpec)
		cfg := &tls.Config{}
		apply(cfg)
		expected := objtls.NewSettings(cfg)
		Expect(expected.CurvePreferences).To(Equal("29,23"))
		Eventually(func(g Gomega) {
			expectOperands(g, expected)
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())

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
			expectOperands(g, expected)
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(Succeed())
	})
```

Key points for review:

- `DeferCleanup` is registered before the first mutation.
- The test verifies the API persisted the groups; otherwise it skips rather
  than asserting against a value the cluster ignored.
- The restricted phase proves a non-empty custom list reaches both operands.
- The empty phase proves the delete branch removes the old flag.
- Scheduler assertions are conditional because the scheduler is optional.

### 6.8 Build and iterate

After each stage:

```bash
go test ./test/internal/tls/... -v
make test-controllers
make build-e2e-tls
bin/e2e-nrop-tls.test --ginkgo.v --ginkgo.focus='curve'
make binary-e2e-serial
bin/e2e-nrop-serial.test --ginkgo.v --ginkgo.focus='restricted and empty groups'
```

If `make build-e2e-tls` fails with missing imports, fix imports before running
the suite. If the suite compiles but skips, read the skip message; do not
assume the feature is covered.

### 6.9 Pull-request checklist

- Curve assertion present in the RTE helper and covered by unit tests.
- Scheduler helper added with all three flags.
- Unit tests cover match, mismatch, and stale-when-empty.
- Non-disruptive specs cover RTE and scheduler arguments.
- Operator metrics has positive and negative curve probes.
- Positive handshake checks `CurveID` membership.
- Negative handshake asserts `ErrTLSHandshakeRejected`.
- Serial test covers restricted and empty groups, with rollback.
- Every new spec has `feature:tlscompliance`.
- Serial spec has `Slow`, `Reboot`, and `Tier2`.
- No test silently passes when a required object is missing.
- All skips have a reason that explains the environment precondition.

---

## 7. Scenario-to-function and test mapping

The detailed rationale for each scenario is in
[`nrop_tls_curves_e2e_guide.md#84-scenario-catalog-what-to-cover-and-why`](nrop_tls_curves_e2e_guide.md#84-scenario-catalog-what-to-cover-and-why).
Use this table when you need to know which functions and test level implement
a scenario.

| # | Scenario | Primary functions | Suite |
|---|---|---|---|
| 1 | Built-in profile propagates curves to both operands | `FetchAPIServerTLSProfile`, `NewTLSConfigFromProfile`, `NewSettings`, `CheckRTE...`, `CheckScheduler...` | non-disruptive |
| 2 | Every NROP-managed node group is checked | `CheckRTEDaemonSetTLSFlags`, `FindContainerByName`, `GetFlag` | fake-client unit |
| 3 | Restricted Custom groups change the value | `tlsGroupPreferencesEnabled`, `NewTLSConfigFromProfile`, both `Check*` helpers, MCP waits | serial |
| 4 | One restricted list replaces another | `DaemonSetArgs`, `DeploymentTLSSettings`, `matchTLSFlag` | serial or unit |
| 5 | Restricted groups transition to empty | `DaemonSetArgs`, `DeploymentTLSSettings`, `matchTLSFlag` empty branch | serial |
| 6 | Empty groups transition back to restricted | same as 5 | serial |
| 7 | Rollback restores the original profile and flags | `DeferCleanup`, `updateProfile`, `waitForMCPsAndVerifyNodes`, both `Check*` | serial cleanup |
| 8 | Unsupported group names are handled | `TLSGroupsToCurveIDs`, `NewTLSConfigFromProfile` unsupported list | pure unit |
| 9 | Reconciliation is idempotent and repairs drift | `SetOption`, `Delete`, `Argv`, `DaemonSetArgs`, `DeploymentTLSSettings` | unit/controller |
| 10 | Scheduler positive handshake uses an allowed curve | `GetClusterTLSProfile`, `CurveIDsFromProfile`, `ProbeTLSState` | non-disruptive |
| 11 | RTE positive handshake uses an allowed curve | `getRTEPodsFromNRO`, `ProbeTLSState`, `FetchMetrics` | non-disruptive |
| 12 | Scheduler rejects a disallowed curve | `CurveIDsFromProfile`, `FindDisallowedCurve`, `ProbeTLSCurve`, `wrapTLSHandshakeError` | non-disruptive |
| 13 | RTE rejects a disallowed curve | same as 12 plus `getRTEPodsFromNRO` | non-disruptive |
| 14 | TLS 1.2 and TLS 1.3 behave correctly | `GetClusterTLSProfile`, `ProbeTLSSettings`, `ProbeTLSState`, `OpenSSLCipherToGoID` | non-disruptive |
| 15 | PQ hybrid 4588 is not dropped | `TLSGroupToCurveID`, `NewSettings`, `ProbeTLSState` | unit + non-disruptive |
| 16 | Unsupported PQ IDs 4587/4589 are explicit | `TLSGroupToCurveID`, `NewSettings`, RTE contract test | unit/contract |
| 17 | Feature gate unavailable | `tlsGroupPreferencesEnabled`, restore helper | serial precondition |
| 18 | FIPS excludes non-approved PQ groups | profile mapping and dedicated lane assertions | separate FIPS lane |
| 19 | Operator metrics negotiate an allowed curve | `FindNUMAResourcesOperatorPod`, `ProbeTLSState`, `CurveIDsFromProfile` | non-disruptive |
| 20 | Operator metrics reject a disallowed curve | same plus `FindDisallowedCurve`, `ProbeTLSCurve`, `wrapTLSHandshakeError` | non-disruptive |
| 21 | Operator metrics follow a profile change | `tlsGroupPreferencesEnabled`, MCP waits, operator restart, `ProbeTLSState` | optional serial |

### 7.1 What is missing today

Current coverage:

- `CheckRTEDaemonSetTLSFlags` checks minimum version, cipher suites, and curve
  preferences, including the stale-flag deletion case when no curves are
  expected.
- `CheckRTEDaemonSetTLSFlagsMatchClusterProfile` therefore detects a curve
  mismatch in steady state.
- `CheckSchedulerDeploymentTLSFlags` exists and is used by the serial Custom-profile test; fake-client unit tests are still missing.
- `ProbeTLSSettings` discards `ConnectionState.CurveID`.
- Test 88383 switches built-in profiles, but all built-in profiles currently
  use the same groups, so it does not prove value propagation.
- No E2E test covers the non-empty-to-empty transition.
- No E2E test offers a single disallowed curve.
- Operator metrics has no curve assertion at all. Test 85769 only proves that
  `curl -k https://127.0.0.1:8080/metrics` returns a body; it cannot observe
  the negotiated curve.

The minimum closing set is scenarios 1, 2, 3, 5, 10, 11, 12, 13, 19, and 20.
Add 4, 6, 8, 9, and 21 as hardening. Scenario 16 is a contract test against the pinned RTE
version, not a passing E2E test until RTE accepts 4587 and 4589.

### 7.2 How to trace a required scenario to code

Example: "Scenario 12 must reject a disallowed curve on the scheduler."

1. Read the profile: `GetClusterTLSProfile`.
2. Convert groups: `CurveIDsFromProfile`.
3. Select an outside curve: `FindDisallowedCurve`.
4. Find the scheduler pod: `NROSchedObjectKey`,
   `DeploymentByOwnerReference`, `ByDeployment`.
5. Open the port and offer one curve: `ProbeTLSCurve` ->
   `PortForwardToPod` -> `tlsHandshake`.
6. Classify the failure: `wrapTLSHandshakeError`, then
   `errors.Is(err, ErrTLSHandshakeRejected)`.
7. Cover it with the spec in Section 6.5.

Example: "Scenario 19 must accept an allowed curve on operator metrics."

1. Read the profile and convert its groups: `GetClusterTLSProfile` ->
   `CurveIDsFromProfile`.
2. Find the manager Pod: `objects.NROObjectKey` ->
   `deploy.FindNUMAResourcesOperatorPod`.
3. Open port `8080` and perform a normal handshake: `ProbeTLSState` ->
   `PortForwardToPod` -> `tlsHandshake`.
4. Assert `state.CurveID` is non-zero and is in the allowed set.
5. Cover it with the spec in Section 6.6. There is no argument step because
   the operator metrics server has no curve flag.

If any step is missing, the scenario is not covered even if the spec exists.

---

## 8. Debugging by pipeline stage

### 8.1 Ask which stage failed

| Symptom | Stage | First check |
|---|---|---|
| CSV is wrong in a unit test | mapping/formatting | `TLSGroupsToCurveIDs`, `NewSettings` |
| CSV is right but flag is absent | operand updater | `DaemonSetArgs` or `DeploymentTLSSettings` |
| Flag is present but value is stale | reconcile/delete branch | expected empty? `matchTLSFlag` empty case |
| Argument test passes, handshake fails | runtime/server | pod logs, port, TLS config |
| Positive handshake negotiates an outside curve | profile/filter bug | `CurveIDsFromProfile`, server flags |
| Negative handshake succeeds | server ignored policy | operand flag and server version |
| Serial times out | MCP rollout | MCP conditions, node configs |
| RTE crashes on startup | RTE parser compatibility | curve IDs 4587/4589 |
| Operator metrics probe fails but RTE works | operator metrics server | `TLSOpts` in `metricsserver.Options`, manager Pod readiness |

Do not jump to the E2E suite when a unit test can answer the question. Most
curve bugs are deterministic string or slice bugs.

### 8.2 Manual inspection commands

Read the profile:

```bash
oc get apiserver cluster -o yaml | sed -n '/tlsSecurityProfile:/,/^[^ ]/p'
```

Read the resolved built-in profile through a small Go program if you need the
exact groups. Do not assume the YAML shows defaults that are omitted.

Read RTE DaemonSet args:

```bash
oc get ds -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{range .spec.template.spec.containers[*]}{.name}{" "}{.args}{"\n"}{end}{end}'
```

Filter to the curve flag:

```bash
oc get ds -A -o json | jq -r '
  .items[] as $ds |
  $ds.spec.template.spec.containers[] |
  select(.name=="resource-topology-exporter") |
  $ds.metadata.namespace + "/" + $ds.metadata.name + " " +
  ([.args[] | select(startswith("--metrics-tls-curve-preferences"))] | join(" "))'
```

Read scheduler Deployment args:

```bash
oc get deploy -A -o json | jq -r '
  .items[] as $dp |
  $dp.spec.template.spec.containers[] |
  select(.name=="secondary-scheduler") |
  $dp.metadata.namespace + "/" + $dp.metadata.name + " " +
  ([.args[] | select(startswith("--tls-"))] | join(" "))'
```

Check pods and logs:

```bash
oc get pods -A | grep -E 'resource-topology|secondary-scheduler'
oc logs -n <namespace> <pod> -c resource-topology-exporter
oc logs -n <namespace> <pod> -c secondary-scheduler
```

Check MCP state during serial tests:

```bash
oc get mcp
oc get mcp -o json | jq -r '.items[] | [.metadata.name, .status.configuration.name] | @tsv'
oc get nodes -o json | jq -r '.items[] | [.metadata.name, .metadata.annotations["machineconfiguration.openshift.io/currentConfig"]] | @tsv'
```

### 8.3 Manual TLS handshake

Port-forward to the scheduler:

```bash
oc port-forward -n <namespace> <scheduler-pod> 10259:10259
```

In another shell:

```bash
openssl s_client -connect 127.0.0.1:10259 -groups X25519 </dev/null
openssl s_client -connect 127.0.0.1:10259 -groups P-521 </dev/null
```

The first should succeed when X25519 is allowed. The second should fail when
P-521 is not allowed. Use `-tls1_2` to inspect cipher suites; TLS 1.3 cipher
suites are not configurable.

If `openssl s_client` fails but the Go probe succeeds, the difference is
usually the client's default curve list or certificate verification. The Go
probe intentionally sets `InsecureSkipVerify`.

### 8.4 Common errors and fixes

#### `no kind is registered for the type ...`

The fake client or scheme lacks the API type. Add:

```go
utilruntime.Must(nropv1.AddToScheme(scheme.Scheme))
utilruntime.Must(configv1.AddToScheme(scheme.Scheme))
```

before building the fake client.

#### `failed to get APIServer "cluster": forbidden`

The test identity cannot read the cluster APIServer. This is a cluster or
RBAC precondition, not a curve failure. Fail the suite setup rather than
skip, because every TLS assertion would be meaningless.

#### `context deadline exceeded` in `Eventually`

The operator has not reconciled yet, or the assertion is inside a branch that
can never succeed. Check the live args manually. If they are already correct,
raise the timeout or fix the helper. Do not hide the error with a longer
timeout before confirming the expected value.

#### `expected TLS rejection, got <nil>`

The server accepted the curve or cipher. Check:

- the operand flag value is the expected CSV;
- the server process restarted after the arg change;
- the curve is actually outside the allowed set;
- the profile was not changed by another test.

#### Negative curve probe fails with an error that is not `ErrTLSHandshakeRejected`

Print the full error before changing the assertion. A genuine server refusal
is usually `remote error: tls: handshake failure` or a `tls.AlertError`, both
of which `wrapTLSHandshakeError` classifies. If the error is a client-side
configuration error such as "no supported versions" or "no ciphers
available", the probe itself is invalid. Do not weaken
`errors.Is(err, ErrTLSHandshakeRejected)` to `err != nil`; that would let a
port-forward failure masquerade as a policy rejection.

#### `negotiated curve ... is not allowed by profile groups`

The server negotiated an outside curve. Check the operand flag and whether
the server's parser accepted it. If the flag is absent, this is an argument
propagation bug. If the flag is present but ignored, this is an operand bug.

#### RTE CrashLoopBackOff with `unsupported curve ID 4587` or `4589`

RTE v0.25.4 accepts only `23,24,25,29,4588`. It rejects the two other PQ
hybrid IDs that library-go knows about. A Custom profile containing
`SecP256r1MLKEM768` or `SecP384r1MLKEM1024` will crash the pinned RTE even
though OpenShift accepts the profile. Keep this as a documented contract test
until RTE is upgraded; do not add a passing E2E test that expects success.

#### TLS 1.3 cipher assertion fails

TLS 1.3 cipher suites are fixed by Go and cannot be configured. The profile's
cipher list is not applied when `MinVersion == VersionTLS13`. Assert curves,
not ciphers, for TLS 1.3.

#### Serial test times out waiting for `Updating`

The rollout may have completed before the first observation. The wait helper
requires the MCP resource version to change from the supplied object. Refresh
the MCP before waiting, or treat an already-`Updated` condition as success.
Do not reduce the timeout; a TLS profile rollout legitimately takes tens of
minutes.

### 8.5 How to read a Ginkgo failure

Example:

```text
[FAIL] TLS [It] should reject a curve disallowed by the cluster profile
.../tls_test.go:123
Expected
    <bool>: false
to be true
```

Read the last `By` step before the failure. It tells you which stage ran:

- failure while getting the profile: setup/read problem;
- failure while discovering pods: discovery problem;
- failure on `ProbeTLSCurve`: handshake problem;
- failure on `errors.Is`: the handshake failed for a different reason, such
  as port-forward or client config.

Always log the disallowed curve ID and the allowed set before the probe. A
negative test that does not show what it offered is hard to debug.

---

## 9. Quick reference

### 9.1 Operand flags and value formats

| Operand | Minimum version | Cipher suites | Curves |
|---|---|---|---|
| RTE | `--metrics-tls-min-version` | `--metrics-tls-cipher-suites` | `--metrics-tls-curve-preferences` |
| Scheduler | `--tls-min-version` | `--tls-cipher-suites` | `--tls-curve-preferences` |
| Operator metrics | none (managed in `cmd/main.go`) | none | none |

Value formats:

- Minimum version: `VersionTLS10`, `VersionTLS11`, `VersionTLS12`,
  `VersionTLS13`.
- Cipher suites: comma-separated IANA names, for example
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
- Curves: comma-separated decimal IDs, for example `4588,29,23,24`.
- Empty curves: the flag must be absent (or explicitly empty), not `0`.
- Operator metrics: there is no operand flag. Set `CurvePreferences` through
  the shared `tlsConfig` callback and verify the live handshake on port `8080`.

### 9.2 Curve ID table

| OpenShift group | Go constant | Decimal |
|---|---|---:|
| `secp256r1` | `tls.CurveP256` | 23 |
| `secp384r1` | `tls.CurveP384` | 24 |
| `secp521r1` | `tls.CurveP521` | 25 |
| `X25519` | `tls.X25519` | 29 |
| `SecP256r1MLKEM768` | `tls.SecP256r1MLKEM768` | 4587 |
| `X25519MLKEM768` | `tls.X25519MLKEM768` | 4588 |
| `SecP384r1MLKEM1024` | `tls.SecP384r1MLKEM1024` | 4589 |

Built-in Old, Intermediate, and Modern profiles in this snapshot all use
`X25519MLKEM768, X25519, secp256r1, secp384r1`, which becomes
`4588,29,23,24`.

### 9.3 Function signature cheat sheet

```go
// Profile and mapping
ctrltls.FetchAPIServerTLSProfile(ctx, cli) (configv1.TLSProfileSpec, error)
ctrltls.GetTLSProfileSpec(profile) (configv1.TLSProfileSpec, error)
ctrltls.NewTLSConfigFromProfile(spec) (func(*tls.Config), []string)
libgocrypto.TLSGroupToCurveID(group) (tls.CurveID, bool)
libgocrypto.TLSGroupsToCurveIDs(groups) ([]tls.CurveID, []configv1.TLSGroup)
libgocrypto.ValidTLSGroups() []configv1.TLSGroup

// Settings and args
objtls.NewSettings(cfg) objtls.Settings
objtls.Settings.String() string
rteupdate.DaemonSetArgs(ds, conf, settings) error
schedupdate.DeploymentTLSSettings(dp, settings) error
flagcodec.ParseArgvKeyValue(args, opts...) *Flags
flags.SetOption(name, value)
flags.Delete(name)
flags.GetFlag(name) (Val, bool)
flags.Argv() []string

// Discovery and assertions
podlist.With(cli).DeploymentByOwnerReference(ctx, uid) (*Deployment, error)
podlist.With(cli).ByDeployment(ctx, deployment) ([]Pod, error)
podlist.With(cli).ByDaemonset(ctx, daemonset) ([]Pod, error)
deploy.FindNUMAResourcesOperatorPod(ctx, cli, nrop) (*corev1.Pod, error)
remoteexec.CommandOnPod(ctx, k8sCli, pod, command...) ([]byte, []byte, error)
intls.GetClusterTLSProfile(ctx, cli) (uint16, configv1.TLSProfileSpec, error)
intls.RTESettingsFromClusterProfile(ctx, cli) (objtls.Settings, error)
intls.CheckRTEDaemonSetTLSFlags(ctx, cli, settings) error
intls.CheckRTEDaemonSetTLSFlagsMatchClusterProfile(ctx, cli) error
intls.CheckSchedulerDeploymentTLSFlags(ctx, cli, settings) error // implemented
intls.matchTLSFlag(flags, name, expected, objectName) error
intls.TLSVersionBelow(version) (uint16, error)

// Probes
intls.ProbeMaxTLSVersion(k8sCli, pod, port, maxVersion) error
intls.ProbeTLSCipher(k8sCli, pod, port, opensslCipher) error
intls.ProbeTLSSettings(k8sCli, pod, port) (version, cipher uint16, err error)
intls.ProbeTLSState(k8sCli, pod, port) (*tls.ConnectionState, error) // proposed
intls.ProbeTLSCurve(k8sCli, pod, port, curveID) error // proposed
intls.FindDisallowedCurve(allowed) (tls.CurveID, error) // proposed
intls.CurveIDsFromProfile(spec) []tls.CurveID // proposed
intls.FindDisallowedCipher(allowed) string
intls.OpenSSLCipherToGoID(opensslName) (uint16, error)
intls.FetchMetrics(k8sCli, pod, port) ([]byte, error)

// Serial
tlsGroupPreferencesEnabled(ctx, cli) (bool, error) // proposed
waitForMCPConditionWithRetry(ctx, mcp, condition, timeout, interval) error
isTransientMCPError(err) bool
verifyNodesMatchMCPConfig(ctx, mcp) error
```

### 9.4 Minimal test-by-stage commands

```bash
# 1. Profile and mapping
go test ./pkg/objectupdate/tls/... -run Curve -v

# 2. Settings and args
go test ./pkg/objectupdate/rte/... ./pkg/objectupdate/sched/... -run TLS -v

# 3. Helper assertions
go test ./test/internal/tls/... -run 'TLS|Curve|Flag' -v

# 4. Controller reconciliation
make test-controllers

# 5. Installed operands
make build-e2e-tls
bin/e2e-nrop-tls.test --ginkgo.v --ginkgo.label-filter='feature:tlscompliance'

# 6. Profile transitions
make binary-e2e-serial
bin/e2e-nrop-serial.test --ginkgo.v --ginkgo.focus='restricted and empty groups'
```

### 9.5 Glossary

| Term | Meaning |
|---|---|
| TLS profile | OpenShift `APIServer/cluster.spec.tlsSecurityProfile` policy |
| Group | OpenShift API name for a TLS named group, such as `X25519` |
| Curve | Go `crypto/tls` type and ID for the same concept |
| Curve preferences | The operand flag's comma-separated decimal ID list |
| Built-in profile | Old, Intermediate, or Modern profile from `configv1.TLSProfiles` |
| Custom profile | User-supplied `TLSProfileSpec` in `tlsSecurityProfile.custom` |
| Operand | A process NROP deploys: RTE or the secondary scheduler |
| RTE | Resource Topology Exporter, the per-node metrics and NRT agent |
| MCP | MachineConfigPool; a TLS profile change rolls its nodes |
| Delete-on-empty | When expected curves are empty, remove the flag rather than write an empty value |
| Negative probe | Offer a version or curve that policy should reject |
| Positive probe | Perform a normal handshake and assert the result is allowed |

### 9.6 What to do next

For a first contribution, implement Section 6.1 steps 1 and 2 with Section 5.6
and Section 5.7 tests. That is a small, reviewable patch that closes the
argument-coverage gap for both operands. Then add the positive and negative
non-disruptive specs for RTE, the scheduler, and operator metrics (Sections
6.4, 6.5, and 6.6). Add the serial transition last.

If a required scenario still has no test after that patch, use Section 7 to
identify the missing function or suite before writing more code.













