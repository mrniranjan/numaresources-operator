# TLS Curves E2E: Working TODO

Checklist for finishing the TLS curve coverage work in
`test/internal/tls/tls.go`, its unit tests, and the E2E specs. Code blocks are
examples to apply by hand; this repository is documentation-only for the agent
that produced this file.

Cross-references: `nrop_tls_curves_e2e_guide.md` §9.2 (scheduler helper),
§9.2.1 (not-deployed handling), §9.3.2 (curve failure classification),
§9.6-§9.8 (curve specs).

## Status summary

| # | Item | State |
|---|---|---|
| 1 | `gofmt` clean on `test/internal/tls/tls.go` | open |
| 2 | Unit test for the curve-refusal branch | open |
| 3 | Scheduler "not deployed" sentinel | open |
| 4 | Shared `checkPodTemplateTLSFlags` | open |
| 5 | `matchTLSFlag` label rename | open |
| 6 | `probeTLSWithConfig` empty-state error | open |
| 7 | `ProbeMaxTLSVersion` on the shared path | optional |
| 8 | Unit tests for `CheckSchedulerDeploymentTLSFlags` | open |
| 9 | Curve E2E specs (scheduler, RTE, operator metrics) | open |
| 10 | Sync stale `ProbeTLSSettings` references in other docs | open |

## 1. `gofmt` clean

`gofmt -l test/internal/tls/tls.go` currently reports the file. Only diff is a
trailing space in the comment above `withCipher`. Remove it and re-run:

```bash
/home/agent/.local/go/bin/gofmt -l test/internal/tls/tls.go
# no output expected
```

## 2. Unit test for the curve-refusal branch

`wrapTLSHandshakeError` now maps `tls: no supported elliptic curves for ECDHE`
to `ErrTLSClientConfigIncompatible`, but `TestWrapTLSHandshakeError` has no case
for it. Add:

```go
t.Run("no supported elliptic curves wraps as client config incompatible", func(t *testing.T) {
	err := fmt.Errorf("tls: no supported elliptic curves for ECDHE")
	got := wrapTLSHandshakeError(err)
	if !errors.Is(got, ErrTLSClientConfigIncompatible) {
		t.Errorf("expected ErrTLSClientConfigIncompatible, got %v", got)
	}
	if !errors.Is(got, ErrTLSHandshakeRejected) {
		t.Errorf("expected ErrTLSHandshakeRejected in chain, got %v", got)
	}
})
```

Optional hardening: pin the real runtime string with an in-memory handshake
(`net.Pipe` + `tls.Client` with `CurvePreferences: []tls.CurveID{0x1234}`) and
`t.Skipf` if a Go upgrade changes the wording. See guide §9.3.2, patch 3.

## 3. Scheduler "not deployed" sentinel

Today a missing `NUMAResourcesScheduler` surfaces as
`failed to get NUMAResourcesScheduler: ... not found`, which the serial spec
retries for the full timeout and then reports as a TLS mismatch.

```go
// ErrSchedulerNotDeployed reports that NUMAResourcesScheduler is absent, so
// there is no scheduler operand whose TLS settings can be verified.
var ErrSchedulerNotDeployed = errors.New("scheduler is not deployed")
```

```go
nroSched := &nropv1.NUMAResourcesScheduler{}
schedKey := client.ObjectKey{Name: objectnames.DefaultNUMAResourcesSchedulerCrName}
if err := cli.Get(ctx, schedKey, nroSched); err != nil {
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: NUMAResourcesScheduler %q not found", ErrSchedulerNotDeployed, schedKey.Name)
	}
	return fmt.Errorf("failed to get NUMAResourcesScheduler: %w", err)
}
```

Rules:

- CR missing → sentinel → spec skips.
- CR present but `Status.Deployment` empty → plain (retryable) error, never the
  sentinel; the controller may simply not have reconciled yet.
- Deployment present but container missing → real failure.

Spec guard (`test/e2e/serial/tests/configuration.go`, before the profile is
mutated). `client.Client.Get` returns only `error`:

```go
nroSched := &nropv1.NUMAResourcesScheduler{}
err := e2eclient.Client.Get(ctx, objects.NROSchedObjectKey(), nroSched)
if apierrors.IsNotFound(err) {
	Skip("NUMAResourcesScheduler is not deployed on this cluster")
}
Expect(err).ToNot(HaveOccurred(), "failed to get NUMAResourcesScheduler")
```

Do not call `Skip` inside an `Eventually` closure.

## 4. Shared `checkPodTemplateTLSFlags`

The RTE and scheduler helpers differ only in discovery and flag prefix. Extract
the comparison core:

```go
// checkPodTemplateTLSFlags compares the TLS flags of the named container
// against expected. flagPrefix is "--metrics-" for RTE and "--" for the
// scheduler.
func checkPodTemplateTLSFlags(tmpl *corev1.PodTemplateSpec, containerName, flagPrefix string, expected objtls.Settings, objName string) error {
	cnt := k8swgobjupdate.FindContainerByName(tmpl.Spec.Containers, containerName)
	if cnt == nil {
		return fmt.Errorf("container %q not found in %q", containerName, objName)
	}
	flags := flagcodec.ParseArgvKeyValue(cnt.Args, flagcodec.WithFlagNormalization)
	if err := matchTLSFlag(flags, flagPrefix+"tls-min-version", expected.MinVersion, objName); err != nil {
		return err
	}
	if err := matchTLSFlag(flags, flagPrefix+"tls-cipher-suites", expected.CipherSuites, objName); err != nil {
		return err
	}
	return matchTLSFlag(flags, flagPrefix+"tls-curve-preferences", expected.CurvePreferences, objName)
}
```

`flagcodec.ParseArgvKeyValue` always returns a non-nil `*Flags`
(`pkg/numaresourcesoperator/flagcodec`, `:55-73`), so no nil guard is needed.

### RTE caller

```go
func CheckRTEDaemonSetTLSFlags(ctx context.Context, cli client.Client, expected objtls.Settings) error {
	nropObj := &nropv1.NUMAResourcesOperator{}
	if err := cli.Get(ctx, client.ObjectKey{Name: objectnames.DefaultNUMAResourcesOperatorCrName}, nropObj); err != nil {
		return fmt.Errorf("failed to get NUMAResourcesOperator: %w", err)
	}
	if len(nropObj.Status.NodeGroups) == 0 {
		return errors.New("numaresourcesoperator has no NodeGroup in status")
	}
	for _, ng := range nropObj.Status.NodeGroups {
		ds := &appsv1.DaemonSet{}
		if err := cli.Get(ctx, client.ObjectKey{Namespace: ng.DaemonSet.Namespace, Name: ng.DaemonSet.Name}, ds); err != nil {
			return fmt.Errorf("failed to get DaemonSet %s/%s: %w", ng.DaemonSet.Namespace, ng.DaemonSet.Name, err)
		}
		if err := checkPodTemplateTLSFlags(&ds.Spec.Template, rteupdate.MainContainerName, "--metrics-", expected, ds.Name); err != nil {
			return err
		}
	}
	return nil
}
```

### Scheduler caller

```go
func CheckSchedulerDeploymentTLSFlags(ctx context.Context, cli client.Client, expected objtls.Settings) error {
	nroSched := &nropv1.NUMAResourcesScheduler{}
	schedKey := client.ObjectKey{Name: objectnames.DefaultNUMAResourcesSchedulerCrName}
	if err := cli.Get(ctx, schedKey, nroSched); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: NUMAResourcesScheduler %q not found", ErrSchedulerNotDeployed, schedKey.Name)
		}
		return fmt.Errorf("failed to get NUMAResourcesScheduler: %w", err)
	}
	depRef := nroSched.Status.Deployment
	if depRef.Namespace == "" || depRef.Name == "" {
		return fmt.Errorf("scheduler deployment is not reported in NUMAResourcesScheduler %q status", schedKey.Name)
	}
	dp := &appsv1.Deployment{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: depRef.Namespace, Name: depRef.Name}, dp); err != nil {
		return fmt.Errorf("failed to get scheduler Deployment %s/%s: %w", depRef.Namespace, depRef.Name, err)
	}
	return checkPodTemplateTLSFlags(&dp.Spec.Template, schedupdate.MainContainerName, "--", expected, dp.Name)
}
```

### Test for the shared core

```go
func TestCheckPodTemplateTLSFlags(t *testing.T) {
	tmpl := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
		Name: rteupdate.MainContainerName,
		Args: []string{
			"--metrics-tls-min-version=VersionTLS12",
			"--metrics-tls-curve-preferences=29,23",
		},
	}}}}

	err := checkPodTemplateTLSFlags(&tmpl, rteupdate.MainContainerName, "--metrics-",
		objtls.Settings{MinVersion: "VersionTLS12", CurvePreferences: "29,23"}, "rte-ds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := checkPodTemplateTLSFlags(&tmpl, rteupdate.MainContainerName, "--",
		objtls.Settings{MinVersion: "VersionTLS12"}, "rte-ds"); err == nil {
		t.Fatal("expected an error when the prefix does not match the operand flags")
	}
}
```

The second assertion proves the prefix parameter is load-bearing.

## 5. `matchTLSFlag` label rename

The helper now runs against a Deployment but reports `daemonsetName=`:
`test/internal/tls/tls.go:413` and `:422`.

```go
func matchTLSFlag(flags *flagcodec.Flags, flagName, expected, objName string) error {
	// ...
	return fmt.Errorf("%s mismatch object=%q expected=%q got=%q", flagName, objName, expected, got)
}
```

Callers pass `ds.Name` / `dp.Name` unchanged. Update the five exact-string
expectations in `test/internal/tls/tls_test.go:471,492,532,553,595`
(`daemonsetName=` → `object=`).

## 6. `probeTLSWithConfig` empty-state error

`test/internal/tls/tls.go:348` returns a zero `tls.ConnectionState` with a
possibly nil error if the port-forward callback never ran:

```go
if state == nil {
	if err != nil {
		return tls.ConnectionState{}, err
	}
	return tls.ConnectionState{}, errors.New("tls probe finished without a handshake")
}
```

## 7. `ProbeMaxTLSVersion` on the shared path (optional)

```go
func withMaxVersion(v uint16) tlsConfigOpt {
	return func(cfg *tls.Config) {
		cfg.MinVersion = v
		cfg.MaxVersion = v
	}
}

func ProbeMaxTLSVersion(cli kubernetes.Interface, pod *corev1.Pod, podPort string, maxVersion uint16) error {
	_, err := probeTLSWithConfig(cli, pod, podPort, withMaxVersion(maxVersion))
	return err
}
```

Removes the second wrapping/logging implementation.

## 8. Unit tests for `CheckSchedulerDeploymentTLSFlags`

`TestCheckRTEDaemonSetTLSFlags` covers match, mismatch, stale-flag and
multi-nodegroup. Mirror it for the scheduler, plus:

```go
func TestCheckSchedulerDeploymentTLSFlagsNotDeployed(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
	err := CheckSchedulerDeploymentTLSFlags(context.Background(), cli, objtls.Settings{})
	if !errors.Is(err, ErrSchedulerNotDeployed) {
		t.Fatalf("got %v, want ErrSchedulerNotDeployed", err)
	}
}

func TestCheckSchedulerDeploymentTLSFlagsNoDeploymentInStatus(t *testing.T) {
	nroSched := &nropv1.NUMAResourcesScheduler{
		ObjectMeta: metav1.ObjectMeta{Name: objectnames.DefaultNUMAResourcesSchedulerCrName},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(nroSched).Build()
	err := CheckSchedulerDeploymentTLSFlags(context.Background(), cli, objtls.Settings{})
	if err == nil {
		t.Fatal("expected an error when status does not report a deployment")
	}
	if errors.Is(err, ErrSchedulerNotDeployed) {
		t.Fatalf("empty status must stay retryable, got ErrSchedulerNotDeployed: %v", err)
	}
}
```

Add a `newSchedulerDeployment(...)` fixture mirroring
`newRTEDaemonSetWithMainContainerArgs`, using
`schedupdate.MainContainerName`.

## 9. Curve E2E specs

Still to write, in `test/e2e/tls/tls_test.go`:

- Scheduler positive: `ProbeTLSState` on `10259`, assert `state.CurveID != 0`
  and membership in the allowed set.
- Scheduler negative: `FindDisallowedCurve` + `ProbeTLSCurve`, assert
  `errors.Is(err, intls.ErrTLSServerRejected)`.
- RTE positive and negative: same on `2112`, per pod.
- Operator metrics: same on `8080` (needs the manager pod lookup).

Do not assert only `ErrTLSHandshakeRejected` in negative curve specs; a
client-side refusal must not count as server enforcement (guide §9.3.2).

## 10. Doc sync

These still describe `ProbeTLSSettings` as current API:

- `nrop_tls.md:874,902,909,966,1014,1948`
- `nrop_e2e_guide.md:687,714,1370`
- `nrop_tls_curves_automation.md:468,2011,3174,3188,3706,3725,4040`

Replace with `ProbeTLSState` (returns `tls.ConnectionState`) and keep the
deprecation note.

## Verification

```bash
/home/agent/.local/go/bin/gofmt -l test/internal/tls/tls.go test/e2e/tls/tls_test.go
GOCACHE=/tmp/nrop-go-cache GOFLAGS=-mod=vendor \
  /home/agent/.local/go/bin/go vet ./test/internal/tls ./test/e2e/tls ./test/e2e/serial/...
GOCACHE=/tmp/nrop-go-cache GOFLAGS=-mod=vendor \
  /home/agent/.local/go/bin/go test ./test/internal/tls -count=1
```

The Ginkgo suites need a live NROP cluster; the commands above only prove the
packages compile and the helpers behave.
