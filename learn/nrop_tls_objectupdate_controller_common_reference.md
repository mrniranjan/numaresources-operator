# NROP TLS Object-Update and controller-runtime-common Reference

This document is a complete reference for the two packages that convert the
cluster TLS profile into NROP operand configuration:

- `pkg/objectupdate/tls/` — NROP-owned conversion from `*tls.Config` to
  command-line argument strings.
- `vendor/github.com/openshift/controller-runtime-common/pkg/tls/` — OpenShift
  helpers for reading the `APIServer` TLS profile, building a `tls.Config`,
  and watching the profile for changes.

It complements:

- [`nrop_tls.md`](nrop_tls.md): TLS architecture and exposed endpoints.
- [`nrop_tls_curves_e2e_guide.md`](nrop_tls_curves_e2e_guide.md): concepts,
  coverage matrix, and scenario catalog.
- [`nrop_tls_curves_automation.md`](nrop_tls_curves_automation.md): how to
  write and test the automation.

All paths and line numbers were verified against commit `6b76dcedb` on branch
`tls_learning`.

---

## 1. File inventory and mental model

| File | Lines | Role |
|---|---:|---|
| `pkg/objectupdate/tls/tls.go` | 71 | Defines `Settings`, formats a `tls.Config` into operand argument values, and formats curve IDs as decimal CSV. |
| `pkg/objectupdate/tls/tls_test.go` | 181 | Unit tests for version names, cipher names, curve CSV, and `Settings.String`. |
| `vendor/github.com/openshift/controller-runtime-common/pkg/tls/tls.go` | 216 | Fetches the `APIServer` profile, resolves built-in/custom profiles, builds a `tls.Config` mutator, converts ciphers and groups, and sets ALPN protocols. |
| `vendor/github.com/openshift/controller-runtime-common/pkg/tls/controller.go` | 177 | `SecurityProfileWatcher`, a controller that watches `APIServer/cluster` and calls callbacks when the TLS profile or adherence policy changes. |

The runtime data flow is:

```text
APIServer/cluster.spec.tlsSecurityProfile
        │
        │ ctrltls.FetchAPIServerTLSProfile
        ▼
configv1.TLSProfileSpec
        │
        │ ctrltls.NewTLSConfigFromProfile
        ▼
func(*tls.Config)
        │
        │ apply once to an empty &tls.Config{}
        ▼
tls.Config{MinVersion, CipherSuites, CurvePreferences}
        │
        │ objtls.NewSettings
        ▼
objtls.Settings{
    MinVersion:       "VersionTLS12",
    CipherSuites:     "TLS_ECDHE_...",
    CurvePreferences: "4588,29,23,24",
}
        │
        ├──► NUMAResourcesOperatorReconciler.RTEMetricsTLS
        │       └── rteupdate.DaemonSetArgs
        │             --metrics-tls-min-version
        │             --metrics-tls-cipher-suites
        │             --metrics-tls-curve-preferences
        │
        └──► NUMAResourcesSchedulerReconciler.TLSSettings
                └── schedupdate.DeploymentTLSSettings
                      --tls-min-version
                      --tls-cipher-suites
                      --tls-curve-preferences
```

Separately, at the same time:

```text
APIServer/cluster change
        │
        ▼
SecurityProfileWatcher.Reconcile
        │
        ├── GetTLSProfileSpec
        ├── reflect.DeepEqual with InitialTLSProfileSpec
        └── OnProfileChange -> cancel manager context -> restart -> re-read profile
```

The two packages have different responsibilities:

- `controller-runtime-common` turns the **API object** into a **Go TLS
  configuration**.
- `pkg/objectupdate/tls` turns that **Go TLS configuration** into **strings
  that can be passed to operand processes**.

---

## 2. `pkg/objectupdate/tls/tls.go`

### 2.1 Package declaration and imports

```go
package tls

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	libgocrypto "github.com/openshift/library-go/pkg/crypto"
)
```

| Import | Why it is needed |
|---|---|
| `crypto/tls` | Reads `tls.Config.MinVersion`, `tls.Config.CipherSuites`, `tls.Config.CurvePreferences`, and converts cipher IDs to names. |
| `fmt` | Builds the logging string in `Settings.String`. |
| `strconv` | Converts numeric curve IDs to decimal text. |
| `strings` | Builds comma-separated strings with `strings.Builder` and `strings.Join`. |
| `libgocrypto` | Converts the numeric TLS version to the canonical `VersionTLSxx` name. |

The package name is `tls`, but NROP imports it as `objtls` to avoid confusion
with the standard library:

```go
objtls "github.com/openshift-kni/numaresources-operator/pkg/objectupdate/tls"
```

### 2.2 Type `Settings`

```go
// Settings holds pre-computed string representations of TLS configuration.
type Settings struct {
	MinVersion       string
	CipherSuites     string
	CurvePreferences string // Comma-separated numeric IDs (e.g., "29,23,24")
}
```

This is a **plain value type**. It deliberately contains only strings because
its destination is command-line arguments, not a live Go TLS server.

#### Field-by-field explanation

| Field | Type | Meaning | Empty-value meaning | Example |
|---|---|---|---|---|
| `MinVersion` | `string` | Canonical Go/OpenShift TLS version name. | No version should be written; consumers delete the flag. | `"VersionTLS12"` |
| `CipherSuites` | `string` | Comma-separated IANA cipher names in the same order as `tls.Config.CipherSuites`. | No cipher list should be written; consumers delete the flag. For TLS 1.3 this is expected because Go does not allow configuring TLS 1.3 ciphers. | `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"` |
| `CurvePreferences` | `string` | Comma-separated decimal `tls.CurveID` values in preference order. | No curve filter should be written; consumers delete the flag so the operand uses its own defaults. | `"4588,29,23,24"` |

#### Invariants

1. `MinVersion` is expected to be non-empty in normal operation because
   `NewSettings` calls an `OrDie` conversion on it.
2. `CipherSuites` preserves the input order and duplicates. It is not sorted or
   deduplicated.
3. `CurvePreferences` preserves the input order and duplicates. It is not
   sorted or deduplicated.
4. Empty `CurvePreferences` is meaningful. It is how NROP represents a Custom
   profile with no `groups`, so the operand updaters delete
   `--*-tls-curve-preferences`.
5. `Settings` is copied by value into reconciler structs. There are no pointers
   or shared mutable state inside it.

### 2.3 Method `Settings.String`

Source: `pkg/objectupdate/tls/tls.go:35-41`.

```go
func (s Settings) String() string {
	ret := fmt.Sprintf("MinVersion: %s, CipherSuites: %s", s.MinVersion, s.CipherSuites)
	if s.CurvePreferences != "" {
		return ret + fmt.Sprintf(", CurvePreferences: %s", s.CurvePreferences)
	}
	return ret
}
```

#### Line-by-line logic

1. `func (s Settings) String() string` uses a value receiver. Calling `String`
   cannot mutate the `Settings`.
2. It builds the mandatory prefix with `MinVersion` and `CipherSuites`.
   Both fields are always printed, even when the cipher string is empty.
3. If `CurvePreferences` is non-empty, it appends a third field.
4. If curves are empty, it returns the two-field string without a trailing
   curve label.

#### Exact output examples

| Settings | Output |
|---|---|
| `{MinVersion:"VersionTLS12", CipherSuites:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CurvePreferences:"4588,29,23,24"}` | `MinVersion: VersionTLS12, CipherSuites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CurvePreferences: 4588,29,23,24` |
| `{MinVersion:"VersionTLS13", CipherSuites:"", CurvePreferences:""}` | `MinVersion: VersionTLS13, CipherSuites: ` |

Note the trailing space after `CipherSuites:` in the second example. This is
intentional in the implementation and is asserted by
`TestSettings_String`.

#### Why it exists and where it is used

It is a logging aid. It is used in `cmd/main.go`:

```go
tlsSettings := objtls.NewSettings(tlsCfg)
klog.InfoS("found TLS settings from APIServer", "settings", tlsSettings.String())
```

It lets an operator log show exactly what was derived from the profile before
the controllers start. It is not parsed by anything.

### 2.4 Function `NewSettings`

Source: `pkg/objectupdate/tls/tls.go:44-60`.

```go
func NewSettings(cfg *tls.Config) Settings {
	cipherNames := make([]string, 0, len(cfg.CipherSuites))
	for _, id := range cfg.CipherSuites {
		cipherNames = append(cipherNames, tls.CipherSuiteName(id))
	}

	settings := Settings{
		MinVersion:   libgocrypto.TLSVersionToNameOrDie(cfg.MinVersion),
		CipherSuites: strings.Join(cipherNames, ","),
	}

	if len(cfg.CurvePreferences) > 0 {
		settings.CurvePreferences = curveIDsToString(cfg.CurvePreferences)
	}

	return settings
}
```

#### Line-by-line logic

1. `func NewSettings(cfg *tls.Config) Settings` takes a pointer to a fully
   initialized TLS config. It returns a value, not a pointer.
2. `cipherNames := make([]string, 0, len(cfg.CipherSuites))` allocates a slice
   with exactly enough capacity for every cipher ID. This avoids repeated
   allocations during append.
3. The `for` loop walks `cfg.CipherSuites` in order.
4. `tls.CipherSuiteName(id)` converts the numeric cipher ID into its canonical
   Go/IANA name, for example `49199` becomes
   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
   - For an unknown ID, `tls.CipherSuiteName` returns a hexadecimal string such
     as `0xNNNN`; it does not return an error.
5. `strings.Join(cipherNames, ",")` produces one comma-separated argument
   value. An empty input slice produces the empty string.
6. `libgocrypto.TLSVersionToNameOrDie(cfg.MinVersion)` converts the numeric
   version into `VersionTLS10`, `VersionTLS11`, `VersionTLS12`, or
   `VersionTLS13`.
   - The `OrDie` suffix means the function panics if the version is not in its
     map. `NewSettings` therefore has an implicit precondition:
     `cfg.MinVersion` must be a valid Go TLS version. In NROP this is
     guaranteed because the config was built from a `TLSProfileSpec`.
7. The `Settings` value is constructed with the two mandatory fields.
8. If `len(cfg.CurvePreferences) > 0`, the decimal CSV is computed.
   - If the slice is nil or empty, `CurvePreferences` remains `""`.
   - The code intentionally uses `len(...) > 0` rather than checking
     `CurvePreferences != nil`, so nil and empty slices behave the same.
9. The completed `Settings` is returned.

#### Why it exists

The Go TLS runtime and the operand binaries need different representations:

- Go uses numeric `tls.VersionTLS12`, `[]uint16` cipher IDs, and
  `[]tls.CurveID`.
- RTE and the scheduler accept command-line strings such as
  `--metrics-tls-min-version=VersionTLS12`,
  `--metrics-tls-cipher-suites=TLS_ECDHE_...`, and
  `--metrics-tls-curve-preferences=4588,29,23,24`.

`NewSettings` is the single conversion point, so the manager, both controllers,
and all tests compute the same expected strings.

#### Input assumptions and failure modes

| Situation | Behavior |
|---|---|
| `cfg == nil` | Panics when accessing `cfg.CipherSuites`. Callers must pass a non-nil config. |
| `cfg.MinVersion == 0` | `TLSVersionToNameOrDie(0)` panics because no version name maps to zero. |
| `cfg.MinVersion` is an unknown non-zero value | Panics for the same reason. |
| `cfg.CipherSuites` is nil or empty | `CipherSuites` is `""`. |
| A cipher ID is unknown to Go | The field contains a `0xNNNN` string rather than a name. |
| Curve slice is nil or empty | `CurvePreferences` is `""`. |
| Curve slice has duplicates | Duplicates appear in the CSV; no deduplication occurs. |

#### Where it is used

| Call site | Purpose |
|---|---|
| `cmd/main.go:341` | Converts the startup `tls.Config` into `tlsSettings`. |
| `internal/controller/numaresourcesoperator_controller_test.go` | Builds expected RTE settings in controller tests. |
| `internal/controller/numaresourcesscheduler_controller_test.go` | Builds expected scheduler settings in controller tests. |
| `pkg/objectupdate/rte/rte_test.go` | Builds expected `Settings` values for argument tests. |
| `pkg/objectupdate/sched/sched_test.go` | Builds expected scheduler TLS settings. |
| `test/internal/tls/tls.go:210` | `RTESettingsFromClusterProfile` computes expected RTE flags from the live profile. |
| `test/e2e/tls/tls_1.go` | Derives settings from the live cluster profile for an E2E check. |
| `test/e2e/serial/tests/configuration.go:1910` | Computes expected RTE settings after changing the profile. |

### 2.5 Function `curveIDsToString`

Source: `pkg/objectupdate/tls/tls.go:62-70`.

```go
func curveIDsToString(ids []tls.CurveID) string {
	var sb strings.Builder
	for i, id := range ids {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.Itoa(int(id)))
	}
	return sb.String()
}
```

#### Line-by-line logic

1. The function is unexported; only `NewSettings` calls it.
2. `var sb strings.Builder` creates a zero-value builder. No capacity hint is
   given, which is fine for the very small curve lists used here.
3. The loop walks the curve IDs in input order.
4. For every element after the first (`i > 0`), it writes a comma before the
   number. This produces `a,b,c` without a trailing comma.
5. `strconv.Itoa(int(id))` converts the `tls.CurveID` (an unsigned 16-bit type)
   to its decimal representation. For example, `tls.X25519` becomes `"29"` and
   `tls.X25519MLKEM768` becomes `"4588"`.
6. It returns the built string. An empty or nil slice returns `""`.

#### Examples

| Input | Output |
|---|---|
| `[]tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}` | `"29,23,24"` |
| `[]tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}` | `"4588,29,23"` |
| `[]tls.CurveID{tls.X25519MLKEM768}` | `"4588"` |
| `nil` | `""` |

#### Why it uses decimal, not names

The operand flags expect the numeric IANA IDs, not the OpenShift group names.
For example, OpenShift says `X25519`, but RTE and the scheduler accept `29`.
Mapping from names to numeric IDs happens earlier in
`libgocrypto.TLSGroupsToCurveIDs`; this function only formats the final IDs.

### 2.6 Test file `pkg/objectupdate/tls/tls_test.go`

There are six test functions. They exercise `NewSettings` and
`Settings.String`; they do not test `curveIDsToString` directly.

#### `TestNewSettingsMinVersion`

Source: `tls_test.go:24-48`.

Local declarations:

```go
type testCase struct {
	version  uint16
	expected string
}

testCases := []testCase{
	{tls.VersionTLS10, "VersionTLS10"},
	{tls.VersionTLS11, "VersionTLS11"},
	{tls.VersionTLS12, "VersionTLS12"},
	{tls.VersionTLS13, "VersionTLS13"},
}
```

- `testCase.version` is the numeric input.
- `testCase.expected` is the expected string name.
- `testCases` covers all four supported versions.
- Each subtest builds a `tls.Config` with that `MinVersion` and one cipher.
- It asserts `s.MinVersion == tc.expected`.

What it proves: every supported numeric version maps to the canonical name.

What it does not prove: zero or unknown versions (both panic), or version
mapping without ciphers.

#### `TestNewSettingsCipherSuites`

Source: `tls_test.go:50-65`.

Local declarations:

```go
ciphers := []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}
```

- `ciphers` supplies two distinct TLS 1.2 cipher IDs.
- The test asserts the exact ordered CSV:
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.

What it proves: IDs become names, order is preserved, and the separator is a
single comma.

#### `TestNewSettingsCipherSuitesEmpty`

Source: `tls_test.go:67-75`.

- Builds a config with `MinVersion: tls.VersionTLS12` and no `CipherSuites`.
- Asserts `s.CipherSuites == ""`.

What it proves: nil cipher input produces an empty flag value, which downstream
code interprets as “delete the cipher flag”.

#### `TestNewSettingsCipherSuitesSingle`

Source: `tls_test.go:77-87`.

- Uses `tls.TLS_AES_128_GCM_SHA256`.
- Asserts exactly `TLS_AES_128_GCM_SHA256`.

What it proves: a single value has no leading or trailing comma, and TLS 1.3
cipher IDs are still name-converted even though Go does not allow configuring
them.

#### `TestNewSettings_WithCurvePreferences`

Source: `tls_test.go:89-145`.

Table type:

```go
tests := []struct {
	name           string
	curveIDs       []tls.CurveID
	wantCurvePrefs string
}{ ... }
```

Table fields:

- `name` is the subtest name.
- `curveIDs` is the input to `tls.Config.CurvePreferences`.
- `wantCurvePrefs` is the expected decimal CSV.

Cases:

| Case | Curves | Expected |
|---|---|---|
| Intermediate profile | X25519, P-256, P-384 | `29,23,24` |
| Modern profile with PQ | X25519MLKEM768, X25519, P-256 | `4588,29,23` |
| Empty curves (Legacy) | empty slice | `""` |
| Only PQ curve | X25519MLKEM768 | `4588` |
| Only FIPS-approved curves | P-256, P-384, P-521 | `23,24,25` |

Each subtest:

1. Builds a `tls.Config` with TLS 1.2, one cipher, and the table's curves.
2. Calls `NewSettings`.
3. Asserts `CurvePreferences` exactly.
4. Asserts `MinVersion` is not empty.
5. Asserts `CipherSuites` is not empty.

What it proves: decimal conversion, order preservation, empty handling, PQ
384-bit and 256-bit IDs, and the classic FIPS curves.

#### `TestSettings_String`

Source: `tls_test.go:147-179`.

Table fields:

- `name`
- `settings`
- `want`

Cases:

1. With curves, expecting all three fields.
2. Without curves, expecting the trailing `CipherSuites: ` space and no curve
   field.

What it proves: logging output format is stable.

#### Local variable inventory in the test file

| Test | Variable | Type / value | Purpose |
|---|---|---|---|
| `TestNewSettingsMinVersion` | `testCase` | local struct type | Pairs numeric version with expected name. |
| `TestNewSettingsMinVersion` | `testCase.version` | `uint16` | Numeric input. |
| `TestNewSettingsMinVersion` | `testCase.expected` | `string` | Expected name. |
| `TestNewSettingsMinVersion` | `testCases` | `[]testCase` | Four supported versions. |
| `TestNewSettingsMinVersion` | `tc` | `testCase` | Current subtest row. |
| `TestNewSettingsMinVersion` | `s` | `Settings` | Output under test. |
| `TestNewSettingsCipherSuites` | `ciphers` | `[]uint16` | Two cipher IDs. |
| `TestNewSettingsCipherSuites` | `s` | `Settings` | Output under test. |
| `TestNewSettingsCipherSuites` | `expected` | `string` | Exact expected CSV. |
| `TestNewSettingsCipherSuitesEmpty` | `s` | `Settings` | Output under test. |
| `TestNewSettingsCipherSuitesSingle` | `s` | `Settings` | Output under test. |
| `TestNewSettingsCipherSuitesSingle` | `expected` | `string` | Single cipher name. |
| `TestNewSettings_WithCurvePreferences` | anonymous struct fields `name`, `curveIDs`, `wantCurvePrefs` | `string`, `[]tls.CurveID`, `string` | Table schema. |
| `TestNewSettings_WithCurvePreferences` | `tests` | anonymous struct slice | Five curve cases. |
| `TestNewSettings_WithCurvePreferences` | `tt` | one table row | Current subtest. |
| `TestNewSettings_WithCurvePreferences` | `cfg` | `*tls.Config` | Input config. |
| `TestNewSettings_WithCurvePreferences` | `settings` | `Settings` | Output under test. |
| `TestSettings_String` | anonymous struct fields `name`, `settings`, `want` | `string`, `Settings`, `string` | Table schema. |
| `TestSettings_String` | `tests` | anonymous struct slice | Two formatting cases. |
| `TestSettings_String` | `tt` | one table row | Current subtest. |
| `TestSettings_String` | `got` | `string` | Actual output. |

`pkg/objectupdate/tls/tls.go` has **no package-level variables**. Its only
state is the fields of `Settings`, which are per-value.

#### Test coverage gaps in this package

The existing tests do not cover:

- Nil `*tls.Config` (panic).
- `MinVersion == 0` or unknown version (panic).
- Unknown cipher ID behavior (`0xNNNN`).
- Duplicate ciphers or duplicate curves.
- Nil versus empty curve slices as distinct cases.
- Direct unit tests of `curveIDsToString`.
- Interaction with `NewTLSConfigFromProfile`, especially the Modern/TLS 1.3
  empty-cipher path.

These gaps matter when changing formatting behavior, but they do not indicate
a bug in the current implementation.

### 2.7 How `Settings` is consumed by operand updaters

#### RTE: `rteupdate.DaemonSetArgs`

Source: `pkg/objectupdate/rte/rte.go:174-251`.

TLS-related logic:

```go
flags.SetOption("--metrics-mode", "httptls")
if metricsTLS.MinVersion != "" {
	flags.SetOption("--metrics-tls-min-version", metricsTLS.MinVersion)
} else {
	flags.Delete("--metrics-tls-min-version")
}
if metricsTLS.CipherSuites != "" {
	flags.SetOption("--metrics-tls-cipher-suites", metricsTLS.CipherSuites)
} else {
	flags.Delete("--metrics-tls-cipher-suites")
}
if metricsTLS.CurvePreferences != "" {
	flags.SetOption("--metrics-tls-curve-preferences", metricsTLS.CurvePreferences)
} else {
	flags.Delete("--metrics-tls-curve-preferences")
}
```

Behavior:

| `Settings` field | Non-empty | Empty |
|---|---|---|
| `MinVersion` | set `--metrics-tls-min-version=<value>` | delete the flag |
| `CipherSuites` | set `--metrics-tls-cipher-suites=<value>` | delete the flag |
| `CurvePreferences` | set `--metrics-tls-curve-preferences=<value>` | delete the flag |

The function always sets `--metrics-mode=httptls`, so RTE serves metrics over
TLS. At the end it writes the reconstructed argument list back with
`cnt.Args = flags.Argv()`.

Why delete instead of writing an empty value: an empty `--flag=` can be
rejected by a parser or can mean “explicitly empty”, while omitting the flag
lets RTE use its compiled defaults. This is especially important for a Custom
profile with no groups.

#### Scheduler: `schedupdate.DeploymentTLSSettings`

Source: `pkg/objectupdate/sched/sched.go:85-117`.

TLS-related logic:

```go
if tlsSettings.MinVersion != "" {
	flags.SetOption("--tls-min-version", tlsSettings.MinVersion)
} else {
	flags.Delete("--tls-min-version")
}
if tlsSettings.CipherSuites != "" {
	flags.SetOption("--tls-cipher-suites", tlsSettings.CipherSuites)
} else {
	flags.Delete("--tls-cipher-suites")
}
if tlsSettings.CurvePreferences != "" {
	flags.SetOption("--tls-curve-preferences", tlsSettings.CurvePreferences)
} else {
	flags.Delete("--tls-curve-preferences")
}
cnt.Args = flags.Argv()
```

Behavior is the same set-or-delete pattern with scheduler flag names.

#### Why both updaters are idempotent

`flagcodec.SetOption` replaces an existing value rather than appending a
duplicate, and `flagcodec.Delete` is a no-op when the flag is absent. Therefore
reconciling the same `Settings` repeatedly converges to the same argument list.
See `pkg/numaresourcesoperator/flagcodec` and its tests for the codec behavior.

---

## 3. `vendor/github.com/openshift/controller-runtime-common/pkg/tls/tls.go`

### 3.1 Package declaration and imports

```go
package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	"sigs.k8s.io/controller-runtime/pkg/client"
)
```

| Import | Why it is needed |
|---|---|
| `context` | Passes cancellation and deadlines to Kubernetes API calls. |
| `crypto/tls` | Uses `tls.Config`, `tls.CurveID`, and `tls.VersionTLS13`. |
| `errors` | Creates the sentinel `ErrCustomProfileNil`. |
| `fmt` | Wraps errors with context. |
| `configv1` | Provides `APIServer`, `TLSSecurityProfile`, `TLSProfileSpec`, TLS version constants, and the built-in `TLSProfiles` map. |
| `libgocrypto` | Converts min versions, cipher names, and TLS groups. |
| `client` | Reads the `APIServer` object through a controller-runtime client. |

### 3.2 Constant `APIServerName`

```go
const (
	// APIServerName is the name of the APIServer resource in the cluster.
	APIServerName = "cluster"
)
```

- OpenShift stores the cluster-wide configuration in a singleton `APIServer`
  object named `cluster`.
- It is cluster-scoped, so the namespace in the object key is empty.
- The constant is exported because tests and other packages need to build the
  same key, for example `client.ObjectKey{Name: ctrltls.APIServerName}`.

Used in:

- `FetchAPIServerTLSProfile`
- `FetchAPIServerTLSAdherencePolicy`
- `SecurityProfileWatcher.SetupWithManager` predicates
- `test/e2e/serial/tests/configuration.go:1862`

### 3.3 Package variables

#### `ErrCustomProfileNil`

```go
ErrCustomProfileNil = errors.New("custom TLS profile specified but Custom field is nil")
```

- A sentinel error returned by `GetTLSProfileSpec` when
  `spec.tlsSecurityProfile.type == "Custom"` but `spec.tlsSecurityProfile.custom`
  is nil.
- Callers can compare with `errors.Is(err, ctrltls.ErrCustomProfileNil)`.
- It signals an invalid API object: the type says “Custom” but no custom spec
  was supplied.
- NROP does not compare against it directly; `FetchAPIServerTLSProfile` wraps
  it and the manager exits at startup. The watcher returns it from
  `Reconcile`, which causes controller-runtime to retry.

#### `DefaultTLSCiphers`

```go
DefaultTLSCiphers = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers
```

- A package-level copy of the Intermediate profile's cipher slice.
- The slice header is copied, but the backing array is the same as the global
  `configv1.TLSProfiles` entry. It is not a deep copy.
- It is exported for consumers that need the OpenShift default cipher list
  without reading the API.
- NROP does not reference it. NROP always derives settings from the live
  `APIServer` profile.

#### `DefaultMinTLSVersion`

```go
DefaultMinTLSVersion = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion
```

- The Intermediate profile's minimum version, currently `VersionTLS12`.
- NROP does not reference it; `GetTLSProfileSpec` uses the whole Intermediate
  profile instead.

#### `HTTP2NextProtos`

```go
HTTP2NextProtos = []string{"h2", "http/1.1"}
```

- ALPN protocol list for HTTP/2 with HTTP/1.1 fallback.
- Intended to be passed to `SetNextProtos`.
- Exported slice; callers can mutate it, so treat it as read-only.
- NROP does not use it. `cmd/main.go` has its own `webhookTLSOpts` helper for
  the webhook's HTTP/2 switch.

#### `HTTP1NextProtos`

```go
HTTP1NextProtos = []string{"http/1.1"}
```

- ALPN list restricted to HTTP/1.1.
- The comment explains the defense-in-depth rationale against HTTP/2 Rapid
  Reset (CVE-2023-44487, CVE-2023-39325), in addition to the primary Go and
  `golang.org/x/net` fixes.
- NROP does not use it. The manager's metrics server uses
  controller-runtime's defaults, and the webhook uses `webhookTLSOpts`, which
  sets `NextProtos = []string{"http/1.1"}` when HTTP/2 is disabled.

### 3.4 Function `FetchAPIServerTLSProfile`

Source: `vendor/.../pkg/tls/tls.go:56-72`.

```go
func FetchAPIServerTLSProfile(ctx context.Context, k8sClient client.Client) (configv1.TLSProfileSpec, error) {
	apiServer := &configv1.APIServer{}
	key := client.ObjectKey{Name: APIServerName}

	if err := k8sClient.Get(ctx, key, apiServer); err != nil {
		return configv1.TLSProfileSpec{}, fmt.Errorf("failed to get APIServer %q: %w", key.String(), err)
	}

	profile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		return configv1.TLSProfileSpec{}, fmt.Errorf("failed to get TLS profile from APIServer %q: %w", key.String(), err)
	}

	return profile, nil
}
```

#### Line-by-line logic

1. `ctx` carries cancellation. In NROP it is the manager setup context; a
   failure means the operator cannot determine TLS policy and should exit.
2. `k8sClient` is any controller-runtime client, including a fake client in
   tests.
3. Allocates an empty `configv1.APIServer`.
4. Builds `client.ObjectKey{Name: "cluster"}`. Namespace stays empty because
   `APIServer` is cluster-scoped.
5. Reads the object. On any error, returns a zero `TLSProfileSpec` and a wrapped
   error containing the object key.
   - “Not found” is treated as a hard error here. This differs from
     `SecurityProfileWatcher.Reconcile`, which tolerates deletion.
6. Calls `GetTLSProfileSpec` with the pointer field
   `apiServer.Spec.TLSSecurityProfile`. A nil pointer is valid input and means
   “use the default”.
7. If profile resolution fails, returns a zero spec and a wrapped error.
   The two wrapping layers let logs distinguish API read failure from invalid
   profile content.
8. Returns the resolved `TLSProfileSpec` value.

#### Why it exists

It hides the two-step “read APIServer, resolve profile” sequence and gives every
component the same defaulting behavior. Without it, each caller would need to
know that `Old`, `Intermediate`, and `Modern` are global map entries rather than
fields on the API object.

#### Where it is used

| Call site | Purpose |
|---|---|
| `cmd/main.go:326` | Reads the profile once at operator startup. Any error exits the process. |
| `test/internal/tls/tls.go:195` | `GetClusterTLSProfile` reads the live profile for E2E assertions. |

#### Testing notes

- Unit test with a fake client containing an `APIServer` named `cluster` and
  each profile type.
- Test missing APIServer: expect a wrapped error and zero spec.
- Test Custom with nil `Custom`: expect an error wrapping
  `ErrCustomProfileNil`.

### 3.5 Function `FetchAPIServerTLSAdherencePolicy`

Source: `vendor/.../pkg/tls/tls.go:74-84`.

```go
func FetchAPIServerTLSAdherencePolicy(ctx context.Context, k8sClient client.Client) (configv1.TLSAdherencePolicy, error) {
	apiServer := &configv1.APIServer{}
	key := client.ObjectKey{Name: APIServerName}

	if err := k8sClient.Get(ctx, key, apiServer); err != nil {
		return configv1.TLSAdherencePolicyNoOpinion, fmt.Errorf("failed to get APIServer %q: %w", key.String(), err)
	}

	return apiServer.Spec.TLSAdherence, nil
}
```

#### Line-by-line logic

1. Allocates an empty `APIServer`.
2. Builds the `cluster` key.
3. Reads the object.
4. On error, returns `TLSAdherencePolicyNoOpinion` **and a non-nil error**.
   The default value is only meaningful when the caller decides to ignore the
   error; callers should normally treat the error as authoritative.
5. On success, returns `apiServer.Spec.TLSAdherence`.
   - If the field is omitted, Go's zero value is `""`, which is exactly
     `TLSAdherencePolicyNoOpinion`.
   - `NoOpinion` is documented to behave like
     `LegacyAdheringComponentsOnly`.

#### Adherence policy values

| Value | Meaning |
|---|---|
| `""` (`NoOpinion`) | Field omitted; platform treats it as legacy behavior. |
| `LegacyAdheringComponentsOnly` | Only components that already honor the cluster profile continue to do so. |
| `StrictAllComponents` | All components must honor the cluster profile unless they have a component-specific override. |

#### Why it exists

TLS adherence is a cluster-level policy separate from the TLS profile: it says
which components must honor the profile. Components that need to react when an
administrator changes that policy can read it with this function instead of
duplicating the `APIServer/cluster` lookup.

#### Use in NROP

NROP does **not** call this function. `cmd/main.go` does not read
`TLSAdherence`, and `SecurityProfileWatcher` is constructed without an initial
adherence value or an adherence callback.

Consequences:

- NROP's TLS behavior is determined solely by `TLSSecurityProfile`.
- If `TLSAdherence` changes alone, the watcher will notice it on the next
  reconcile, call a nil callback, and update its internal baseline. No restart
  occurs.
- If NROP later needs to react to adherence changes, it must set
  `InitialTLSAdherencePolicy` from this function and provide
  `OnAdherencePolicyChange`.

### 3.6 Function `GetTLSProfileSpec`

Source: `vendor/.../pkg/tls/tls.go:86-117`.

```go
func GetTLSProfileSpec(profile *configv1.TLSSecurityProfile) (configv1.TLSProfileSpec, error) {
	defaultProfile := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	if profile == nil || profile.Type == "" {
		return defaultProfile, nil
	}

	profileType := profile.Type

	if profileType != configv1.TLSProfileCustomType {
		if tlsConfig, ok := configv1.TLSProfiles[profileType]; ok {
			return *tlsConfig, nil
		}

		return defaultProfile, nil
	}

	if profile.Custom == nil {
		return configv1.TLSProfileSpec{}, ErrCustomProfileNil
	}

	return profile.Custom.TLSProfileSpec, nil
}
```

#### Line-by-line logic

1. `defaultProfile := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]`
   dereferences the global Intermediate entry and copies the struct value.
   - The `Ciphers` and `Groups` slices inside the copy still point to the
     global map's backing arrays. The function does not deep-copy them.
   - The map lookup is assumed to succeed; a missing built-in entry would panic.
2. If the caller passed a nil profile pointer or the union type is empty, return
   the default. This is how an omitted `tlsSecurityProfile` becomes
   Intermediate.
3. Copy the type into a local variable for readability.
4. If the type is not `Custom`, look it up in the built-in map.
5. If found, return a copy of the map value. The built-in `Old`, `Intermediate`,
   and `Modern` API structs are empty markers; the actual ciphers/groups live in
   this map, not in `profile.Old`, `profile.Intermediate`, or `profile.Modern`.
6. If the type is unknown, silently return the default. The Type field has
   API enum validation, so this is defensive behavior rather than a supported
   input.
7. If the type is `Custom` but the `Custom` pointer is nil, return a zero spec
   and `ErrCustomProfileNil`.
8. Otherwise return the embedded `TLSProfileSpec` from the Custom object.

#### Truth table

| Input | Result |
|---|---|
| `nil` | Intermediate profile |
| `&TLSSecurityProfile{}` (`Type == ""`) | Intermediate profile |
| `Type: Old` | `TLSProfiles[Old]` |
| `Type: Intermediate` | `TLSProfiles[Intermediate]` |
| `Type: Modern` | `TLSProfiles[Modern]` |
| Unknown type | Intermediate profile |
| `Type: Custom`, `Custom == nil` | Zero spec + `ErrCustomProfileNil` |
| `Type: Custom`, `Custom != nil` | `Custom.TLSProfileSpec` |

#### Built-in profile values in this snapshot

| Profile | Min version | Groups | Curve CSV | Cipher notes |
|---|---|---|---|---|
| Old | `VersionTLS10` | `X25519MLKEM768, X25519, secp256r1, secp384r1` | `4588,29,23,24` | 24 ciphers including legacy CBC and RSA key exchange. |
| Intermediate | `VersionTLS12` | same | `4588,29,23,24` | 9 ciphers: 3 TLS 1.3 names plus 6 ECDHE AEAD suites. |
| Modern | `VersionTLS13` | same | `4588,29,23,24` | 3 TLS 1.3 cipher names. |

The built-in profiles intentionally share the same group list in this
snapshot. That is why a serial E2E test that switches between built-in profiles
does not prove a curve value change.

#### Aliasing warning

Because returned slices alias the global map or the caller's Custom object:

- Callers must not mutate `Ciphers` or `Groups` on the returned spec.
- A deep copy would be required if a caller wanted to modify them safely.
- NROP only reads them, so the alias is harmless in the current code.

#### Where it is used

| Call site | Purpose |
|---|---|
| `FetchAPIServerTLSProfile` | Resolves the API object's profile. |
| `SecurityProfileWatcher.Reconcile` | Resolves the current profile on every event for comparison. |

There is no direct NROP unit test for `GetTLSProfileSpec`; it is exercised
indirectly through `FetchAPIServerTLSProfile` and the watcher.

### 3.7 Function `NewTLSConfigFromProfile`

Source: `vendor/.../pkg/tls/tls.go:119-157`.

```go
func NewTLSConfigFromProfile(profile configv1.TLSProfileSpec) (tlsConfig func(*tls.Config), unsupported []string) {
	minVersion := libgocrypto.TLSVersionOrDie(string(profile.MinTLSVersion))
	cipherSuites, unsupportedCiphers := cipherCodes(profile.Ciphers)
	curvePrefs, unsupportedGroups := libgocrypto.TLSGroupsToCurveIDs(profile.Groups)

	unsupported = unsupportedCiphers
	for _, g := range unsupportedGroups {
		unsupported = append(unsupported, string(g))
	}

	return func(tlsConf *tls.Config) {
		tlsConf.MinVersion = minVersion
		if len(curvePrefs) > 0 {
			tlsConf.CurvePreferences = curvePrefs
		}

		if minVersion != tls.VersionTLS13 {
			tlsConf.CipherSuites = cipherSuites
		}
	}, unsupported
}
```

#### Line-by-line logic

1. The function accepts a `TLSProfileSpec` by value. The slices inside it are
   read but not modified.
2. `libgocrypto.TLSVersionOrDie(string(profile.MinTLSVersion))` converts the
   API version name to the Go numeric version.
   - Empty string means “unspecified”. `library-go` maps empty to its default,
     which is `tls.VersionTLS12`.
   - Any unknown non-empty name panics. API enum validation normally prevents
     this.
3. `cipherCodes(profile.Ciphers)` converts every cipher name to a `uint16` and
   collects names it could not convert.
4. `libgocrypto.TLSGroupsToCurveIDs(profile.Groups)` maps every OpenShift group
   to a `tls.CurveID` and collects unknown groups.
5. `unsupported = unsupportedCiphers` starts the returned unsupported list with
   cipher names.
6. The loop appends unsupported group names as strings. The final list mixes
   cipher names and group names; it is intended for logging, not
   programmatic dispatch.
7. The function returns a closure and the unsupported list.

#### Closure logic

The closure is a `func(*tls.Config)` suitable for controller-runtime's
`TLSOpts`. It captures `minVersion`, `cipherSuites`, and `curvePrefs`.

1. Always sets `tlsConf.MinVersion`.
2. If there is at least one recognized curve, sets `CurvePreferences`.
   - If the list is empty, it leaves the existing field untouched. On a fresh
     `&tls.Config{}` this means nil, so Go uses its defaults.
   - This is not a “clear” operation. Reusing a config that already had curves
     would retain them. NROP always applies the closure to a fresh config, so
     this does not occur.
3. If the minimum version is not TLS 1.3, sets `CipherSuites` to the converted
   list.
   - Setting an empty slice is intentional when the profile has no supported
     ciphers; Go then falls back to its default cipher list for TLS 1.0-1.2.
4. If the minimum version is TLS 1.3, it does **not** set `CipherSuites`,
   because Go's TLS 1.3 cipher suites are not configurable. The captured
   `cipherSuites` value is unused in that branch.
   - The profile's TLS 1.3 cipher names are still passed through `cipherCodes`
     and may appear in the unsupported list if the binary does not know them.

#### Field behavior table

| Profile property | Closure action |
|---|---|
| `MinTLSVersion` always | Set `tlsConf.MinVersion`. |
| `Groups` non-empty and recognized | Set `tlsConf.CurvePreferences` to mapped IDs. |
| `Groups` empty | Leave `CurvePreferences` unchanged (nil on a fresh config). |
| `Groups` contains unknown names | Drop unknown names; set recognized ones; return unknown names in `unsupported`. |
| `MinTLSVersion != VersionTLS13` | Set `tlsConf.CipherSuites` to converted IDs. |
| `MinTLSVersion == VersionTLS13` | Do not set `tlsConf.CipherSuites`. |
| `Ciphers` contains unknown names | Drop unknown names; return them in `unsupported`. |
| All ciphers unknown and min != 1.3 | Set a nil/empty `CipherSuites` slice; Go then uses its default ciphers. |

#### Why it exists

It centralizes OpenShift profile semantics:

- Built-in profile selection is already resolved by `GetTLSProfileSpec`.
- Cipher names can be OpenSSL-style or IANA-style.
- Go requires numeric cipher IDs.
- Go's TLS 1.3 cipher configuration rule must be honored.
- OpenShift group names must become Go curve IDs, in the same order.
- Unsupported entries must be reported but must not prevent the rest of the
  profile from being applied.

#### Where it is used

| Call site | Purpose |
|---|---|
| `cmd/main.go:332` | Builds the callback used for operator metrics, webhook, and `objtls.NewSettings`. |
| `test/internal/tls/tls.go:354` | `tlsConfigFromProfileSpec` builds a config for tests. |
| `test/e2e/tls/tls_1.go:19` | Derives a config from the live profile. |
| `test/e2e/serial/tests/configuration.go:1907` | Builds expected settings for a newly applied profile. |

#### Example

```go
profile := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
apply, unsupported := ctrltls.NewTLSConfigFromProfile(*profile)

cfg := &tls.Config{}
apply(cfg)

fmt.Println(cfg.MinVersion)                 // 771 (VersionTLS12)
fmt.Println(cfg.CurvePreferences)           // [4588 29 23 24]
fmt.Println(len(cfg.CipherSuites))          // profile-dependent
fmt.Println(unsupported)                    // usually empty
```

### 3.8 Function `SetNextProtos`

Source: `vendor/.../pkg/tls/tls.go:159-175`.

```go
func SetNextProtos(protos ...string) func(*tls.Config) {
	var p []string
	for _, proto := range protos {
		if proto != "" {
			p = append(p, proto)
		}
	}
	return func(c *tls.Config) {
		c.NextProtos = p
	}
}
```

#### Line-by-line logic

1. Variadic parameter `protos` accepts zero or more ALPN protocol names.
2. `var p []string` starts nil.
3. The loop copies every non-empty string into `p`.
   - Empty strings are silently ignored. This allows callers to conditionally
     include a protocol without building a separate list.
4. The closure assigns `c.NextProtos = p`.
   - All empty inputs leave `p` nil, which sets `NextProtos` to nil.
5. The closure captures the already-built slice. Later changes to the caller's
   original variadic backing array do not affect it, but the returned closure
   and `p` share the same backing array if the caller mutated through another
   reference; normal use treats it as immutable.

#### Why it exists

It gives callers a composable `TLSOpts` function for ALPN negotiation without
requiring them to write a closure. Examples from the source comment:

```go
// HTTP/1.1 only
ctrltls.SetNextProtos("http/1.1")

// HTTP/2 with fallback
ctrltls.SetNextProtos("h2", "http/1.1")

// Well-known lists
ctrltls.SetNextProtos(ctrltls.HTTP1NextProtos...)
ctrltls.SetNextProtos(ctrltls.HTTP2NextProtos...)
```

#### Use in NROP

NROP does not call `SetNextProtos`. `cmd/main.go:633-643` defines a local
`webhookTLSOpts(enableHTTP2 bool)` function:

```go
func webhookTLSOpts(enableHTTP2 bool) []func(config *tls.Config) {
	disableHTTP2 := func(c *tls.Config) {
		klog.InfoS("HTTP2 serving for webhook", "enabled", enableHTTP2)
		if enableHTTP2 {
			return
		}
		c.NextProtos = []string{"http/1.1"}
	}

	return []func(config *tls.Config){disableHTTP2}
}
```

This local function is equivalent in effect for HTTP/1.1-only mode but does not
use the exported helpers. The webhook is disabled by default in the shipped
bundle and is out of scope for the TLS curve work.

### 3.9 Function `cipherCode`

Source: `vendor/.../pkg/tls/tls.go:177-197`.

```go
func cipherCode(cipher string) uint16 {
	if code, err := libgocrypto.CipherSuite(cipher); err == nil {
		return code
	}

	ianaCiphers := libgocrypto.OpenSSLToIANACipherSuites([]string{cipher})
	if len(ianaCiphers) == 1 {
		if code, err := libgocrypto.CipherSuite(ianaCiphers[0]); err == nil {
			return code
		}
	}

	return 0
}
```

#### Line-by-line logic

1. First try the name as an IANA/Go name with
   `libgocrypto.CipherSuite`. This is an exact map lookup.
   - If it succeeds, return the numeric ID immediately.
2. If the direct lookup fails, call `OpenSSLToIANACipherSuites` with a
   one-element slice.
   - This maps OpenSSL names such as `ECDHE-RSA-AES128-GCM-SHA256` to IANA
     names such as `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
   - Unknown names are silently dropped, so the result can be empty.
3. If exactly one IANA name was produced, try `CipherSuite` again.
4. If that succeeds, return the numeric ID.
5. Otherwise return `0` as a sentinel meaning “unsupported”.
   - `0` is not a valid TLS cipher ID.

#### Input rules

- Matching is exact and case-sensitive. There is no trimming or normalization.
- Both IANA names and OpenSSL aliases are accepted.
- A name that is in neither map is unsupported.
- `cipherCode` is unexported and only used by `cipherCodes`.

#### Testing notes

Because it is unexported, unit tests must be in package `tls`, not `tls_test`.
Useful cases:

| Input | Expected |
|---|---|
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | non-zero Go ID |
| `ECDHE-RSA-AES128-GCM-SHA256` | same non-zero Go ID |
| `BOGUS-CIPHER` | `0` |
| Empty string | `0` |
| Lowercase variant | `0` (not normalized) |

### 3.10 Function `cipherCodes`

Source: `vendor/.../pkg/tls/tls.go:199-214`.

```go
func cipherCodes(ciphers []string) (codes []uint16, unsupportedCiphers []string) {
	for _, cipher := range ciphers {
		code := cipherCode(cipher)
		if code == 0 {
			unsupportedCiphers = append(unsupportedCiphers, cipher)
			continue
		}

		codes = append(codes, code)
	}

	return codes, unsupportedCiphers
}
```

#### Line-by-line logic

1. Named return values start as nil slices.
2. Iterate over the input names in order.
3. Convert each name through `cipherCode`.
4. If the result is `0`, append the original name to `unsupportedCiphers` and
   skip it.
5. Otherwise append the numeric code to `codes`.
6. Return both slices.

#### Properties

- Order of supported ciphers is preserved.
- Duplicates are preserved.
- Unsupported names are preserved in their original order.
- An all-unsupported input returns nil `codes` and a populated unsupported
  list.
- An empty input returns nil for both.

#### Why it exists

It separates per-value conversion from list handling. `cipherCode` knows how to
resolve one name; `cipherCodes` applies that rule to the whole profile, keeps
the supported values in order, and preserves the names that were dropped so the
operator can log them.

#### Where it is used

Only `NewTLSConfigFromProfile` calls it. The returned unsupported names are
logged by `cmd/main.go`:

```go
tlsConfig, unsupported := ctrltls.NewTLSConfigFromProfile(tlsSecurityProfileSpec)
if len(unsupported) > 0 {
	klog.InfoS("TLS profile configuration contains unsupported ciphers or groups that will be ignored", "unsupported", unsupported)
}
```

### 3.11 Dependency reference: `library-go` helpers

These functions are outside the requested directories but determine the
behavior of the code above. They are all in
`vendor/github.com/openshift/library-go/pkg/crypto/crypto.go`.

#### `TLSVersionOrDie`

Source: `library-go/pkg/crypto/crypto.go:95-101`.

```go
func TLSVersionOrDie(versionName string) uint16 {
	version, err := TLSVersion(versionName)
	if err != nil {
		panic(err)
	}
	return version
}
```

- Delegates to `TLSVersion`.
- `TLSVersion("")` returns `DefaultTLSVersion()`, which is `tls.VersionTLS12`.
- `TLSVersion` looks up an exact name in `goTLSVersions`.
- Unknown name returns an error; `OrDie` panics.
- Used by `NewTLSConfigFromProfile`.

#### `TLSVersionToNameOrDie`

Source: `library-go/pkg/crypto/crypto.go:69-84`.

- Iterates `goTLSVersions` looking for a matching numeric value.
- Panics if no match or multiple matches.
- Returns the canonical name.
- Used by `objtls.NewSettings`.

#### `CipherSuite`

Source: `library-go/pkg/crypto/crypto.go:266-272`.

```go
func CipherSuite(cipherName string) (uint16, error) {
	if cipher, ok := goCipherSuites[cipherName]; ok {
		return cipher, nil
	}
	return 0, fmt.Errorf("unknown cipher name %q", cipherName)
}
```

- Exact IANA/Go name lookup.
- Returns `0` plus an error for unknown names.
- Used by `cipherCode`.

#### `OpenSSLToIANACipherSuites`

Source: `library-go/pkg/crypto/crypto.go:353-367`.

- Iterates the input.
- Looks each name up in `openSSLToIANACiphers`.
- Appends the mapped name when found.
- Silently drops unknown names, logging at verbosity 4.
- Used by `cipherCode`.

#### `TLSGroupToCurveID`

Source: `library-go/pkg/crypto/crypto.go:374-377`.

- Exact map lookup from `configv1.TLSGroup` to `tls.CurveID`.
- Returns `(0, false)` for unknown groups.
- Mapping:

| OpenShift group | Go constant | Decimal |
|---|---|---:|
| `X25519` | `tls.X25519` | 29 |
| `secp256r1` | `tls.CurveP256` | 23 |
| `secp384r1` | `tls.CurveP384` | 24 |
| `secp521r1` | `tls.CurveP521` | 25 |
| `X25519MLKEM768` | `tls.X25519MLKEM768` | 4588 |
| `SecP256r1MLKEM768` | `tls.SecP256r1MLKEM768` | 4587 |
| `SecP384r1MLKEM1024` | `tls.SecP384r1MLKEM1024` | 4589 |

#### `TLSGroupsToCurveIDs`

Source: `library-go/pkg/crypto/crypto.go:379-396`.

- Iterates groups in order.
- Calls `TLSGroupToCurveID`.
- Appends recognized IDs to `curves`.
- Appends unrecognized group names to `unrecognized`.
- Does not sort or deduplicate.
- Returns both slices.
- Used by `NewTLSConfigFromProfile`.

#### `ValidTLSGroups`

Source: `library-go/pkg/crypto/crypto.go:398-408`.

- Builds a slice of all keys in `tlsGroupToCurveID`.
- Sorts alphabetically with `slices.SortFunc`.
- Useful for validation or documentation tests.
- NROP does not call it.

### 3.12 Behavior summary tables

#### Cipher handling

| Input form | Direct IANA lookup | OpenSSL conversion | Result |
|---|---|---|---|
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | yes | not needed | numeric ID |
| `ECDHE-RSA-AES128-GCM-SHA256` | no | yes | numeric ID |
| `TLS_AES_128_GCM_SHA256` | yes | not needed | numeric ID |
| Unknown string | no | no mapping | `0`, added to unsupported |
| Empty string | no | no mapping | `0`, added to unsupported |

#### Group handling

| Input | Curve slice | Unsupported |
|---|---|---|
| `X25519`, `secp256r1` | `[29, 23]` | empty |
| `X25519MLKEM768`, `X25519` | `[4588, 29]` | empty |
| `bogus-group` | empty | `[bogus-group]` |
| empty/nil | empty | empty |

#### TLS 1.3 behavior

| Profile | `MinVersion` | `tlsConf.CipherSuites` after closure | `objtls.Settings.CipherSuites` |
|---|---|---|---|
| Old | TLS 1.0 | converted list | comma-separated names |
| Intermediate | TLS 1.2 | converted list | comma-separated names |
| Modern | TLS 1.3 | untouched/nil | `""` |
| Custom TLS 1.3 | TLS 1.3 | untouched/nil | `""` |
| Custom TLS 1.2 with unsupported-only ciphers | TLS 1.2 | empty slice | `""` |

`CurvePreferences` is independent of the TLS version and is set for TLS 1.2
and TLS 1.3 whenever the profile has groups.

---

## 4. `vendor/github.com/openshift/controller-runtime-common/pkg/tls/controller.go`

### 4.1 Package declaration and imports

```go
package tls

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)
```

| Import | Why it is needed |
|---|---|
| `context` | Reconcile context and callback context. |
| `fmt` | Wraps setup and reconcile errors. |
| `reflect` | Deep-compares TLS profile specs, including slices. |
| `logr` | Return type of the custom log constructor. |
| `configv1` | `APIServer`, `TLSProfileSpec`, and `TLSAdherencePolicy`. |
| `apierrors` | Detects `NotFound` during reconcile. |
| `ptr` | Creates the `*bool` for `NeedLeaderElection: ptr.To(false)`. |
| `ctrl` | Manager, request, and result types; controller builder entry point. |
| `builder` | Supplies watch predicates. |
| `client` | Embedded client in the watcher struct. |
| `controller` | Controller options such as leader election. |
| `event` | Create/update/delete/generic event types for predicates. |
| `log` | Builds a logger from the reconcile context. |
| `predicate` | Event filters. |
| `reconcile` | Request type used by the log constructor. |

### 4.2 Type `SecurityProfileWatcher`

Source: `vendor/.../pkg/tls/controller.go:38-72`.

```go
type SecurityProfileWatcher struct {
	client.Client

	InitialTLSProfileSpec configv1.TLSProfileSpec
	InitialTLSAdherencePolicy configv1.TLSAdherencePolicy
	OnProfileChange func(ctx context.Context, oldTLSProfileSpec, newTLSProfileSpec configv1.TLSProfileSpec)
	OnAdherencePolicyChange func(ctx context.Context, oldTLSAdherencePolicy, newTLSAdherencePolicy configv1.TLSAdherencePolicy)
}
```

#### Embedded field

| Field | Meaning |
|---|---|
| `client.Client` | Embedded controller-runtime client. Embedding promotes `Get`, `List`, and other client methods to the watcher. `Reconcile` calls `r.Get`. The caller must set it; a nil client would panic or fail at runtime. |

#### Explicit fields

| Field | Type | Meaning | NROP usage |
|---|---|---|---|
| `InitialTLSProfileSpec` | `configv1.TLSProfileSpec` | Baseline profile captured at startup, then updated after each detected change. | Set from `tlsSecurityProfileSpec`. |
| `InitialTLSAdherencePolicy` | `configv1.TLSAdherencePolicy` | Baseline adherence policy for change detection. | Not set; zero value `""`/`NoOpinion`. |
| `OnProfileChange` | `func(context.Context, configv1.TLSProfileSpec, configv1.TLSProfileSpec)` | Called with `(ctx, old, new)` when the profile differs from the baseline. | Set to a function that logs and calls `cancel()`. |
| `OnAdherencePolicyChange` | `func(context.Context, configv1.TLSAdherencePolicy, configv1.TLSAdherencePolicy)` | Called with `(ctx, old, new)` when adherence differs. | Not set (nil). |

#### Important state semantics

- `InitialTLSProfileSpec` is not truly “initial” after the first change: the
  controller overwrites it with the new value so the next reconciliation
  compares against the latest observed state.
- The fields are plain struct fields with no mutex. This relies on
  controller-runtime serializing reconciles for this controller. With the
  default `MaxConcurrentReconciles == 1`, that is true. Raising concurrency
  without synchronization could race.
- The callback is invoked synchronously inside `Reconcile`. A slow callback
  blocks that reconcile.
- If the callback is nil, change detection still updates the baseline. A nil
  callback is safe.

### 4.3 Method `SetupWithManager`

Source: `vendor/.../pkg/tls/controller.go:74-113`.

```go
func (r *SecurityProfileWatcher) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("tlssecurityprofilewatcher").
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		For(&configv1.APIServer{}, builder.WithPredicates(
			predicate.Funcs{
				CreateFunc: func(e event.CreateEvent) bool {
					return e.Object.GetName() == APIServerName
				},
				UpdateFunc: func(e event.UpdateEvent) bool {
					return e.ObjectNew.GetName() == APIServerName
				},
				DeleteFunc: func(e event.DeleteEvent) bool {
					return e.Object.GetName() == APIServerName
				},
				GenericFunc: func(e event.GenericEvent) bool {
					return e.Object.GetName() == APIServerName
				},
			},
		)).
		WithLogConstructor(func(_ *reconcile.Request) logr.Logger {
			return mgr.GetLogger().WithValues(
				"controller", "tlssecurityprofilewatcher",
			)
		}).
		Complete(r); err != nil {
		return fmt.Errorf("could not set up controller for TLS security profile watcher: %w", err)
	}

	return nil
}
```

#### Line-by-line logic

1. The method is called once during manager startup.
2. `ctrl.NewControllerManagedBy(mgr)` starts a builder bound to the manager.
3. `.Named("tlssecurityprofilewatcher")` gives the controller a stable name for
   metrics, logs, and cache identity.
4. `.WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)})`
   explicitly disables leader election for this controller.
   - Every manager replica runs the watcher, not only the leader.
   - This is intentional: every replica must restart itself when the profile
     changes, otherwise a standby could come up with stale TLS settings.
   - It also means a profile change can restart all replicas at roughly the
     same time.
5. `.For(&configv1.APIServer{}, ...)` watches the cluster-scoped APIServer
   resource as the primary object.
6. The predicate functions filter events to the singleton named `cluster`:
   - Create: `e.Object.GetName() == "cluster"`.
   - Update: `e.ObjectNew.GetName() == "cluster"`. The predicate checks the
     new object; a rename of a different object to `cluster` would pass, but
     Kubernetes does not support renaming objects.
   - Delete: `e.Object.GetName() == "cluster"`.
   - Generic: `e.Object.GetName() == "cluster"`.
7. `.WithLogConstructor(...)` replaces controller-runtime's default
   per-request logger. The comment says the default is very chatty for this
   high-frequency global object. It returns the manager logger with
   `controller=tlssecurityprofilewatcher`.
8. `.Complete(r)` registers `r` as the reconciler.
9. Any builder error is wrapped and returned. `cmd/main.go` treats it as fatal.

#### Event matrix

| Event | Predicate passes when | Result |
|---|---|---|
| Create | object name is `cluster` | Reconcile. |
| Update | new object name is `cluster` | Reconcile. |
| Delete | object name is `cluster` | Reconcile; `Get` returns NotFound and Reconcile returns nil. |
| Generic | object name is `cluster` | Reconcile. |
| Any other object | name differs | Filtered out. |

Because `APIServer` is cluster-scoped and the API guarantees a singleton named
`cluster`, in practice every event for the object passes.

Predicate callback variables:

| Variable | Type | Purpose |
|---|---|---|
| `e` | `event.CreateEvent` / `event.UpdateEvent` / `event.DeleteEvent` / `event.GenericEvent` | Event being filtered. |
| `e.Object` | `client.Object` | Old/current object for create, delete, and generic events. |
| `e.ObjectNew` | `client.Object` | New object for update events. |

The `WithLogConstructor` argument `_ *reconcile.Request` is intentionally
ignored; the manager logger is used instead of a per-request logger.

### 4.4 Method `Reconcile`

Source: `vendor/.../pkg/tls/controller.go:115-176`.

```go
func (r *SecurityProfileWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx, "name", req.Name)

	logger.V(1).Info("Reconciling APIServer TLS profile")
	defer logger.V(1).Info("Finished reconciling APIServer TLS profile")

	apiServer := &configv1.APIServer{}
	if err := r.Get(ctx, req.NamespacedName, apiServer); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get APIServer %s: %w", req.NamespacedName.String(), err)
	}

	currentTLSProfileSpec, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get TLS profile from APIServer %s: %w", req.NamespacedName.String(), err)
	}

	if tlsProfileChanged := !reflect.DeepEqual(r.InitialTLSProfileSpec, currentTLSProfileSpec); tlsProfileChanged {
		if r.OnProfileChange != nil {
			r.OnProfileChange(ctx, r.InitialTLSProfileSpec, currentTLSProfileSpec)
		}
		r.InitialTLSProfileSpec = currentTLSProfileSpec
	}

	if tlsAdherencePolicyChanged := r.InitialTLSAdherencePolicy != apiServer.Spec.TLSAdherence; tlsAdherencePolicyChanged {
		if r.OnAdherencePolicyChange != nil {
			r.OnAdherencePolicyChange(ctx, r.InitialTLSAdherencePolicy, apiServer.Spec.TLSAdherence)
		}
		r.InitialTLSAdherencePolicy = apiServer.Spec.TLSAdherence
	}

	return ctrl.Result{}, nil
}
```

#### Line-by-line logic

1. `logger := log.FromContext(ctx, "name", req.Name)` builds a logger with the
   APIServer name.
2. Logs at verbosity 1 that reconciliation started.
3. Defers a matching “finished” log, so it appears even on an early return.
4. Allocates an empty `APIServer`.
5. Reads the object using `req.NamespacedName`.
6. If the read fails with `NotFound`:
   - Returns an empty result and nil error.
   - No requeue, no callback.
   - This covers deletion or a stale event for an object that no longer exists.
7. Any other read error is wrapped and returned. Controller-runtime retries with
   backoff.
8. Resolves the current profile with `GetTLSProfileSpec`.
   - A nil profile pointer or empty type becomes Intermediate.
   - A Custom profile with nil `Custom` returns `ErrCustomProfileNil`.
9. On resolution error, returns a wrapped error, causing retries. A malformed
   Custom profile keeps retrying until an administrator fixes it.
10. Compares the baseline with the current spec using `reflect.DeepEqual`.
    - This compares struct fields recursively, including slice contents and
      order.
    - Reordering the same group or cipher set counts as a change.
    - Nil and empty slices are different to `DeepEqual`.
11. If changed and `OnProfileChange` is non-nil, calls it with the old baseline
    and current spec. The callback receives the resolved specs, not the raw
    API objects.
12. Updates `InitialTLSProfileSpec` to the current spec.
    - This happens even if the callback is nil.
    - If the callback panics, this assignment is not reached.
13. Compares adherence policy with the API field using `!=`. It is a string
    type, so this is a direct value comparison.
14. If changed and the callback is non-nil, calls it with old and new values.
15. Updates the adherence baseline.
16. Returns an empty result and nil error. No requeue and no fixed interval;
    future reconciles are driven by APIServer events.

#### Why restart-on-change instead of live reload

TLS servers read their configuration when they start. Reconfiguring a live
`tls.Config` safely would require coordinating certificate reloads, listener
restarts, and in-flight connections. The simpler and safer strategy is:

1. Detect a profile change.
2. Cancel the manager context.
3. Let the process exit gracefully.
4. Start again.
5. Fetch the new profile at startup.

NROP's callback does exactly that:

```go
OnProfileChange: func(ctx context.Context, oldSpec, newSpec configv1.TLSProfileSpec) {
	klog.InfoS("TLS profile changed, triggering graceful shutdown to reload", "old profile", oldSpec, "new profile", newSpec)
	cancel()
},
```

### 4.5 How NROP wires the watcher

Source: `cmd/main.go:326-399`.

```go
tlsSecurityProfileSpec, err := ctrltls.FetchAPIServerTLSProfile(ctx, k8sClient)
if err != nil {
	klog.ErrorS(err, "unable to get TLS profile from APIServer")
	exitWithCancel(cancel, 1)
}

tlsConfig, unsupported := ctrltls.NewTLSConfigFromProfile(tlsSecurityProfileSpec)
if len(unsupported) > 0 {
	klog.InfoS("TLS profile configuration contains unsupported ciphers or groups that will be ignored", "unsupported", unsupported)
}

tlsCfg := &tls.Config{}
tlsConfig(tlsCfg)
tlsSettings := objtls.NewSettings(tlsCfg)
klog.InfoS("found TLS settings from APIServer", "settings", tlsSettings.String())

webhookTLSOpts := append(webhookTLSOpts(params.enableHTTP2), tlsConfig)

mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
	Metrics: metricsserver.Options{
		BindAddress:   params.metricsAddr,
		SecureServing: true,
		CertDir:       "/certs",
		TLSOpts:       []func(*tls.Config){tlsConfig},
	},
	WebhookServer: webhook.NewServer(webhook.Options{
		Port:    params.webhookPort,
		TLSOpts: webhookTLSOpts,
	}),
})

watcher := &ctrltls.SecurityProfileWatcher{
	Client:                mgr.GetClient(),
	InitialTLSProfileSpec: tlsSecurityProfileSpec,
	OnProfileChange: func(ctx context.Context, oldSpec, newSpec configv1.TLSProfileSpec) {
		klog.InfoS("TLS profile changed, triggering graceful shutdown to reload", "old profile", oldSpec, "new profile", newSpec)
		cancel()
	},
}

if err := watcher.SetupWithManager(mgr); err != nil {
	klog.ErrorS(err, "unable to set up TLS security profile watcher")
	exitWithCancel(cancel, 1)
}
```

Key observations:

1. The profile is fetched **before** the manager starts.
2. The same callback is reused for operator metrics and webhook TLS options.
3. A fresh `&tls.Config{}` is created only to compute `Settings`; the real
   servers receive the callback and create their own configs.
4. The watcher client is the manager's cache-backed client.
5. `InitialTLSProfileSpec` is the same resolved spec used to build the server
   configs.
6. `InitialTLSAdherencePolicy` and `OnAdherencePolicyChange` are omitted.

### 4.6 Watcher caveats and edge cases

| Situation | Behavior |
|---|---|
| APIServer deleted | Reconcile returns nil; no callback; no crash. |
| APIServer recreated with a different profile | Create event passes predicate; baseline likely differs; callback fires. |
| Custom profile becomes invalid (`Custom == nil`) | Reconcile returns an error and retries. The old process keeps serving the last valid config until the API is fixed. |
| Profile reordered but same set | `reflect.DeepEqual` reports a change; callback fires and process restarts. |
| Only adherence changes | Callback is nil in NROP; baseline updates; no restart. |
| Callback nil | Baseline still updates; no effect. |
| Callback cancels context | Manager shuts down; `main` exits after `mgr.Start` returns. |
| More than one manager replica | All replicas run this controller because leader election is disabled; all restart. |
| Concurrent reconciles | Not synchronized. Default concurrency is one; do not raise it without a mutex. |

---

## 5. Complete function and variable usage map

Function parameters are explained in the line-by-line sections above. The
tables here inventory exported symbols, receiver fields, named results, and
body-local variables, plus where each symbol is consumed.

### 5.1 `pkg/objectupdate/tls`

| Symbol | Kind | Exported | Called by | Calls |
|---|---|---|---|---|
| `Settings` | type | yes | Controllers, updaters, tests | — |
| `Settings.MinVersion` | field | yes | `String`, `DaemonSetArgs`, `DeploymentTLSSettings`, tests | — |
| `Settings.CipherSuites` | field | yes | same | — |
| `Settings.CurvePreferences` | field | yes | same | — |
| `Settings.String` | method | yes | `cmd/main.go` log | `fmt.Sprintf` |
| `NewSettings` | function | yes | `cmd/main.go`, controllers/tests, test helpers | `tls.CipherSuiteName`, `TLSVersionToNameOrDie`, `strings.Join`, `curveIDsToString` |
| `curveIDsToString` | function | no | `NewSettings` | `strings.Builder`, `strconv.Itoa` |

Local variables:

| Function | Variable | Purpose |
|---|---|---|
| `Settings.String` | `ret` | Holds the mandatory two-field prefix. |
| `NewSettings` | `cipherNames` | Accumulates canonical cipher names. |
| `NewSettings` | `id` | Loop variable for each cipher ID. |
| `NewSettings` | `settings` | Result value under construction. |
| `curveIDsToString` | `sb` | String builder. |
| `curveIDsToString` | `i`, `id` | Index and curve ID in the loop. |

### 5.2 `controller-runtime-common/pkg/tls/tls.go`

| Symbol | Kind | Exported | Called by | Calls |
|---|---|---|---|---|
| `APIServerName` | const | yes | Fetch functions, watcher predicates, tests | — |
| `ErrCustomProfileNil` | var | yes | `GetTLSProfileSpec` | `errors.New` |
| `DefaultTLSCiphers` | var | yes | External consumers; unused by NROP | map lookup |
| `DefaultMinTLSVersion` | var | yes | External consumers; unused by NROP | map lookup |
| `HTTP2NextProtos` | var | yes | External consumers; unused by NROP | — |
| `HTTP1NextProtos` | var | yes | External consumers; unused by NROP | — |
| `FetchAPIServerTLSProfile` | function | yes | `cmd/main.go`, `test/internal/tls/tls.go` | `k8sClient.Get`, `GetTLSProfileSpec` |
| `FetchAPIServerTLSAdherencePolicy` | function | yes | Unused by NROP | `k8sClient.Get` |
| `GetTLSProfileSpec` | function | yes | Fetch function, watcher | `configv1.TLSProfiles` |
| `NewTLSConfigFromProfile` | function | yes | `cmd/main.go`, test helpers | `TLSVersionOrDie`, `cipherCodes`, `TLSGroupsToCurveIDs` |
| `SetNextProtos` | function | yes | Unused by NROP | — |
| `cipherCode` | function | no | `cipherCodes` | `CipherSuite`, `OpenSSLToIANACipherSuites` |
| `cipherCodes` | function | no | `NewTLSConfigFromProfile` | `cipherCode` |

Local variables:

| Function | Variable | Purpose |
|---|---|---|
| `FetchAPIServerTLSProfile` | `apiServer` | Destination object. |
| `FetchAPIServerTLSProfile` | `key` | `cluster` object key. |
| `FetchAPIServerTLSProfile` | `profile` | Resolved profile. |
| `FetchAPIServerTLSProfile` | `err` | Resolution error. |
| `FetchAPIServerTLSAdherencePolicy` | `apiServer`, `key` | Same pattern. |
| `GetTLSProfileSpec` | `defaultProfile` | Intermediate profile copy. |
| `GetTLSProfileSpec` | `profileType` | Requested type. |
| `GetTLSProfileSpec` | `tlsConfig`, `ok` | Map lookup result. |
| `NewTLSConfigFromProfile` | `minVersion` | Numeric minimum version. |
| `NewTLSConfigFromProfile` | `cipherSuites`, `unsupportedCiphers` | Converted IDs and rejected names. |
| `NewTLSConfigFromProfile` | `curvePrefs`, `unsupportedGroups` | Converted curves and rejected groups. |
| `NewTLSConfigFromProfile` | `unsupported` | Combined rejected-name list. |
| `NewTLSConfigFromProfile` | `tlsConf` | Closure parameter. |
| `SetNextProtos` | `p` | Filtered protocol list. |
| `SetNextProtos` | `proto` | Loop variable. |
| `SetNextProtos` | `c` | Closure parameter. |
| `cipherCode` | `code` | Direct lookup result. |
| `cipherCode` | `ianaCiphers` | OpenSSL conversion result. |
| `cipherCodes` | `codes`, `unsupportedCiphers` | Named results. |
| `cipherCodes` | `cipher`, `code` | Loop variables. |

### 5.3 `controller-runtime-common/pkg/tls/controller.go`

| Symbol | Kind | Exported | Called by | Calls |
|---|---|---|---|---|
| `SecurityProfileWatcher` | type | yes | `cmd/main.go` | — |
| `SecurityProfileWatcher.Client` | embedded field | yes | `Reconcile` | `Get` |
| `SecurityProfileWatcher.InitialTLSProfileSpec` | field | yes | `Reconcile` | — |
| `SecurityProfileWatcher.InitialTLSAdherencePolicy` | field | yes | `Reconcile` | — |
| `SecurityProfileWatcher.OnProfileChange` | field | yes | `Reconcile` | caller callback |
| `SecurityProfileWatcher.OnAdherencePolicyChange` | field | yes | `Reconcile` | caller callback |
| `SetupWithManager` | method | yes | `cmd/main.go` | controller builder APIs |
| `Reconcile` | method | yes | controller-runtime | `Get`, `GetTLSProfileSpec`, `DeepEqual`, callbacks |

Local variables:

| Function | Variable | Purpose |
|---|---|---|
| `SetupWithManager` | `r` | Watcher receiver. |
| `SetupWithManager` | `mgr` | Manager. |
| `SetupWithManager` | `err` | Builder error. |
| `Reconcile` | `ctx`, `req` | Standard reconcile inputs. |
| `Reconcile` | `logger` | Request-scoped logger. |
| `Reconcile` | `apiServer` | Fetched object. |
| `Reconcile` | `err` | Fetch/resolve error. |
| `Reconcile` | `currentTLSProfileSpec` | Resolved current spec. |
| `Reconcile` | `tlsProfileChanged` | DeepEqual result. |
| `Reconcile` | `tlsAdherencePolicyChanged` | Direct comparison result. |

---

## 6. How to test each layer

### 6.1 Existing tests

| Test | File | What it proves |
|---|---|---|
| `TestNewSettingsMinVersion` | `pkg/objectupdate/tls/tls_test.go` | Numeric version to canonical name. |
| `TestNewSettingsCipherSuites` | same | Ordered cipher CSV. |
| `TestNewSettingsCipherSuitesEmpty` | same | Empty cipher input. |
| `TestNewSettingsCipherSuitesSingle` | same | Single value formatting. |
| `TestNewSettings_WithCurvePreferences` | same | Decimal curve CSV and empty curves. |
| `TestSettings_String` | same | Log format with and without curves. |
| `[test_id:88380]` | `test/e2e/tls/tls_test.go` | Live RTE args match min version and ciphers. |
| `[test_id:88381]` | same | RTE metrics handshake is allowed. |
| `[test_id:88382]` | same | RTE rejects a lower version/disallowed cipher. |
| `[test_id:90743]` | same | Scheduler rejects lower version/disallowed cipher. |
| `[test_id:90744]` | same | Scheduler negotiates allowed version/cipher. |
| `[test_id:88383]` | `test/e2e/serial/tests/configuration.go` | RTE args survive a profile change. |
| `[test_id:85769]` | `test/e2e/serial/tests/metrics.go` | Operator metrics endpoint is reachable over HTTPS. |

No vendored test files exist for `controller-runtime-common/pkg/tls`; behavior
is tested indirectly through NROP unit, controller, and E2E tests.

### 6.2 Unit tests to add for `pkg/objectupdate/tls`

#### `TestSettingsString_EmptyCurves`

Already covered by `TestSettings_String`; keep it.

#### `TestNewSettings_NilConfig`

```go
func TestNewSettings_NilConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil config")
		}
	}()
	_ = NewSettings(nil)
}
```

Why: documents the precondition explicitly. If a panic is not desired, change
the API to return an error instead of adding this test.

#### `TestNewSettings_ZeroMinVersion`

```go
func TestNewSettings_ZeroMinVersion(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for zero MinVersion")
		}
	}()
	_ = NewSettings(&tls.Config{})
}
```

Why: `TLSVersionToNameOrDie(0)` panics. This is a real precondition of the
function.

#### `TestNewSettings_UnknownCipherID`

```go
func TestNewSettings_UnknownCipherID(t *testing.T) {
	s := NewSettings(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{0xFFFF},
	})
	if s.CipherSuites != "0xFFFF" {
		t.Fatalf("got %q, want %q", s.CipherSuites, "0xFFFF")
	}
}
```

Why: `tls.CipherSuiteName` falls back to hexadecimal; this behavior may matter
when diagnosing a bad profile.

#### `TestCurveIDsToString_DuplicatesAndOrder`

```go
func TestCurveIDsToString_DuplicatesAndOrder(t *testing.T) {
	got := curveIDsToString([]tls.CurveID{
		tls.CurveP384, tls.X25519, tls.CurveP384,
	})
	if got != "24,29,24" {
		t.Fatalf("got %q", got)
	}
}
```

Why: locks in order and duplicate preservation.

### 6.3 Unit tests to add for `controller-runtime-common/pkg/tls`

Tests must live in a package that can access unexported `cipherCode` and
`cipherCodes`. Either add them to the vendored package's own test file (not
ideal in this repository) or test through `NewTLSConfigFromProfile` from
`test/internal/tls`.

#### Table-driven `GetTLSProfileSpec`

```go
func TestGetTLSProfileSpec(t *testing.T) {
	tests := []struct {
		name    string
		profile *configv1.TLSSecurityProfile
		want    configv1.TLSProfileSpec
		wantErr error
	}{
		{
			name: "nil uses Intermediate",
			want: *configv1.TLSProfiles[configv1.TLSProfileIntermediateType],
		},
		{
			name:    "empty type uses Intermediate",
			profile: &configv1.TLSSecurityProfile{},
			want:    *configv1.TLSProfiles[configv1.TLSProfileIntermediateType],
		},
		{
			name:    "Modern",
			profile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			want:    *configv1.TLSProfiles[configv1.TLSProfileModernType],
		},
		{
			name:    "Custom nil",
			profile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType},
			wantErr: ctrltls.ErrCustomProfileNil,
		},
	}
	// compare fields and use errors.Is for wantErr
}
```

#### `NewTLSConfigFromProfile` cases

| Case | Assertion |
|---|---|
| Modern | `MinVersion == tls.VersionTLS13`, `CipherSuites` untouched/nil, curves set. |
| Intermediate | `MinVersion == tls.VersionTLS12`, cipher list non-empty, curves set. |
| Custom with only `secp256r1` | `CurvePreferences == []tls.CurveID{tls.CurveP256}`. |
| Custom with no groups | `CurvePreferences` remains nil. |
| Unsupported cipher name | returned in `unsupported`, other ciphers still applied. |
| Unsupported group name | returned in `unsupported`, other groups still applied. |
| OpenSSL cipher name | converted successfully. |
| Empty `MinTLSVersion` | defaults to TLS 1.2. |
| Unknown `MinTLSVersion` | panics. |

#### `SetNextProtos`

| Input | Expected `NextProtos` |
|---|---|
| no args | nil |
| `""` | nil |
| `"http/1.1"` | `["http/1.1"]` |
| `"", "h2"` | `["h2"]` |
| `"h2", "http/1.1"` | `["h2", "http/1.1"]` |

#### `SecurityProfileWatcher` with a fake client

Recommended tests:

1. **No change**: baseline equals API spec; callbacks are not called.
2. **Profile change**: baseline differs; `OnProfileChange` receives the exact
   old and new specs and the baseline is updated.
3. **Adherence change**: callback receives old and new policy.
4. **NotFound**: fake client has no APIServer; `Reconcile` returns nil error and
   no callback.
5. **Invalid Custom**: `Custom == nil`; `Reconcile` returns an error wrapping
   `ErrCustomProfileNil`.
6. **Nil callbacks**: change is detected and baseline updates without panic.

A direct `Reconcile` call with `ctrl.Request{NamespacedName: types.NamespacedName{Name: "cluster"}}`
is enough; the controller builder does not need to run.

### 6.4 E2E mapping

The packages above are validated end to end in three places:

1. **Operand arguments**: `NewSettings` values appear in RTE and scheduler
   container args. Existing tests: 88380 (RTE), and the proposed scheduler
   argument helper.
2. **Handshake**: the same values are enforced by the live servers. Existing
   tests: 88381, 88382, 90743, 90744, plus the proposed curve probes.
3. **Profile change/restart**: `SecurityProfileWatcher` triggers a restart after
   an `APIServer` change. Existing serial test: 88383 for RTE arguments. The
   proposed operator metrics scenario adds a post-restart handshake.

For the exact E2E code, see
[`nrop_tls_curves_automation.md`](nrop_tls_curves_automation.md#6-automation-cookbook)
and
[`nrop_tls_curves_e2e_guide.md`](nrop_tls_curves_e2e_guide.md#9-detailed-e2e-design-and-example-code).

### 6.5 Function-to-test matrix

| Function | Unit | Fake client | E2E |
|---|---|---|---|
| `Settings.String` | existing | — | visible in logs |
| `NewSettings` | existing + proposed edge cases | — | settings appear in operand args |
| `curveIDsToString` | proposed direct test | — | covered through `NewSettings` |
| `FetchAPIServerTLSProfile` | — | proposed | used by all TLS E2E helpers |
| `FetchAPIServerTLSAdherencePolicy` | — | proposed | unused by NROP |
| `GetTLSProfileSpec` | proposed table | — | indirectly through fetch |
| `NewTLSConfigFromProfile` | proposed table | — | settings and handshakes |
| `SetNextProtos` | proposed table | — | unused by NROP |
| `cipherCode` | proposed internal table | — | indirectly |
| `cipherCodes` | proposed internal table | — | indirectly |
| `SecurityProfileWatcher.SetupWithManager` | — | controller test | manager startup |
| `SecurityProfileWatcher.Reconcile` | — | proposed | 88383 restart path |

---

## 7. Troubleshooting by symptom

| Symptom | Likely layer | What to inspect |
|---|---|---|
| Panic at startup `no name found for 0` | `NewSettings` | `tls.Config.MinVersion` was not set. Check that `NewTLSConfigFromProfile` ran. |
| Panic `unknown tls version` | `NewTLSConfigFromProfile` | Custom profile has an invalid `minTLSVersion`. |
| `unsupported ciphers or groups` log line | `NewTLSConfigFromProfile` | The profile contains names unknown to this binary. Compare with Go/library-go version. |
| RTE/scheduler has no curve flag | `NewSettings` or updater | `CurvePreferences` empty? Check profile `groups` and `TLSGroupsToCurveIDs`. |
| Curve flag has unexpected order | `TLSGroupsToCurveIDs` / formatter | The profile order is preserved; check the APIServer object. |
| Curve flag has duplicates | API object or mapping | Neither converter deduplicates. |
| TLS 1.3 profile has no cipher flag | expected | Go does not allow configuring TLS 1.3 ciphers. |
| Operator does not restart after profile change | watcher | Check `InitialTLSProfileSpec`, callback, and APIServer event. |
| Operator restarts on a harmless reorder | `reflect.DeepEqual` | Slice order is significant. |
| Adherence change does nothing | NROP wiring | `InitialTLSAdherencePolicy` and callback are unset. |
| Invalid Custom profile causes reconcile errors | `GetTLSProfileSpec` | `type: Custom` requires `custom` to be non-nil. |

---

## 8. Quick reference

### 8.1 Conversion examples

```text
Intermediate profile
  MinTLSVersion: VersionTLS12
  Groups:        X25519MLKEM768, X25519, secp256r1, secp384r1
  →
  tls.Config{
      MinVersion:       tls.VersionTLS12,
      CipherSuites:     []uint16{...},
      CurvePreferences: []tls.CurveID{4588, 29, 23, 24},
  }
  →
  objtls.Settings{
      MinVersion:       "VersionTLS12",
      CipherSuites:     "TLS_AES_128_GCM_SHA256,...,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      CurvePreferences: "4588,29,23,24",
  }
```

```text
Custom profile with no groups
  MinTLSVersion: VersionTLS12
  Ciphers:       ECDHE-RSA-AES128-GCM-SHA256
  Groups:        <empty>
  →
  CurvePreferences: ""
  →
  RTE:       --metrics-tls-curve-preferences is deleted
  Scheduler: --tls-curve-preferences is deleted
```

```text
Modern profile
  MinTLSVersion: VersionTLS13
  →
  tls.Config.CipherSuites is not set
  →
  Settings.CipherSuites == ""
  →
  RTE/scheduler cipher flag is deleted; TLS 1.3 ciphers are Go-controlled
```

### 8.2 Symbol cheat sheet

```go
// pkg/objectupdate/tls
type Settings struct {
	MinVersion       string
	CipherSuites     string
	CurvePreferences string
}
func (s Settings) String() string
func NewSettings(cfg *tls.Config) Settings
func curveIDsToString(ids []tls.CurveID) string

// controller-runtime-common/pkg/tls/tls.go
const APIServerName = "cluster"
var ErrCustomProfileNil
var DefaultTLSCiphers
var DefaultMinTLSVersion
var HTTP2NextProtos
var HTTP1NextProtos
func FetchAPIServerTLSProfile(ctx, client) (configv1.TLSProfileSpec, error)
func FetchAPIServerTLSAdherencePolicy(ctx, client) (configv1.TLSAdherencePolicy, error)
func GetTLSProfileSpec(profile *configv1.TLSSecurityProfile) (configv1.TLSProfileSpec, error)
func NewTLSConfigFromProfile(spec configv1.TLSProfileSpec) (func(*tls.Config), []string)
func SetNextProtos(protos ...string) func(*tls.Config)
func cipherCode(cipher string) uint16
func cipherCodes(ciphers []string) ([]uint16, []string)

// controller-runtime-common/pkg/tls/controller.go
type SecurityProfileWatcher struct { ... }
func (r *SecurityProfileWatcher) SetupWithManager(mgr ctrl.Manager) error
func (r *SecurityProfileWatcher) Reconcile(ctx, req) (ctrl.Result, error)
```

### 8.3 Invariants worth remembering

1. Empty `Settings.CurvePreferences` means “delete the curve flag”, not “allow
   no curves”.
2. Empty `Settings.CipherSuites` means “delete the cipher flag”, which is
   normal for TLS 1.3.
3. `NewSettings` panics on an invalid or unset `MinVersion`; it never returns
   an error.
4. `GetTLSProfileSpec` never errors for an unknown built-in type; it falls back
   to Intermediate.
5. Only a Custom profile with a nil `Custom` produces
   `ErrCustomProfileNil`.
6. `NewTLSConfigFromProfile` drops unsupported ciphers and groups but keeps
   the rest.
7. Go TLS 1.3 cipher suites cannot be configured; curve preferences still can.
8. The watcher restarts the process rather than mutating live TLS servers.
9. `reflect.DeepEqual` makes group/cipher order significant for restart
   detection.
10. NROP does not track TLS adherence policy today.
