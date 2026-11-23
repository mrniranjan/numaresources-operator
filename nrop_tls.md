# TLS in the NUMA Resources Operator

This document describes how the NUMA Resources Operator handles TLS for its
**metrics endpoint** and **admission webhook**, and how end users can interact
with those endpoints.

---

## Overview

| Endpoint | Default port | TLS enabled | Certificate source | Protocol |
|---|---|---|---|---|
| Metrics (`/metrics`) | 8080 | Always (secure serving) | OpenShift service-serving CA | HTTPS |
| Admission webhook (`/convert`) | 9443 | Always | OLM-managed (when enabled) | HTTPS |
| Health / Readiness probes | 8081 | No | N/A | HTTP |

Both endpoints honour the cluster-wide TLS security profile configured on the
`APIServer` resource (named `cluster`). The operator reads the profile at
startup and applies the resulting minimum TLS version and cipher suites to
every TLS listener it creates. A `SecurityProfileWatcher` monitors the
`APIServer` resource; when the profile changes the operator performs a graceful
restart so the new settings take effect.

---

## Metrics endpoint

### How TLS is configured

1. **Certificate provisioning** -- The metrics `Service` carries the annotation
   `service.beta.openshift.io/serving-cert-secret-name: metrics-service-cert`.
   The OpenShift **service CA operator** sees this annotation and automatically
   creates (and rotates) a `Secret` named `metrics-service-cert` containing
   `tls.crt` and `tls.key` signed by the cluster service CA.

2. **Volume mount** -- The `Deployment` mounts that secret at `/certs`
   (read-only) inside the operator container:

   ```yaml
   volumes:
   - name: metrics-tls
     secret:
       secretName: metrics-service-cert
   containers:
   - volumeMounts:
     - name: metrics-tls
       mountPath: /certs
       readOnly: true
   ```

3. **Server configuration** -- The controller-runtime metrics server is started
   with:

   ```go
   Metrics: metricsserver.Options{
       BindAddress:   ":8080",
       SecureServing: true,
       CertDir:       "/certs",
       TLSOpts:       []func(*tls.Config){tlsConfig},
   }
   ```

   `tlsConfig` is built from the cluster-wide `APIServer` TLS profile
   (`FetchAPIServerTLSProfile` / `NewTLSConfigFromProfile` from
   `github.com/openshift/controller-runtime-common/pkg/tls`). It sets
   `MinVersion` and `CipherSuites` according to the active profile
   (Old, Intermediate, Modern, or Custom).

4. **HTTP/2** -- The metrics server uses the controller-runtime default, which
   advertises `h2` in the TLS ALPN negotiation. The `--enable-http2` flag only
   controls HTTP/2 on the webhook server, not on metrics.

### How Prometheus scrapes metrics over TLS

On OpenShift with cluster monitoring enabled, Prometheus is pre-configured to
trust the service CA. A `ServiceMonitor` (available under
`config/prometheus/monitor.yaml`) describes how Prometheus should connect:

```yaml
endpoints:
- bearerTokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token"
  targetPort: 8080
  path: /metrics
  scheme: https
  tlsConfig:
    caFile: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
    serverName: <service-name>.<namespace>.svc
    insecureSkipVerify: false
```

Key points:
- `scheme: https` -- Prometheus connects over TLS.
- `caFile` -- the cluster service CA bundle, automatically mounted by the
  cluster monitoring stack.
- `serverName` -- must match the Common Name in the serving certificate
  (which equals the Service DNS name).
- `insecureSkipVerify: false` -- full certificate verification is performed.

### Accessing metrics manually (for debugging)

From inside the cluster, you can reach the metrics endpoint using the service
CA bundle for verification. For example, from a pod with the appropriate
service account token:

```bash
# 1. Obtain a bearer token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# 2. Fetch metrics using the service CA
curl -s \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer ${TOKEN}" \
  https://numaresources-controller-manager-metrics-service.<namespace>.svc:8080/metrics
```

Using `oc` from outside the cluster, you can port-forward and skip
verification (for debugging only):

```bash
oc port-forward -n <namespace> svc/numaresources-controller-manager-metrics-service 8080:8080

# In another terminal (the service certificate will not match localhost,
# so --insecure is needed for a local port-forward):
curl -sk https://localhost:8080/metrics
```

Alternatively, extract the service CA from the cluster to verify properly:

```bash
# Extract the service CA bundle
oc get configmap/signing-key -n openshift-service-ca -o jsonpath='{.data.tls\.crt}' > service-ca.crt

# Port-forward and curl with --cacert (still needs --resolve or -k because
# the certificate CN will not match localhost)
curl -s --cacert service-ca.crt \
  --resolve numaresources-controller-manager-metrics-service.<namespace>.svc:8080:127.0.0.1 \
  https://numaresources-controller-manager-metrics-service.<namespace>.svc:8080/metrics
```

### Verifying the TLS handshake with Go

You can use Go's `crypto/tls` package to connect to the metrics endpoint and
programmatically inspect the TLS handshake (negotiated version, cipher suite,
server certificates). This is useful for validating that the cluster-wide TLS
profile is being enforced correctly.

The example below must run from a pod inside the cluster (or adjust the
address when using `oc port-forward`). Replace `<namespace>` with the actual
operator namespace (typically `openshift-numaresources`).

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	// The service CA bundle. From within a pod this is typically:
	//   /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
	// From outside, extract it with:
	//   oc get configmap/signing-key -n openshift-service-ca \
	//       -o jsonpath='{.data.tls\.crt}' > service-ca.crt
	caCert, err := os.ReadFile("service-ca.crt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read CA bundle: %v\n", err)
		os.Exit(1)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		fmt.Fprintf(os.Stderr, "failed to parse CA bundle\n")
		os.Exit(1)
	}

	svcHost := "numaresources-controller-manager-metrics-service.<namespace>.svc"

	tlsConf := &tls.Config{
		RootCAs:    caCertPool,
		ServerName: svcHost, // must match the certificate CN/SAN
	}

	// --- 1. Inspect the raw TLS handshake ---
	conn, err := tls.Dial("tcp", svcHost+":8080", tlsConf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Printf("TLS version:           %s\n", tlsVersionName(state.Version))
	fmt.Printf("Cipher suite:          %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("Negotiated protocol:   %s\n", state.NegotiatedProtocol)
	fmt.Printf("Server certificates:   %d\n", len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		fmt.Printf("  [%d] Subject:  %s\n", i, cert.Subject)
		fmt.Printf("      Issuer:   %s\n", cert.Issuer)
		fmt.Printf("      DNSNames: %v\n", cert.DNSNames)
		fmt.Printf("      NotAfter: %s\n", cert.NotAfter)
	}

	// --- 2. Fetch /metrics over HTTPS ---
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}
	resp, err := client.Get("https://" + svcHost + ":8080/metrics")
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTP request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("\nHTTP status: %s\n", resp.Status)
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Body (first 500 bytes):\n%s\n", string(body[:min(500, len(body))]))
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
```

What to look for in the output:

- **TLS version** -- with the default `Intermediate` profile expect `TLS 1.2`;
  with `Modern` expect `TLS 1.3`.
- **Cipher suite** -- should be one of the ciphers allowed by the active
  `APIServer` TLS profile.
- **Negotiated protocol** -- `h2` (HTTP/2) for the metrics server by default.
- **Server certificate Subject/DNSNames** -- should contain the Service DNS
  name.

When using `oc port-forward` from outside the cluster, the certificate CN will
not match `localhost`, so either set `InsecureSkipVerify: true` (debugging
only) or keep `ServerName` set to the real Service DNS name while connecting
to `localhost:8080`.

### RTE (Resource Topology Exporter) metrics

The RTE DaemonSet pods expose their own metrics endpoint on port `2112` using
a separate service:

```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    service.beta.openshift.io/serving-cert-secret-name: rte-metrics-service-cert
  name: numaresources-rte-metrics-service
spec:
  ports:
  - name: metrics-port
    port: 2112
    targetPort: metrics-port
```

The same service-serving CA mechanism applies: the OpenShift service CA
operator provisions `rte-metrics-service-cert` and the RTE pods mount it for
TLS serving. Clients verify using the same service CA bundle.

---

## Admission webhook (CRD conversion)

### Current state

The admission webhook in this operator is a **CRD conversion webhook** used
for converting between API versions (v1 and v1alpha1) of the
`NUMAResourcesOperator` and `NUMAResourcesScheduler` custom resources. It is
**not** a validating or mutating admission webhook.

In the shipped OLM bundle, the conversion webhook is **disabled** by default:
- The operator Deployment does not pass `--enable-webhooks`.
- The CRD manifests do not include `spec.conversion.strategy: Webhook`.
- The kustomize patches for webhook CRD conversion
  (`config/crd/patches/webhook_in_*.yaml`) are commented out.

When the webhook is enabled (e.g. for development or future releases), the
following applies.

### How TLS is configured

1. **Webhook server** -- The operator always creates a controller-runtime
   webhook server regardless of whether webhooks are registered:

   ```go
   WebhookServer: webhook.NewServer(webhook.Options{
       Port:    9443,
       TLSOpts: webhookTLSOpts,
   })
   ```

   `webhookTLSOpts` combines:
   - An HTTP/2 toggle (controlled by `--enable-http2`; HTTP/2 is disabled by
     default, restricting the server to `http/1.1`).
   - The cluster-wide TLS profile (same `APIServer` profile used by the
     metrics server).

2. **Certificate provisioning** -- The webhook server does **not** set
   `CertDir` explicitly, so controller-runtime falls back to its default
   certificate directory (`/tmp/k8s-webhook-server/serving-certs/`). The
   mechanism for populating this directory depends on the deployment model:

   | Deployment model | Certificate provisioning |
   |---|---|
   | **OLM** (production) | OLM creates and mounts webhook certificates automatically. The kustomize patch in `config/manifests/kustomization.yaml` documents removing the generic `cert` volume because OLM provides its own. |
   | **cert-manager** (development) | Commented scaffolding exists under `config/certmanager/` and `config/crd/patches/cainjection_in_*.yaml`. This injects a CA from a cert-manager `Certificate` resource into the CRD. Not intended for production OLM installs. |

3. **CRD webhook configuration** -- When enabled, CRD patches configure the
   API server to call back to the operator for conversions:

   ```yaml
   spec:
     conversion:
       strategy: Webhook
       webhook:
         clientConfig:
           service:
             name: webhook-service
             path: /convert
         conversionReviewVersions:
         - v1
   ```

   The API server uses the `caBundle` field (injected by OLM or cert-manager)
   to verify the webhook server's TLS certificate.

### Interacting with the webhook endpoint

Under normal operation, users do **not** interact with the webhook endpoint
directly. The Kubernetes API server is the sole client: when a client submits
a request for a stored CRD version that differs from the request version, the
API server calls the `/convert` endpoint over HTTPS.

For debugging purposes, if the webhook is enabled and certificates are in
place:

```bash
# Port-forward to the webhook port
oc port-forward -n <namespace> deploy/numaresources-controller-manager 9443:9443

# Send a test ConversionReview (the certificate won't match localhost)
curl -sk https://localhost:9443/convert \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "apiextensions.k8s.io/v1",
    "kind": "ConversionReview",
    "request": {
      "uid": "test",
      "desiredAPIVersion": "nodetopology.openshift.io/v1",
      "objects": []
    }
  }'
```

---

## Cluster-wide TLS profile integration

The operator declares TLS profile support via the CSV annotation:

```yaml
features.operators.openshift.io/tls-profiles: "true"
```

At startup, the operator:

1. Reads the `APIServer` resource named `cluster` to obtain the
   `spec.tlsSecurityProfile`.
2. Resolves it to a concrete `TLSProfileSpec` (defaults to `Intermediate` if
   unset).
3. Converts the profile into Go `tls.Config` settings (minimum TLS version and
   cipher suites).
4. Applies those settings to both the metrics and webhook TLS listeners via
   `TLSOpts` callbacks.

A `SecurityProfileWatcher` controller watches the `APIServer` resource. When
the TLS profile changes, the watcher triggers a graceful shutdown
(`context.CancelFunc`) so the operator pod restarts and picks up the new
profile.

The RBAC required for this is:

```yaml
- apiGroups:
  - config.openshift.io
  resources:
  - apiservers
  verbs:
  - get
  - list
  - watch
```

### Supported TLS profiles

| Profile | MinTLSVersion | Notes |
|---|---|---|
| Old | TLS 1.0 | Broadest compatibility, weakest security |
| Intermediate (default) | TLS 1.2 | Recommended balance |
| Modern | TLS 1.3 | Strongest; cipher suites not configurable in Go for TLS 1.3 |
| Custom | Configurable | User-defined ciphers and minimum version |

---

## Summary of certificate trust chains

| Component | Certificate Secret | Signed by | Clients verify with |
|---|---|---|---|
| Operator metrics | `metrics-service-cert` | OpenShift service CA | `service-ca.crt` bundle |
| RTE metrics | `rte-metrics-service-cert` | OpenShift service CA | `service-ca.crt` bundle |
| Conversion webhook | OLM-managed (when enabled) | OLM or cert-manager CA | `caBundle` in CRD spec |

---

## Scheduler TLS compliance

The NUMA-aware **secondary scheduler** also enforces TLS on its secure serving
endpoint (port `10259`, path `/healthz`). Unlike the operator (which applies
TLS via `TLSOpts` callbacks), the scheduler receives its TLS settings as
**command-line arguments** on the container spec:

```
--tls-min-version=VersionTLS12
--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,...
--tls-curve-preferences=4588,29,23,24
```

### How the scheduler gets its TLS args

When the NRO operator reconciles the `NUMAResourcesScheduler` CR, it:

1. Fetches the cluster TLS profile via `FetchAPIServerTLSProfile`.
2. Converts it to a `tls.Config` via `NewTLSConfigFromProfile`.
3. Converts the `tls.Config` to string arguments via `objupdate.NewSettings`
   (from `pkg/objectupdate/tls`).
4. Calls `schedupdate.DeploymentTLSSettings(deployment, settings)` (from
   `pkg/objectupdate/sched`) which parses the container's argument vector,
   sets `--tls-min-version` and `--tls-cipher-suites`, and writes the args back.

```
APIServer (cluster)
  │
  │  FetchAPIServerTLSProfile
  ▼
TLSProfileSpec { MinTLSVersion, Ciphers }
  │
  │  NewTLSConfigFromProfile
  ▼
tls.Config { MinVersion: 0x0303, CipherSuites: [0xc02b, ...] }
  │
  │  objupdate.NewSettings
  ▼
Settings { MinVersion: "VersionTLS12", CipherSuites: "TLS_ECDHE_...", CurvePreferences: "4588,29,23,24" }
  │
  │  schedupdate.DeploymentTLSSettings
  ▼
Deployment container args:
  --tls-min-version=VersionTLS12
  --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,...
  --tls-curve-preferences=4588,29,23,24
```

When the cluster TLS profile changes (e.g. from Intermediate to Modern), the
operator's `SecurityProfileWatcher` triggers a restart. On restart, the
operator re-reads the profile and updates the scheduler deployment's container
args. Kubernetes then performs a rolling update of the scheduler pods with the
new TLS settings.

### `pkg/objectupdate/tls` — TLS settings conversion

The `pkg/objectupdate/tls` package provides the `Settings` struct that bridges
Go's numeric `tls.Config` values and the string arguments the scheduler binary
expects:

```go
type Settings struct {
    MinVersion       string  // e.g. "VersionTLS12"
    CipherSuites     string  // comma-separated IANA names
    CurvePreferences string  // comma-separated numeric curve IDs (e.g. "4588,29,23,24")
}

func NewSettings(cfg *tls.Config) Settings
```

`NewSettings` converts:
- `cfg.MinVersion` (e.g. `tls.VersionTLS12` = `0x0303`) → `"VersionTLS12"`
  using `library-go/pkg/crypto.TLSVersionToNameOrDie`.
- `cfg.CipherSuites` (e.g. `[0xc02b, 0xc030]`) → `"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"`
  using `tls.CipherSuiteName` for each ID.
- `cfg.CurvePreferences` (e.g. `[4588, 29, 23, 24]`) → `"4588,29,23,24"` —
  the **numeric** curve/group IDs, joined with commas. See
  [TLS curve (group) preferences](#tls-curve-group-preferences) below.

### `pkg/objectupdate/sched.DeploymentTLSSettings`

This function takes the scheduler `Deployment` and a `Settings` value, finds
the `"secondary-scheduler"` container, parses its argument vector with
`flagcodec`, and sets the two TLS flags:

```go
func DeploymentTLSSettings(dp *appsv1.Deployment, tlsSettings objtls.Settings) error {
    cnt := FindContainerByName(dp.Spec.Template.Spec.Containers, "secondary-scheduler")
    flags := flagcodec.ParseArgvKeyValue(cnt.Args, flagcodec.WithFlagNormalization)
    flags.SetOption("--tls-min-version", tlsSettings.MinVersion)
    flags.SetOption("--tls-cipher-suites", tlsSettings.CipherSuites)
    flags.SetOption("--tls-curve-preferences", tlsSettings.CurvePreferences)
    cnt.Args = flags.Argv()
    return nil
}
```

---

## TLS curve (group) preferences

In addition to minimum version and cipher suites, the cluster TLS profile can
restrict the **TLS groups** (elliptic curves and post-quantum hybrid groups)
used during key exchange. This is exposed via the `Groups` field of
`configv1.TLSProfileSpec` (gated by the `TLSGroupPreferences` feature gate on
the OpenShift API side). The operator propagates these to both operands as
numeric curve IDs, mirroring how upstream `kube-apiserver` accepts them
(`--tls-curve-preferences`, see kubernetes/kubernetes@53b1632).

### Where groups come from

- The built-in profiles **Old, Intermediate, and Modern** all include by
  default: `X25519MLKEM768, X25519, secp256r1, secp384r1`.
- A **Custom** profile may specify an explicit `groups` list (1–7 entries).
- A profile may have **no groups configured** (e.g. a Custom profile that only
  pins version/ciphers, or a Legacy-style configuration): the resulting
  `CurvePreferences` is empty and operands fall back to Go defaults.

### Supported groups and their curve IDs

`library-go`'s `TLSGroupsToCurveIDs()` maps the OpenShift API `TLSGroup`
names to Go `tls.CurveID` values (IANA "TLS Supported Groups" registry):

| TLSGroup (OpenShift API) | Go constant | Curve ID (decimal) | Notes |
|---|---|---|---|
| `X25519` | `tls.X25519` | 29 | |
| `secp256r1` | `tls.CurveP256` | 23 | P-256 |
| `secp384r1` | `tls.CurveP384` | 24 | P-384 |
| `secp521r1` | `tls.CurveP521` | 25 | P-521 |
| `X25519MLKEM768` | `tls.X25519MLKEM768` | 4588 | Post-quantum hybrid; **not FIPS-approved** |
| `SecP256r1MLKEM768` | `tls.SecP256r1MLKEM768` | 4587 | Post-quantum hybrid; **not FIPS-approved** |
| `SecP384r1MLKEM1024` | `tls.SecP384r1MLKEM1024` | 4589 | Post-quantum hybrid; **not FIPS-approved** |

Unrecognized group names are returned separately as "unsupported" and
**do not fail** the operator — they are logged and skipped (see below).

### Conversion pipeline

```
APIServer (cluster) .spec.tlsSecurityProfile
  │
  │  FetchAPIServerTLSProfile          (controller-runtime-common)
  ▼
TLSProfileSpec { MinTLSVersion, Ciphers, Groups }
  │
  │  NewTLSConfigFromProfile           (controller-runtime-common)
  │    └─ libgocrypto.TLSGroupsToCurveIDs(profile.Groups)
  │         → curvePrefs []tls.CurveID, unsupportedGroups []TLSGroup
  ▼
tls.Config { MinVersion, CipherSuites, CurvePreferences: [4588, 29, 23, 24] }
  │
  │  objtls.NewSettings                (pkg/objectupdate/tls)
  │    └─ curveIDsToString: numeric IDs joined by commas
  ▼
Settings { CurvePreferences: "4588,29,23,24" }
  │
  ├─ schedupdate.DeploymentTLSSettings  → scheduler container arg:
  │      --tls-curve-preferences=4588,29,23,24
  └─ rteupdate.DaemonSetArgs            → RTE container arg:
         --metrics-tls-curve-preferences=4588,29,23,24
```

Notes on the pipeline:

- `NewTLSConfigFromProfile` only sets `tlsConf.CurvePreferences` when the
  list is non-empty; an empty groups list leaves Go's default curve
  preference ordering in place.
- Unsupported ciphers **and** groups are aggregated into the `unsupported`
  return value. The operator logs them at startup and continues:
  `"TLS profile configuration contains unsupported ciphers or groups that
  will be ignored"`.
- The numeric-ID format (rather than names) is what the scheduler binary
  expects, matching the upstream k8s flag semantics.

### Operand flag semantics (set-or-delete)

Both operands follow the same pattern — the flag is **set when non-empty and
deleted when empty**:

- **Scheduler** (`pkg/objectupdate/sched/sched.go`,
  `DeploymentTLSSettings`):
  ```go
  if tlsSettings.CurvePreferences != "" {
      flags.SetOption("--tls-curve-preferences", tlsSettings.CurvePreferences)
  } else {
      flags.Delete("--tls-curve-preferences")
  }
  ```
  The same guard applies to `--tls-min-version` and `--tls-cipher-suites`.

- **RTE** (`pkg/objectupdate/rte/rte.go`, `DaemonSetArgs`):
  ```go
  // Delete curve preferences when empty to allow RTE to use Go defaults.
  // This handles TLS profile changes from configured groups to Legacy (empty groups).
  if metricsTLS.CurvePreferences != "" {
      flags.SetOption("--metrics-tls-curve-preferences", metricsTLS.CurvePreferences)
  } else {
      flags.Delete("--metrics-tls-curve-preferences")
  }
  ```

The explicit **delete** on the empty case matters for profile transitions:
when the cluster moves from a profile with configured groups (e.g.
Intermediate) to one without (empty groups), a stale flag from the previous
reconciliation must be removed, otherwise the operand would keep enforcing
the old curves instead of reverting to Go defaults.

RTE support for these flags was introduced upstream in
resource-topology-exporter **v0.25.2**, with validation added in **v0.25.4**;
the operator pins those versions via its `go.mod` RTE dependency.

### Operator's own endpoints

The operator's metrics and webhook servers apply curve preferences
automatically: the same `tlsConfig` function returned by
`NewTLSConfigFromProfile` (which sets `CurvePreferences`) is passed as a
`TLSOpts` callback to both servers. No separate flag handling is needed for
the operator itself.

### Current E2E coverage gap

Curve preferences are **not yet covered** by the TLS E2E suite:

- `test/internal/tls/tls.go` — `CheckRTEDaemonSetTLSFlags` verifies only
  `--metrics-tls-min-version` and `--metrics-tls-cipher-suites`; it does not
  check `--metrics-tls-curve-preferences`. `matchTLSFlag`'s empty-value
  semantics (absent-or-empty is valid when nothing is expected) already
  make it directly reusable for a third curve flag check.
- `test/e2e/tls/tls_test.go` and
  `test/e2e/serial/tests/configuration.go` — the non-disruptive and serial
  tests assert min-version/ciphers only. Extending them for curves means:
  - computing expected curve IDs from
    `NewTLSConfigFromProfile`'s `tls.Config.CurvePreferences` via
    `objtls.NewSettings` (already the source of truth used by the
    operator), and
  - verifying the scheduler deployment args and RTE DaemonSet args carry
    `--tls-curve-preferences` / `--metrics-tls-curve-preferences`
    accordingly (including the empty-groups case where the flags must be
    **absent**).

Unit-level coverage already exists for the flag-writing logic in
`pkg/objectupdate/tls/tls_test.go`, `pkg/objectupdate/sched/sched_test.go`,
and `pkg/objectupdate/rte/rte_test.go`.

The concrete plan for closing this gap is in
[Test plan: TLS curve preferences E2E coverage](#test-plan-tls-curve-preferences-e2e-coverage).

---

## Fetching the cluster TLS profile programmatically

The `FetchAPIServerTLSProfile` function from
`github.com/openshift/controller-runtime-common/pkg/tls` is the standard API
for retrieving the active TLS profile from an OpenShift cluster.

### How it works

```go
func FetchAPIServerTLSProfile(ctx context.Context, k8sClient client.Client) (configv1.TLSProfileSpec, error) {
    apiServer := &configv1.APIServer{}
    key := client.ObjectKey{Name: "cluster"}   // singleton name
    k8sClient.Get(ctx, key, apiServer)

    return GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
}
```

It reads the `configv1.APIServer` object named `"cluster"` and resolves its
`spec.tlsSecurityProfile` to a concrete `TLSProfileSpec`.

### Profile resolution (`GetTLSProfileSpec`)

| `profile.Type` | What happens |
|---|---|
| `nil` or `""` | Returns the **Intermediate** profile (OpenShift default) |
| `Old` | Looks up `configv1.TLSProfiles[OldType]` — broadest cipher set, TLS 1.0 minimum |
| `Intermediate` | Looks up `configv1.TLSProfiles[IntermediateType]` — TLS 1.2 minimum |
| `Modern` | Looks up `configv1.TLSProfiles[ModernType]` — TLS 1.3 minimum |
| `Custom` | Returns `profile.Custom.TLSProfileSpec` directly |

The returned `TLSProfileSpec` contains:

```go
type TLSProfileSpec struct {
    Ciphers       []string             // e.g. ["TLS_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", ...]
    MinTLSVersion TLSProtocolVersion   // e.g. "VersionTLS12"
}
```

### Converting to Go's `tls.Config`

`NewTLSConfigFromProfile` returns a function that populates a `tls.Config`:

```go
tlsConfigFn, unsupportedCiphers := ctrltls.NewTLSConfigFromProfile(profileSpec)
tlsCfg := &tls.Config{}
tlsConfigFn(tlsCfg)
// tlsCfg.MinVersion = tls.VersionTLS12
// tlsCfg.CipherSuites = [0xc02b, 0xc02f, ...]
```

For TLS 1.3, `CipherSuites` is intentionally left empty because Go's TLS 1.3
implementation does not allow configuring cipher suites — all TLS 1.3 ciphers
are always enabled.

### Prerequisite: scheme registration

The `configv1` API group must be registered in the client's scheme. In the
test clients (`test/internal/clients/clients.go`), this is done in `init()`:

```go
import configv1 "github.com/openshift/api/config/v1"

configv1.Install(scheme.Scheme)
```

Without this, calls like `client.Get(ctx, key, &configv1.APIServer{})` fail
with `"no kind is registered for the type v1.APIServer"`.

### Complete usage example

```go
import (
    "context"
    "crypto/tls"
    "fmt"

    ctrltls "github.com/openshift/controller-runtime-common/pkg/tls"
    libgocrypto "github.com/openshift/library-go/pkg/crypto"
    e2eclient "github.com/openshift-kni/numaresources-operator/test/internal/clients"
)

ctx := context.Background()

// Fetch the active profile
profileSpec, err := ctrltls.FetchAPIServerTLSProfile(ctx, e2eclient.Client)
// profileSpec.MinTLSVersion = "VersionTLS12"
// profileSpec.Ciphers = ["TLS_AES_128_GCM_SHA256", ...]

// Convert to tls.Config
tlsConfigFn, _ := ctrltls.NewTLSConfigFromProfile(profileSpec)
tlsCfg := &tls.Config{}
tlsConfigFn(tlsCfg)

fmt.Println("Min version:", libgocrypto.TLSVersionToNameOrDie(tlsCfg.MinVersion))
fmt.Println("Cipher count:", len(tlsCfg.CipherSuites))
```

You can also inspect the profile via `oc`:

```bash
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile}'
```

---

## TLS E2E testing

TLS compliance is verified by two categories of E2E tests: **non-disruptive**
tests that validate the scheduler's current TLS behavior, and a
**serial/disruptive** test that mutates the cluster TLS profile and verifies
the scheduler deployment is reconciled.

### Test infrastructure: `test/internal/tls` probing package

The `test/internal/tls` package provides utilities for probing TLS behavior
of pods using Go's native `crypto/tls` library over Kubernetes port-forwarding
(SPDY tunnels). Unlike the previous curl-based approach, this performs TLS
handshakes directly from the test process without requiring any tools inside
the target pod.

#### How it works: port-forward + native Go TLS

Each probe function calls `remoteexec.PortForwardToPod`, which:

1. Opens an SPDY tunnel to the Kubernetes API server.
2. Creates a data stream targeting the specified pod port.
3. Returns a `net.Conn` that speaks directly to the port inside the pod.

The probe then wraps this `net.Conn` with `tls.Client(conn, cfg)` and performs
a Go-native TLS handshake. The `tls.ConnectionState` returned after a
successful handshake contains the negotiated version and cipher suite as
`uint16` identifiers.

#### Understanding the `uint16` return values

Both `version` and `cipherSuite` returned by `ProbeTLSSettings` are `uint16`
values from Go's `crypto/tls` package. They correspond to IANA-assigned
numbers from the TLS protocol specification.

**TLS Version constants** (from the TLS record-layer `ProtocolVersion` field):

| Go constant | Hex | Decimal | Human name |
|---|---|---|---|
| `tls.VersionTLS10` | `0x0301` | 769 | TLS 1.0 |
| `tls.VersionTLS11` | `0x0302` | 770 | TLS 1.1 |
| `tls.VersionTLS12` | `0x0303` | 771 | TLS 1.2 |
| `tls.VersionTLS13` | `0x0304` | 772 | TLS 1.3 |

Convert to a human-readable string with `tls.VersionName(v)`.

**Cipher Suite ID constants** (from the IANA TLS Cipher Suite Registry):

| IANA name | Hex | Decimal | TLS version |
|---|---|---|---|
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `0xc02b` | 49195 | 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `0xc02f` | 49199 | 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `0xc030` | 49200 | 1.2 |
| `TLS_AES_128_GCM_SHA256` | `0x1301` | 4865 | 1.3 |
| `TLS_AES_256_GCM_SHA384` | `0x1302` | 4866 | 1.3 |
| `TLS_CHACHA20_POLY1305_SHA256` | `0x1303` | 4867 | 1.3 |

Convert to a human-readable string with `tls.CipherSuiteName(id)`.

For example, if `ProbeTLSSettings` returns `(772, 4865, nil)`, that means
the server negotiated **TLS 1.3** with cipher **TLS_AES_128_GCM_SHA256**.

#### Function reference

| Function | Signature | Purpose |
|----------|-----------|---------|
| `ProbeTLSSettings` | `(cli, pod, podPort) → (version uint16, cipherSuite uint16, err)` | Opens a permissive TLS connection (no version/cipher constraints) and returns the negotiated version and cipher. Used in **positive tests** to verify the server applies the expected TLS profile. |
| `ProbeMaxTLSVersion` | `(cli, pod, podPort, maxVersion uint16) → error` | Attempts a TLS handshake pinned to exactly `maxVersion` (sets both Min and Max). If the server requires a higher version, the handshake fails. Used in **negative tests** to confirm the server rejects old versions. |
| `ProbeTLSCipher` | `(cli, pod, podPort, cipher string) → error` | Converts an OpenSSL cipher name to a Go ID, then attempts a TLS 1.2 handshake offering only that single cipher. If the server doesn't allow it, the handshake fails. Used in **negative tests** to confirm disallowed ciphers are rejected. |
| `FetchMetrics` | `(cli, pod, podPort) → ([]byte, error)` | Uses a port-forwarded stream with a custom Go `http.Client` transport to issue an HTTPS `GET /metrics` request and return the response body. Used to verify the metrics endpoint is functional over TLS end-to-end. |
| `FindDisallowedCipher` | `(allowed []string) → string` | Compares the `allowed` list against the broadest profile (`Old`) and returns the first TLS 1.2 cipher **not** in the allowed set. Provides a cipher for negative testing. |
| `OpenSSLCipherToGoID` | `(opensslName string) → (uint16, error)` | Converts an OpenSSL cipher name (e.g. `"ECDHE-RSA-AES128-GCM-SHA256"`) to Go's numeric cipher suite ID, going through the IANA name as an intermediate form via `library-go`. |
| `TLSVersionBelow` | `(v uint16) → (uint16, error)` | Returns the TLS version one step below `v` (e.g. TLS 1.3 → TLS 1.2). Used to compute the version for negative tests. |

#### `FetchMetrics` request flow

`FetchMetrics` uses a layered flow:

1. Open Kubernetes port-forward to the target pod and port.
2. Reuse the single forwarded stream via a custom `DialContext`.
3. Execute HTTPS `GET /metrics` with Go `http.Client`.
4. Validate HTTP status (`200`) and return response body bytes.

```{mermaid}
flowchart TD
    A[FetchMetrics cli pod podPort] --> B[fetchMetricsWithPortForward]
    B --> C[remoteexec.PortForwardToPod callback]
    C --> D[doMetricsRequestOverConnection conn podPort]
    D --> E[buildMetricsHTTPClient conn]
    E --> F[executeMetricsRequest httpCli podPort]

    F --> G[Create GET request to https://127.0.0.1/metrics]
    G --> H[Set Host header 127.0.0.1:podPort]
    H --> I[httpCli.Do req]
    I --> J[Read resp.Body]
    J --> K{Status code == 200?}
    K -- No --> L[Return error with status and body]
    K -- Yes --> M[Return responseBody bytes]

    M --> N[defer httpCli.CloseIdleConnections]
    N --> O[Callback assigns outer body]
    O --> P[PortForwardToPod returns]
    P --> Q[fetchMetricsWithPortForward returns body]
    Q --> R[FetchMetrics returns body]
```

#### Error classification

The package defines sentinel errors for distinguishing handshake failures:

- **`ErrTLSServerRejected`** — the remote server sent a TLS alert rejecting
  the handshake (e.g. the server's minimum version is higher than what we
  offered, or the cipher is not in the server's allowed set).
- **`ErrTLSClientConfigIncompatible`** — Go's TLS client refused to even
  attempt the connection because the configured parameters are impossible
  (e.g. `MinVersion > MaxVersion`, or no cipher suites match).

Both wrap the base `ErrTLSHandshakeRejected`, so callers can use
`errors.Is(err, intls.ErrTLSHandshakeRejected)` to catch any rejection.

#### Usage example (from `rte_test.go`)

```go
gotVersion, gotCipherID, err := intls.ProbeTLSSettings(clients.K8sClient, rtePod, port)
// gotVersion = 772 → tls.VersionName(772) = "TLS 1.3"
// gotCipherID = 4865 → tls.CipherSuiteName(4865) = "TLS_AES_128_GCM_SHA256"
Expect(err).ToNot(HaveOccurred())
Expect(gotVersion).To(BeNumerically(">=", minVersion))
```

### Non-disruptive tests (`test/e2e/tls/`)

These tests verify the scheduler's **current** TLS behavior without changing
cluster state. The suite has a lightweight `BeforeSuite` — it only needs
`e2eclient.ClientsEnabled` (no fixture or `serialconfig.Config`).

**Negative test** — verifies that connections below the minimum TLS version
and connections with disallowed ciphers are **rejected**:

```go
It("should reject TLS connections that are not compatible with the profile", func(ctx context.Context) {
    // Fetch current profile
    tlsProfileSpec, _ := ctrltls.FetchAPIServerTLSProfile(ctx, e2eclient.Client)
    tlsConfigFn, _ := ctrltls.NewTLSConfigFromProfile(tlsProfileSpec)
    tlsCfg := &tls.Config{}
    tlsConfigFn(tlsCfg)

    // Try connecting with a TLS version below the minimum
    belowMinVersion := intls.TlsVersionBelow(tlsCfg.MinVersion)
    endpoint := fmt.Sprintf("https://localhost:%s/healthz", schedulerSecurePort)
    _, err := intls.ProbeMaxTLSVersion(ctx, e2eclient.K8sClient, schedulerPod, endpoint, belowMinVersion)
    Expect(err).To(HaveOccurred())
    Expect(err.Error()).To(ContainSubstring("code 35"))

    // Try connecting with a disallowed cipher
    disallowedCipher := intls.FindDisallowedCipher(tlsProfileSpec.Ciphers)
    err = intls.ProbeTLSCipher(ctx, e2eclient.K8sClient, schedulerPod, endpoint, disallowedCipher)
    Expect(err).To(HaveOccurred())
    Expect(err.Error()).To(ContainSubstring("code 35"))
})
```

**Positive test** — verifies that the negotiated TLS version and cipher suite
match the active profile:

```go
It("should adhere to openshift TLS profile", func(ctx context.Context) {
    gotVersion, gotCipher, err := intls.ProbeTLSSettings(ctx, e2eclient.K8sClient, schedulerPod, endpoint)
    Expect(err).ToNot(HaveOccurred())

    uint16Version, _ := intls.CurlTLSVersionToUint16(gotVersion)
    Expect(uint16Version).To(BeNumerically(">=", minVersion))

    // For TLS 1.2 and below, verify cipher is in the allowed set
    if uint16Version < tls.VersionTLS13 {
        ianaCiphers := libgocrypto.OpenSSLToIANACipherSuites([]string{gotCipher})
        for _, cipher := range ianaCiphers {
            Expect(tlsProfileSpec.Ciphers).To(ContainElement(cipher))
        }
    }
})
```

### Serial/disruptive test (`test/e2e/serial/tests/configuration.go`)

This test mutates the cluster's TLS profile and verifies the scheduler
deployment is updated. Labeled `Tier0`, `Slow`, `Reboot`, and
`feature:tlscompliance`.

**Test flow:**

1. **Capture initial state** — read the current TLS profile, compute expected
   scheduler container args (`--tls-min-version`, `--tls-cipher-suites`), and
   verify they match the deployment. Record scheduler pod UIDs.

2. **Switch TLS profile** — pick a different profile type (Modern ↔
   Intermediate) and update the `APIServer` object. Register a `defer` to
   revert to the original profile.

3. **Wait for MachineConfigPool rollout** — changing the TLS profile triggers
   MachineConfig updates across all pools, causing node reboots. The test uses
   `errgroup.Group` to wait on all MCPs in parallel, first for
   `MachineConfigPoolUpdating`, then for `MachineConfigPoolUpdated`.

4. **Verify scheduler deployment updated** — poll (`Eventually`) the scheduler
   deployment until the container args match the new TLS settings.

5. **Verify pod restart** — wait for the deployment rollout to complete, then
   confirm all scheduler pod UIDs differ from the initial ones.

```
Initial state                    Mutate                           Verify
─────────────                    ──────                           ──────
APIServer: Intermediate  ──►  APIServer: Modern            Scheduler args:
Scheduler args:                  │                            --tls-min-version=VersionTLS13
  --tls-min-version=             │  MCP rollout               --tls-cipher-suites=...
    VersionTLS12                 │  (node reboots)
  --tls-cipher-suites=...        ▼                           Pod UIDs changed ✓
                              Operator restarts
                              → reconciles scheduler
                              → updates deployment args
                              → rolling restart
```

### RTE TLS flag compliance tests

In addition to scheduler endpoint probing, the suite also validates that
**Resource Topology Exporter (RTE)** DaemonSet arguments are kept in sync with
the active cluster TLS profile.

These checks are implemented in:

- `test/internal/tls/tls.go` (helpers)
- `test/e2e/tls/tls_test.go` (non-disruptive Tier0 check)
- `test/e2e/serial/tests/configuration.go` (serial/disruptive Tier2 check)

#### Helper functions (`test/internal/tls/tls.go`)

| Function | Purpose | Key behavior |
|---|---|---|
| `CheckRTEDaemonSetTLSFlags(ctx, cli, expected)` | Validates TLS-related flags on every RTE DaemonSet tracked by the operator | Reads `NUMAResourcesOperator` status node groups, fetches each referenced DaemonSet, finds the main RTE container, parses CLI args, and verifies `--metrics-tls-min-version` and `--metrics-tls-cipher-suites` against expected values. |
| `matchTLSFlag(rteFlags, flagName, expected, dsName)` | Compares one expected flag value with the actual container arg value | If expected is empty, flag may be absent/empty; otherwise, flag must exist and match exactly. Errors include the DaemonSet name and expected vs actual values for easier debugging. |

For the Modern profile, `expected.CipherSuites` may be empty because Go's TLS
1.3 cipher suites are fixed and not user-configurable.

##### Detailed helper behavior

**`CheckRTEDaemonSetTLSFlags(ctx, cli, expected)`**

This helper performs a full-cluster consistency check for RTE TLS flags.

1. It reads the default `NUMAResourcesOperator` custom resource.
2. It asserts that `status.nodeGroups` is populated, because each node group
   contains the DaemonSet reference that must be validated.
3. For every node group, it fetches the corresponding DaemonSet and locates
   the main exporter container by `rteupdate.MainContainerName`.
4. It parses the container argument list into normalized key/value form using
   `flagcodec.ParseArgvKeyValue(..., flagcodec.WithFlagNormalization)`.
5. It validates:
   - `--metrics-tls-min-version` against `expected.MinVersion`
   - `--metrics-tls-cipher-suites` against `expected.CipherSuites`

Operationally, it returns on the first error. This is intentional: callers use
`Eventually(...)`, so the same strict check is retried until reconciliation
converges or timeout is reached.

**`matchTLSFlag(rteFlags, flagName, expected, dsName)`**

This helper encapsulates per-flag comparison semantics.

- If `expected == ""`:
  - the flag may be absent, or
  - the flag may be present with an empty value.
  - It fails only when a non-empty value is present.
- If `expected != ""`:
  - the flag must exist, and
  - the value must match `expected` exactly.
  - Missing or mismatched values fail.

The error text always includes `flagName` and `dsName`, plus expected/actual
values where applicable, so test logs immediately show which DaemonSet drifted
and by how much.

**Why this split helps test reliability**

- `CheckRTEDaemonSetTLSFlags` handles object traversal and argument extraction.
- `matchTLSFlag` handles exact comparison rules, including empty-value semantics.
- Keeping these concerns separate makes failures easier to diagnose and keeps
  asynchronous `Eventually(...)` retries deterministic.

##### Unit tests for helper logic (`test/internal/tls/tls_test.go`)

The unit test block around `TestCheckRTEDaemonSetTLSFlags` and
`TestMatchTLSFlag` validates both happy-path behavior and defensive/error
handling for the helper functions.

**Test fixtures and setup helpers**

- `testScheme` + `init()`:
  - Registers `nropv1` and `appsv1` types so the controller-runtime fake client
    can store and retrieve `NUMAResourcesOperator` and `DaemonSet` objects.
- `newNROP(nodeGroups...)`:
  - Builds a synthetic `NUMAResourcesOperator` object with the default CR name.
  - Injects `Status.NodeGroups`, which is the traversal source used by
    `CheckRTEDaemonSetTLSFlags`.
- `newRTEDaemonSet(namespace, name, args...)`:
  - Builds a minimal DaemonSet with one container named
    `rteupdate.MainContainerName` and caller-provided args.
  - This isolates TLS flag parsing/validation from unrelated pod spec concerns.

Those fixtures are intentionally minimal: they include only fields the helper
reads, which keeps tests focused and resilient to unrelated API changes.

**`TestCheckRTEDaemonSetTLSFlags` coverage map**

Each subtest builds a fake API state and checks that the helper returns the
expected success/failure outcome and message category.

1. `NROP not found`
   - Setup: fake client has no NROP object.
   - Expected: error containing `"failed to get NUMAResourcesOperator"`.
   - Value: proves initial CR lookup is mandatory and reported clearly.

2. `NROP has no NodeGroups`
   - Setup: NROP exists but `Status.NodeGroups` is empty.
   - Expected: error mentioning `"at least one NodeGroup"`.
   - Value: protects against false positives when status is not populated.

3. `DaemonSet not found`
   - Setup: NodeGroup references a DaemonSet that does not exist.
   - Expected: error containing `"failed to get DaemonSet"`.
   - Value: verifies each node group's DaemonSet reference is dereferenced and
     failures are surfaced.

4. `RTE container not found`
   - Setup: DaemonSet exists, but container list lacks
     `rteupdate.MainContainerName`.
   - Expected: error containing `"main container not found"`.
   - Value: ensures TLS flags are read from the correct container only.

5. `flags match intermediate profile`
   - Setup: DaemonSet args carry matching min version and cipher suite.
   - Expected: `nil` error.
   - Value: confirms the nominal path for non-modern profile values.

6. `MinVersion mismatch`
   - Setup: DaemonSet min version is lower than expected, cipher matches.
   - Expected: error containing `"mismatch"`.
   - Value: validates exact equality check for `--metrics-tls-min-version`.

7. `CipherSuites mismatch`
   - Setup: min version matches, cipher suite differs from expected.
   - Expected: error containing `"mismatch"`.
   - Value: validates exact equality check for
     `--metrics-tls-cipher-suites`.

8. `Modern profile with empty cipher suites`
   - Setup: only min-version flag is present; expected cipher suites is empty.
   - Expected: `nil` error.
   - Value: captures the TLS 1.3/Modern semantics where configurable cipher
     suite lists may be intentionally empty.

9. `multiple NodeGroups all match`
   - Setup: two node groups with separate DaemonSets, both matching.
   - Expected: `nil` error.
   - Value: proves multi-DaemonSet traversal success path.

10. `multiple NodeGroups second fails`
    - Setup: first DaemonSet matches; second has wrong min version.
    - Expected: error containing `"mismatch"`.
    - Value: confirms the function fails fast on first detected drift while
      still checking multiple node groups in sequence.

**`TestMatchTLSFlag` coverage map**

This table-style test validates pure comparison semantics independent of K8s
object fetching.

1. `expected empty and flag absent`
   - Input: no flag, expected empty.
   - Expected: success.
   - Meaning: absence is valid when no value is expected.

2. `expected empty but flag present with data`
   - Input: flag exists with non-empty value, expected empty.
   - Expected: error containing `"should be absent or empty"`.
   - Meaning: prevents stale or over-configured values from slipping through.

3. `expected non-empty and flag matches`
   - Input: flag exists and equals expected.
   - Expected: success.
   - Meaning: confirms exact-match happy path.

4. `expected non-empty but flag missing`
   - Input: flag absent, expected non-empty.
   - Expected: error containing `"mismatch"`.
   - Meaning: required values must be explicitly present.

5. `expected non-empty but flag has wrong value`
   - Input: flag present but different value.
   - Expected: error containing `"mismatch"`.
   - Meaning: catches configuration drift and typo-level mismatches.

**Why this test structure is effective**

- It separates integration-like helper behavior (`CheckRTEDaemonSetTLSFlags`)
  from pure comparator behavior (`matchTLSFlag`).
- It validates both single and multi-nodegroup paths.
- It codifies Modern-profile empty-cipher expectations, which is a common edge
  case for TLS 1.3 handling.
- It asserts error message categories, making future regressions easier to
  diagnose in CI output.

#### Non-disruptive RTE check (`test/e2e/tls/tls_test.go`)

Test: `[test_id:88380] should have RTE DaemonSet args aligned with the cluster TLS profile`

Flow:

1. Read current cluster TLS profile from `APIServer` (`FetchAPIServerTLSProfile`).
2. Convert profile to a Go TLS config (`NewTLSConfigFromProfile`), then to
   object settings (`objtls.NewSettings`).
3. Use `Eventually(...)` to call `CheckRTEDaemonSetTLSFlags` until reconciliation
   converges (timeout 30s, polling 5s).

What it proves:

- At steady state, RTE DaemonSet TLS args match the active cluster profile.

#### Serial/disruptive RTE check (`test/e2e/serial/tests/configuration.go`)

Test: `[test_id:88383] should update RTE daemonset TLS args to adhere to modified TLS profile`

Flow:

1. Read current APIServer TLS profile and pick a different target profile
   (Modern or Intermediate).
2. Update the APIServer profile and register cleanup to restore the original
   profile at test end.
3. Wait for MachineConfigPool rollout (`Updating` -> `Updated`) and verify
   node/MCP alignment.
4. Recompute expected TLS settings from the new profile.
5. Use `Eventually(...)` with `CheckRTEDaemonSetTLSFlags` to verify RTE
   DaemonSet args are updated accordingly.

What it proves:

- RTE TLS args are reconciled not only at initial state, but also after live
  TLS profile changes and reboot-driven machine config rollouts.

### Feature topic registration

TLS compliance tests use the label `Label("feature:tlscompliance")`. This
topic is registered in `internal/api/features/_topics.json`:

```text
{
  "active": [
    ...
    "tlscompliance"
  ]
}
```

CI systems can run only TLS tests with:

```bash
ginkgo --label-filter="feature:tlscompliance" ./test/e2e/serial/...
ginkgo --label-filter="feature:tlscompliance" ./test/e2e/tls/...
```

---

## Test plan: TLS curve preferences E2E coverage

This section is the plan for extending the TLS compliance suite to cover the
recently added TLS curve preferences support (see
[TLS curve (group) preferences](#tls-curve-group-preferences)). It follows the
existing suite structure: shared helpers in `test/internal/tls`, unit tests for
those helpers, non-disruptive tests in `test/e2e/tls/`, and serial/disruptive
tests in `test/e2e/serial/tests/configuration.go`.

### Prerequisites and scope

- Expected values are always derived from the **same source of truth the
  operator uses**: `ctrltls.FetchAPIServerTLSProfile` → `NewTLSConfigFromProfile`
  → `objtls.NewSettings`, yielding `Settings.CurvePreferences` as a
  comma-separated string of numeric curve IDs (e.g. `"4588,29,23,24"`).
  `test/internal/tls.RTESettingsFromClusterProfile` already returns such a
  `Settings` value and needs no change — it picks up `CurvePreferences`
  automatically via `NewSettings`.
- All new tests carry the `feature:tlscompliance` label so they run with the
  existing CI filter.
- Test IDs for new `It()` blocks must be allocated from the project's ID range
  (recent TLS tests used 88380–88383, 90743–90744); placeholders below are
  marked `TBD`.

### 1. Helper extension — `test/internal/tls/tls.go`

**Change:** add a third flag check to `CheckRTEDaemonSetTLSFlags`, next to the
existing min-version and cipher-suite checks:

```go
// Curve preferences: numeric curve IDs (e.g. "4588,29,23,24"); empty when
// the active profile defines no groups — the flag must then be absent.
if err := matchTLSFlag(rteFlags, "--metrics-tls-curve-preferences", expected.CurvePreferences, ds.Name); err != nil {
    return err
}
```

`matchTLSFlag` is already generic and its empty-value semantics (absent or
empty is valid when nothing is expected) map exactly onto the operator's
set-or-delete flag behavior, so no comparator changes are needed.

**New probe (optional, for handshake-level negative tests):**

```go
// ProbeTLSCurve attempts a TLS handshake offering only the given curve
// (client-side CurvePreferences pinned to a single group). If the server
// does not allow that group, the handshake fails. Mirrors ProbeTLSCipher.
func ProbeTLSCurve(cli kubernetes.Interface, pod *corev1.Pod, podPort string, curveID tls.CurveID) error
```

Note: Go's `tls.ConnectionState` does not export the negotiated group, so
**positive** handshake-level curve assertions are not possible with the
current probing approach; positive coverage is therefore argument-level
(flags on DaemonSet/Deployment), and handshake-level coverage is
**negative-only** (offering a disallowed curve must fail the handshake),
analogous to `ProbeTLSCipher`.

A `FindDisallowedCurve(allowed []tls.CurveID) (tls.CurveID, error)` helper
(complement of `FindDisallowedCipher`) picks a curve from the built-in
profiles that is not in the allowed set.

### 2. Unit tests — `test/internal/tls/tls_test.go`

Extend `TestCheckRTEDaemonSetTLSFlags` with curve-specific subtests, reusing
the existing fixtures (`newNROP`, `newRTEDaemonSet`):

| # | Subtest | Setup | Expected |
|---|---|---|---|
| 1 | `flags match intermediate profile with curves` | args carry `--metrics-tls-curve-preferences=4588,29,23,24` matching expected | `nil` error |
| 2 | `CurvePreferences mismatch` | args carry a different (e.g. truncated) ID list | error containing `"mismatch"` mentioning `--metrics-tls-curve-preferences` |
| 3 | `profile with no groups, flag absent` | expected `CurvePreferences` empty, no curve flag in args | `nil` error |
| 4 | `profile with no groups, stale flag present` | expected empty, args still carry the old flag from a previous profile | error containing `"should be absent or empty"` — guards the set-or-delete regression |
| 5 | `multiple NodeGroups, second has stale curve flag` | first DS matches, second keeps old curve list | error containing `"mismatch"` |

Subtest 4 is the most valuable: it codifies the deletion path added for
profile transitions to empty-groups configurations.

`TestMatchTLSFlag` needs no new cases — the comparator is curve-agnostic.

### 3. Non-disruptive tests — `test/e2e/tls/tls_test.go`

Inside the existing `[tlscompliance][rte]` context:

**Extend `[test_id:88380]`** (RTE DaemonSet args aligned with cluster
profile): once `CheckRTEDaemonSetTLSFlags` checks the curve flag, this test
automatically covers curves at steady state — including the flag-present case
for Intermediate/Modern (both define groups) and the flag-absent case on
clusters running a groups-less profile. No test-body change needed.

**New test — scheduler deployment curve args** (`[test_id:TBD]`, Tier0):

```
It("[test_id:TBD] should have scheduler deployment TLS args aligned with the cluster TLS profile")
```

Flow (mirrors the RTE check but for the `NUMAResourcesScheduler`-owned
Deployment):

1. Get the scheduler Deployment (via `podlist.With(...).DeploymentByOwnerReference`
   on the `NUMAResourcesScheduler` CR, as the serial suite does).
2. Compute expected `objtls.Settings` from the cluster profile
   (`RTESettingsFromClusterProfile`-equivalent; expected values are
   operand-agnostic).
3. Parse the `secondary-scheduler` container args with
   `flagcodec.ParseArgvKeyValue` and verify `--tls-min-version`,
   `--tls-cipher-suites` and `--tls-curve-preferences` against expected —
   either as a new `CheckSchedulerDeploymentTLSFlags` helper in
   `test/internal/tls` (preferred, symmetric with the RTE helper) or inline.
4. Wrap in `Eventually` (30s timeout / 5s polling, matching test 88380).

**New negative handshake test** (`[test_id:TBD]`, Tier0, optional — requires
`ProbeTLSCurve`):

- Fetch the cluster profile, compute allowed curve IDs.
- Pick a disallowed curve (`FindDisallowedCurve`).
- `ProbeTLSCurve` against the scheduler `/healthz` secure port (and/or the
  RTE metrics port 2112) must fail with a handshake rejection
  (`ErrTLSServerRejected`).

### 4. Serial/disruptive tests — `test/e2e/serial/tests/configuration.go`

**Extend `[test_id:88383]`** (RTE daemonset args adhere to modified TLS
profile): the existing Intermediate ↔ Modern switch already changes the curve
set between profiles only in ordering, not membership (both use
`X25519MLKEM768, X25519, secp256r1, secp384r1`). With the helper extended,
the test still verifies the curve flag survives reconciliation after a
profile change and MCP rollout. To make the curve values actually differ,
prefer switching to a **Custom** profile with a restricted group list (see
next item) instead of Modern when the cluster allows it.

**New serial test — curve flag transition to restricted and empty groups**
(`[test_id:TBD]`, labels: `feature:tlscompliance`, Tier2, Slow, Reboot):

```
It("[test_id:TBD] should update TLS curve preference args when groups change")
```

Flow:

1. Capture original `APIServer` profile; register `DeferCleanup` to revert
   (same `Eventually`-update pattern as test 88383).
2. **Phase A — restricted groups:** set a Custom profile with
   `groups: [X25519, secp256r1]` (and ciphers/minVersion copied from
   Intermediate to keep the handshake valid for the apiserver itself).
   Wait for MCP rollout (`waitForMCPsAndVerifyNodes`), then `Eventually`
   verify both the RTE DaemonSets and the scheduler Deployment carry
   `--metrics-tls-curve-preferences=29,23` /
   `--tls-curve-preferences=29,23` exactly.
3. **Phase B — empty groups:** set a Custom profile with no `groups` (only
   ciphers/minVersion from Intermediate). Wait for MCP rollout, then verify
   the curve flags are **absent** on both operands — this exercises the
   delete-on-empty path end to end.
4. Revert (DeferCleanup) and wait for MCPs.

Caveats:

- Setting `groups` on a Custom profile requires the OpenShift
  `TLSGroupPreferences` feature gate to be enabled on the cluster; if the
  gate is off, the API may reject or drop the field. The test should detect
  this and skip (or the profile should fall back to Old/Intermediate/Modern,
  which always define groups) rather than fail.
- Reboot/label requirements and PDB/topology constraints are the same as for
  test 88383 (see
  [Node drain, PodDisruptionBudgets, and cluster topology considerations](#node-drain-poddisruptionbudgets-and-cluster-topology-considerations)).
- Phase B's empty-groups Custom profile must still keep a valid cipher list,
  otherwise the apiserver itself may reject the configuration.

### 5. What is intentionally out of scope

- **Operator's own metrics/webhook endpoints**: curve preferences are applied
  in-process via `TLSOpts` from `controller-runtime-common`; there is no
  user-visible flag to assert, and the negative probe would test
  controller-runtime-common rather than NRO logic. Handshake-level probing of
  the operator's own endpoints adds little value beyond what the existing
  version/cipher probes already cover.
- **FIPS-mode behavior** (X25519MLKEM768 and other MLKEM hybrids are not
  FIPS-approved): worth a follow-up only if the suite gains a FIPS cluster
  profile.

### 6. Summary of changes

| File | Change | Type |
|---|---|---|
| `test/internal/tls/tls.go` | Check `--metrics-tls-curve-preferences` in `CheckRTEDaemonSetTLSFlags`; add `ProbeTLSCurve` + `FindDisallowedCurve` (optional); optionally add `CheckSchedulerDeploymentTLSFlags` | helper |
| `test/internal/tls/tls_test.go` | 5 new curve subtests for `TestCheckRTEDaemonSetTLSFlags` (incl. stale-flag deletion case) | unit |
| `test/e2e/tls/tls_test.go` | 88380 extended implicitly; new scheduler-args test `[test_id:TBD]`; optional negative curve probe test | e2e, Tier0 |
| `test/e2e/serial/tests/configuration.go` | 88383 extended implicitly; new restricted/empty-groups transition test `[test_id:TBD]` | e2e, serial, Tier2 |

---

## Node drain, PodDisruptionBudgets, and cluster topology considerations

Changing the `APIServer` TLS profile triggers MachineConfig regeneration across
all MachineConfigPools. This causes every node in the cluster to reboot —
control plane and workers alike. Before rebooting, each node must be
**drained**: all non-DaemonSet pods are evicted so workloads can be
rescheduled elsewhere. This process interacts with Kubernetes
**PodDisruptionBudgets (PDBs)** and can cause nodes to become stuck in the
`SchedulingDisabled` state if the cluster topology does not have enough
capacity.

This section explains the mechanics in detail and analyzes which cluster
topologies are safe and which are not.

### What is a PodDisruptionBudget (PDB)?

A PodDisruptionBudget is a Kubernetes resource that limits the number of pods
of a replicated application that can be simultaneously down during
**voluntary disruptions** (node drains, rolling updates, manual evictions).
PDBs do **not** protect against involuntary disruptions like hardware
failures.

A PDB specifies one of two constraints:

| Field | Meaning | Example |
|-------|---------|---------|
| `minAvailable` | Minimum number (or %) of pods that must remain running | `minAvailable: 1` means at least 1 pod must be up |
| `maxUnavailable` | Maximum number (or %) of pods that can be down | `maxUnavailable: 1` means at most 1 pod can be evicted |

The PDB controller continuously computes `status.disruptionsAllowed` — the
number of pods that can be safely evicted right now without violating the
budget. When a pod eviction request is submitted via the **Eviction API**
(`POST /pods/<name>/eviction`), the API server checks the applicable PDB:

- If `disruptionsAllowed > 0` → eviction is **permitted**, the pod is
  terminated, `disruptionsAllowed` is decremented.
- If `disruptionsAllowed == 0` → eviction is **denied** with HTTP 429
  (Too Many Requests): *"Cannot evict pod as it would violate the pod's
  disruption budget."*

Critically, `disruptionsAllowed` depends on whether evicted pods can be
**rescheduled to a schedulable node**. If all nodes are cordoned, the
scheduler cannot place new pods, existing pods cannot be evicted, and
**replicas never come back up** — so `disruptionsAllowed` stays at 0.

#### Common PDBs in an OpenShift cluster

An OpenShift cluster ships with many PDBs pre-configured for platform
components:

| Namespace | PDB | Constraint | Typical replicas |
|-----------|-----|-----------|-----------------|
| `openshift-etcd` | `etcd-guard-pdb` | `minAvailable: 2` | 3 (one per control plane) |
| `openshift-kube-apiserver` | `kube-apiserver-guard-pdb` | `minAvailable: 2` | 3 |
| `openshift-kube-controller-manager` | `kube-controller-manager-guard-pdb` | `minAvailable: 2` | 3 |
| `openshift-kube-scheduler` | `openshift-kube-scheduler-guard-pdb` | `minAvailable: 2` | 3 |
| `openshift-ingress` | `router-default` | `maxUnavailable: 50%` | 2 |
| `openshift-monitoring` | `prometheus-k8s` | `minAvailable: 1` | 2 |
| `openshift-monitoring` | `alertmanager-main` | `maxUnavailable: 1` | 2 |
| `openshift-monitoring` | `thanos-querier-pdb` | `minAvailable: 1` | 2 |
| `openshift-monitoring` | `monitoring-plugin` | `minAvailable: 1` | 2 |
| `openshift-monitoring` | `prometheus-operator-admission-webhook` | `minAvailable: 1` | 2 |
| `openshift-monitoring` | `metrics-server` | `minAvailable: 1` | 2 |
| `openshift-apiserver` | `openshift-apiserver-pdb` | `maxUnavailable: 1` | 3 |
| `openshift-oauth-apiserver` | `oauth-apiserver-pdb` | `maxUnavailable: 1` | 3 |
| `openshift-image-registry` | `image-registry` | `minAvailable: 0` | 1-2 |
| `openshift-cluster-storage-operator` | `csi-snapshot-controller-pdb` | `maxUnavailable: 1` | 2 |
| `openshift-console` | `console` | `maxUnavailable: 1` | 2 |
| `openshift-console` | `downloads` | `maxUnavailable: 1` | 2 |

Many of these have `minAvailable: 1` or `minAvailable: 2`. When there are
only 2 replicas and both are on nodes being drained simultaneously, the PDB
allows **zero disruptions** because evicting either replica would bring the
count below the minimum.

### How the MCO drains nodes

The Machine Config Operator uses a two-component architecture for draining
nodes:

```
MCD (Machine Config Daemon)            MCC Drain Controller
─────────────────────────              ────────────────────
Runs on every node                     Runs on control plane

1. Sets annotation:                    3. Watches for annotation
   desiredDrain = "drain-<mc>"            mismatch

2. Polls every 10s for up              4. Cordons node
   to 1 hour waiting for:                 (Spec.Unschedulable = true)
   desiredDrain == lastAppliedDrain
                                       5. Runs drain.RunNodeDrain()
                                          - Evicts all non-DaemonSet pods
                                          - Uses Eviction API (honours PDBs)
                                          - 90s timeout per attempt

                                       6. On success: sets
                                          lastAppliedDrain = desiredDrain

                                       7. On failure: requeues after
                                          1 min (or 5 min after 10 min)
```

After the node reboots and reaches the desired config, the MCD requests an
**uncordon** by setting `desiredDrain = "uncordon-<mc>"`. The drain controller
then sets `Spec.Unschedulable = false`, removing the `SchedulingDisabled`
status.

#### Key timeouts and retry behaviour

| Parameter | Value | Description |
|-----------|-------|-------------|
| `DrainHelperTimeout` | 90 seconds | Per-attempt timeout for `RunNodeDrain`; bounds the PDB eviction retry loop |
| `DrainRequeueDelay` | 1 minute | Delay before retrying a failed drain |
| `DrainRequeueFailingThreshold` | 10 minutes | After this duration, drain is considered long-failing |
| `DrainRequeueFailingDelay` | 5 minutes | Slower retry interval for long-failing drains |
| `DrainTimeoutDuration` | 1 hour | Warning threshold; drain continues to retry beyond this |
| `EvictErrorRetryDelay` | 0 seconds (default) | On PDB 429 rejection, retry is **immediate** (tight loop until 90s timeout) |
| MCD poll for drain completion | 10 seconds | MCD polls node annotations |
| MCD drain wait limit | 1 hour | MCD degrades the node after this |
| MCD uncordon wait limit | 10 minutes | MCD polls for uncordon completion |

The 0-second `EvictErrorRetryDelay` means that when a PDB blocks eviction,
the drain controller retries in a tight loop — hundreds of eviction API calls
per second — until the 90-second `DrainHelperTimeout` expires. This causes
client-side throttling and generates a very large volume of log messages:

```
error when evicting pods/"router-default-..." -n "openshift-ingress"
  (will retry after 0s): Cannot evict pod as it would violate the
  pod's disruption budget.
```

#### How maxUnavailable controls concurrent drains

The MCO **node controller** decides which nodes to drain based on the
`maxUnavailable` setting of each MachineConfigPool. The default is **1**,
meaning at most 1 node per pool can be unavailable at a time.

Critically, **each MCP independently computes its maxUnavailable**. There is
no cross-pool coordination. If multiple MCPs exist (e.g. `master`, `worker`,
`worker-cnf`), each pool can drain up to `maxUnavailable` nodes
simultaneously — even if this results in **every worker node in the cluster
being drained at the same time**.

A node that matches multiple pool selectors (e.g. has both `worker` and
`worker-cnf` labels) is **owned by the most specific pool** (`worker-cnf`)
for update purposes. It does **not** count toward the `worker` pool's
`machineCount`.

### Cluster topology analysis

The following scenarios analyze what happens when a TLS profile change (or any
`APIServer` modification) triggers node reboots across the cluster. The key
question for each: **is there always at least one schedulable worker node for
PDB-protected pods to land on?**

#### Scenario 1: 3 control plane + 2 workers (1 in worker-cnf) — DEADLOCK

```
Nodes:
  ctlplane-0,1,2  →  master MCP (3 nodes, maxUnavailable=1)
  worker-0         →  worker-cnf MCP (1 node, maxUnavailable=1)
  worker-1         →  worker MCP (1 node, maxUnavailable=1)

Drain behaviour:
  master:     drains 1 of 3 control planes      → 2 remain schedulable
  worker-cnf: drains worker-0 (its only node)    → 0 remain in pool
  worker:     drains worker-1 (its only node)    → 0 remain in pool

Result: ALL worker nodes are cordoned simultaneously.
```

**Why it deadlocks:**

- `router-default` has `maxUnavailable: 50%` with 2 replicas — both replicas
  are on workers. Evicting either one requires the other to be running, but
  both nodes are cordoned. Allowed disruptions = **0**.
- `prometheus-k8s` has `minAvailable: 1` with 2 replicas — same situation.
  No schedulable node to place a replacement pod. Allowed disruptions = **0**.
- All openshift-monitoring PDBs (alertmanager, thanos-querier,
  monitoring-plugin, prometheus-operator-admission-webhook, metrics-server)
  face the same problem.

The drain controller enters a cycle:
1. Attempt eviction → PDB rejects with 429 → tight-loop retry for 90s
2. Drain fails → requeue after 1 minute
3. Retry → same PDB rejection → fail again
4. After 10 minutes of failure → slow down to 5-minute retries
5. After 1 hour → log warning, but **continue retrying forever**

The nodes remain `SchedulingDisabled` indefinitely until manual intervention.

**This is the topology used in NROP CI TLS testing and is known to hit this
issue.**

#### Scenario 2: 3 control plane + 3 workers (1 in worker-cnf) — SAFE

```
Nodes:
  ctlplane-0,1,2  →  master MCP (3 nodes, maxUnavailable=1)
  worker-0         →  worker-cnf MCP (1 node, maxUnavailable=1)
  worker-1         →  worker MCP (2 nodes, maxUnavailable=1)
  worker-2         →  worker MCP

Drain behaviour:
  master:     drains 1 of 3 control planes       → 2 remain schedulable
  worker-cnf: drains worker-0                     → 0 remain in cnf pool
  worker:     drains 1 of {worker-1, worker-2}    → 1 remains schedulable

Result: At least 1 worker + 2 control planes remain schedulable.
```

PDB-protected pods evicted from drained workers can be rescheduled to the
remaining schedulable worker. Drains succeed, nodes reboot, uncordon, and the
process continues to the next batch.

**Cost:** Requires an additional worker node.

#### Scenario 3: 3 control plane + 2 workers (both in worker-cnf, no separate worker pool) — SAFE

```
Nodes:
  ctlplane-0,1,2  →  master MCP (3 nodes, maxUnavailable=1)
  worker-0         →  worker-cnf MCP (2 nodes, maxUnavailable=1)
  worker-1         →  worker-cnf MCP

  worker MCP has 0 nodes (both workers are owned by worker-cnf)

Drain behaviour:
  master:     drains 1 of 3 control planes        → 2 remain schedulable
  worker-cnf: drains 1 of {worker-0, worker-1}    → 1 remains schedulable
  worker:     no nodes to drain

Result: 1 worker + 2 control planes remain schedulable.
```

By labeling both workers as `worker-cnf`, they are both owned by the
`worker-cnf` pool (the more specific pool). The `worker` pool has
`machineCount=0`. Now `worker-cnf` has 2 nodes with `maxUnavailable=1`, so
only 1 worker is drained at a time.

**Cost:** No additional hardware needed. However, both workers will receive
the `worker-cnf` rendered config (performance profiles, kernel args, NUMA
tuning, etc.). This is only appropriate if both workers should have identical
CNF configurations.

#### Scenario 4: 3 control plane + 2 workers (no worker-cnf MCP) — SAFE

```
Nodes:
  ctlplane-0,1,2  →  master MCP (3 nodes, maxUnavailable=1)
  worker-0         →  worker MCP (2 nodes, maxUnavailable=1)
  worker-1         →  worker MCP

Drain behaviour:
  master:  drains 1 of 3 control planes       → 2 remain schedulable
  worker:  drains 1 of {worker-0, worker-1}   → 1 remains schedulable

Result: 1 worker + 2 control planes remain schedulable.
```

Without a separate `worker-cnf` pool, both workers are in the single `worker`
pool with `maxUnavailable=1`. Only 1 is drained at a time.

**Trade-off:** No CNF-specific configuration isolation. All workers share the
same rendered MachineConfig.

#### Scenario 5: 3 control plane + 2 workers + 2 in worker-cnf (one shared) — DEADLOCK RISK

```
Nodes:
  ctlplane-0,1,2  →  master MCP (3 nodes, maxUnavailable=1)
  worker-0         →  worker-cnf MCP (1 node, maxUnavailable=1)
  worker-1         →  worker MCP (1 node, maxUnavailable=1)

  worker-0 has both worker and worker-cnf labels but is owned by worker-cnf.
  worker MCP only contains worker-1.
```

This is identical to Scenario 1. Having labels on both pools does not help
because the node is claimed by the most specific pool. The `worker` MCP still
has only 1 node. **Same deadlock.**

#### Scenario 6: 3 control plane + 4 workers (2 in worker-cnf) — SAFE

```
Nodes:
  ctlplane-0,1,2  →  master MCP (3 nodes, maxUnavailable=1)
  worker-0         →  worker-cnf MCP (2 nodes, maxUnavailable=1)
  worker-1         →  worker-cnf MCP
  worker-2         →  worker MCP (2 nodes, maxUnavailable=1)
  worker-3         →  worker MCP

Drain behaviour:
  master:     drains 1 of 3   → 2 remain
  worker-cnf: drains 1 of 2   → 1 remains schedulable
  worker:     drains 1 of 2   → 1 remains schedulable

Result: 2 workers + 2 control planes remain schedulable.
```

Each pool has >= 2 nodes with `maxUnavailable=1`. No deadlock possible.

#### Scenario 7: Single-node OpenShift (SNO) — SAFE (drain skipped)

```
Nodes:
  node-0  →  master MCP (1 node, control-plane + worker roles)

Drain behaviour:
  Drain is SKIPPED entirely on single-node topology.
```

The MCD explicitly checks for single-node topology and bypasses the drain:

```go
func (dn *Daemon) drainRequired() bool {
    // Drain operation is not useful on a single node cluster as there
    // is no other node in the cluster where workload with PDB set
    // can be rescheduled.
    return !isSingleNodeTopology(dn.getControlPlaneTopology())
}
```

Instead, SNO relies on the Kubernetes
[graceful node shutdown](https://kubernetes.io/docs/concepts/architecture/nodes/#graceful-node-shutdown)
feature.

### Summary table

| Topology | Worker MCPs | Nodes per MCP | Deadlock? | Why |
|----------|------------|---------------|-----------|-----|
| 3cp + 2w (1 cnf) | `worker`(1), `worker-cnf`(1) | 1 each | **YES** | Both pools drain their only node simultaneously |
| 3cp + 3w (1 cnf) | `worker`(2), `worker-cnf`(1) | 2 and 1 | No | `worker` pool keeps 1 node schedulable |
| 3cp + 2w (both cnf) | `worker-cnf`(2) | 2 | No | 1 worker always remains schedulable |
| 3cp + 2w (no cnf) | `worker`(2) | 2 | No | 1 worker always remains schedulable |
| 3cp + 2w (1 shared) | `worker`(1), `worker-cnf`(1) | 1 each | **YES** | Same as first row — shared label does not help |
| 3cp + 4w (2 cnf) | `worker`(2), `worker-cnf`(2) | 2 each | No | Each pool keeps 1 node schedulable |
| SNO (1 node) | N/A | 1 | No | Drain is skipped entirely |

**Rule of thumb:** Any MCP with exactly 1 node and `maxUnavailable >= 1`
will drain its only node. If every worker is the sole member of its pool,
all workers drain simultaneously and PDB deadlock occurs.

### Recommendations for NROP TLS testing environments

1. **Minimum safe topology:** Ensure every worker MCP has **at least 2
   nodes**. This guarantees `maxUnavailable=1` always leaves one node
   schedulable.

2. **Simplest fix for 2-worker clusters:** Either:
   - Add both workers to the same `worker-cnf` pool (if both can accept CNF
     config), or
   - Remove the `worker-cnf` pool so both workers are in the `worker` pool.

3. **If a separate worker-cnf pool is required:** Add a third worker node so
   the `worker` pool has 2 nodes.

4. **Recovery from a stuck cluster:** If nodes are already stuck in
   `SchedulingDisabled`:
   ```bash
   # Manually uncordon one worker to break the deadlock
   oc adm uncordon <worker-node-name>

   # The drain controller may re-cordon it. If so, scale down the
   # machine-config-controller temporarily:
   oc scale deployment/machine-config-controller -n openshift-machine-config-operator --replicas=0

   # Uncordon the worker and wait for pods to reschedule
   oc adm uncordon <worker-node-name>

   # Once pods are running and PDB allows disruptions, scale MCC back up
   oc scale deployment/machine-config-controller -n openshift-machine-config-operator --replicas=1
   ```

5. **Monitoring for the issue:** Watch for these log patterns in the
   `machine-config-controller` pod:
   ```
   error when evicting pods/... (will retry after 0s):
     Cannot evict pod as it would violate the pod's disruption budget
   ```
   ```
   Drain failed. Waiting 1 minute then retrying.
   ```
   ```
   Drain has been failing for more than 10 minutes.
   ```

---

## Related files

All paths are relative to the
[numaresources-operator](https://github.com/openshift-kni/numaresources-operator)
repository root.

| File | Purpose |
|---|---|
| `cmd/main.go` | TLS profile fetch, metrics/webhook server setup, `SecurityProfileWatcher` |
| `config/rbac/service.yaml` | Metrics Service with `serving-cert-secret-name` annotation |
| `config/manager/manager.yaml` | Deployment with `/certs` volume mount |
| `config/prometheus/monitor.yaml` | ServiceMonitor for Prometheus scraping over TLS |
| `config/crd/patches/webhook_in_*.yaml` | CRD conversion webhook patches (commented out) |
| `config/manifests/kustomization.yaml` | OLM webhook cert volume patch documentation |
| `config/networkpolicy/ingress-to-metrics.yaml` | Optional NetworkPolicy allowing TCP 8080 |
| `pkg/metrics/manifests/yaml/service.yaml` | RTE metrics Service with `serving-cert-secret-name` |
| `pkg/objectupdate/tls/tls.go` | `Settings` struct and `NewSettings` — converts `tls.Config` to operand arg strings, including numeric curve IDs |
| `pkg/objectupdate/sched/sched.go` | `DeploymentTLSSettings` — writes `--tls-min-version`, `--tls-cipher-suites` and `--tls-curve-preferences` to scheduler container args |
| `pkg/objectupdate/rte/rte.go` | `DaemonSetArgs` — writes `--metrics-tls-min-version`, `--metrics-tls-cipher-suites` and `--metrics-tls-curve-preferences` to RTE container args |
| `test/internal/tls/tls.go` | TLS probing utilities (`ProbeMaxTLSVersion`, `ProbeTLSCipher`, `ProbeTLSSettings`, `FetchMetrics`, etc.) |
| `test/internal/tls/tls_test.go` | Unit tests for TLS probing and conversion utilities |
| `internal/api/features/_topics.json` | Feature topic registry — includes `"tlscompliance"` |
| `test/e2e/tls/tls_test.go` | Non-disruptive TLS compliance E2E tests (positive + negative) |
| `test/e2e/tls/tls_suite_test.go` | TLS test suite entry point |
| `test/e2e/serial/tests/configuration.go` | Serial/disruptive TLS profile modification test |
| `test/internal/clients/clients.go` | E2E test client initialization — registers `configv1` scheme for TLS tests |
| `vendor/.../controller-runtime-common/pkg/tls/tls.go` | `FetchAPIServerTLSProfile`, `NewTLSConfigFromProfile` |
