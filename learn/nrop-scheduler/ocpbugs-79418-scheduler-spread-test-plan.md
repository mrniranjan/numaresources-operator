# OCPBUGS-79418: Scheduler Deployment Spread — E2E Test Plan

**Feature:** NUMA-aware (secondary) scheduler pods spread across nodes via `topologySpreadConstraints`  
**Jira:** [OCPBUGS-79418](https://issues.redhat.com/browse/OCPBUGS-79418)  
**Related code:** [`test/e2e/sched/sched_test.go`](../test/e2e/sched/sched_test.go)  
**Technical background:** [OCPBUGS-79418 Scheduler Deployment Spread — Technical Document](ocpbugs-79418-scheduler-topology-spread.md)

---

## Global prerequisites (all tests)

| Item | Requirement |
|------|-------------|
| Cluster | OpenShift (or HyperShift for TP-79418-10 only) with NRO installed and healthy |
| Operator | `NUMAResourcesOperator` and `NUMAResourcesScheduler` CRs present and not Degraded |
| Scheduler deployment | `secondary-scheduler` Deployment exists in `openshift-numaresources` |
| Access | `oc` / e2e client with permission to get/update NRS CR, Deployment, Pods, and Nodes |
| Default NRS spec | For autodetect tests: `spec.replicas` **unset** (nil) unless the test says otherwise |

---

## TP-79418-01: Steady-state — each replica on a different node

**Tier:** 0 (existing E2E)  
**Maps to:** R1 — core customer bug fix  
**Automation reference:** `It("should have each replica running on a different node")`

### Setup

1. Cluster with **at least 3 schedulable control-plane nodes** (OpenShift) or **3 worker nodes** (HyperShift).
2. NRO installed; `NUMAResourcesScheduler` CR exists with **`spec.replicas` unset** (autodetect mode).
3. Scheduler Deployment reconciled and **Available**; replica count equals autodetected value (typically 3 on a 3-node cluster, capped at 3 on larger clusters).
4. Deployment pod template includes `topologySpreadConstraints` with `MaxSkew: 1`, `topologyKey: kubernetes.io/hostname`, `whenUnsatisfiable: DoNotSchedule`, `matchLabelKeys: [pod-template-hash]`.

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Get scheduler Deployment: `oc get deploy -n openshift-numaresources secondary-scheduler -o jsonpath='{.spec.replicas}'` | Replicas ≥ 2 (typically 3 on 3-CP cluster) |
| 2 | List scheduler pods: `oc get pods -n openshift-numaresources -l app=secondary-scheduler -o wide` | All pods `Running`; count matches Deployment replicas |
| 3 | Collect `NODE` column for each pod | **Each pod on a distinct node** — no two pods share the same node name |
| 4 | (Optional) Verify spread constraint on Deployment template | `topologySpreadConstraints` present as in Setup step 4 |

---

## TP-79418-02: Spread constraints present on Deployment

**Tier:** 0 (existing E2E — BeforeEach assertion)  
**Maps to:** R2 — operator applies spread rules  
**Automation reference:** `BeforeEach` in `When("testing deployment TopologySpreadConstraints")`

### Setup

1. Same as global prerequisites.
2. NRS CR reconciled at least once after operator version containing the fix.

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Get Deployment pod template spread constraints: `oc get deploy -n openshift-numaresources secondary-scheduler -o jsonpath='{.spec.template.spec.topologySpreadConstraints}'` | Exactly **one** constraint returned |
| 2 | Verify constraint fields | `maxSkew: 1` |
| 3 | Verify constraint fields | `topologyKey: kubernetes.io/hostname` |
| 4 | Verify constraint fields | `whenUnsatisfiable: DoNotSchedule` |
| 5 | Verify constraint fields | `matchLabelKeys` contains `pod-template-hash` |
| 6 | Verify constraint fields | `labelSelector.matchLabels` matches pod template labels (e.g. `app: secondary-scheduler`) |
| 7 | Confirm **no** required `podAntiAffinity` on scheduler Deployment | `podAntiAffinity` absent or not used for spread (fix uses topology spread, not anti-affinity) |

---

## TP-79418-03: Compact cluster — recreated pod stays Pending when spread impossible

**Tier:** 0 (existing E2E)  
**Maps to:** R5 — node failure on compact / full-capacity cluster  
**Automation reference:** `When("one host of a scheduler pod is down")`  
**Notes:** Disruptive; cordons nodes. Run serially.

### Setup

1. Cluster with **3 control-plane nodes** and scheduler autodetect → **3 replicas**, each on a **different** CP node (verify TP-79418-01 first).
2. Identify one scheduler pod and its node (`targetPod`, `targetNode`).
3. Ensure test can cordon/uncordon nodes (cluster-admin or equivalent).

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Verify initial spread: 3 running pods on 3 unique nodes | TP-79418-01 passes |
| 2 | Cordon **all cluster nodes except** the CP nodes that still host the **remaining** scheduler pods (after removing target node from the “keep” set). On a 3-CP compact cluster, cordon every node except the 2 CP nodes that still have a scheduler pod | Cordoned nodes show `SchedulingDisabled` |
| 3 | Delete the scheduler pod on `targetNode`: `oc delete pod -n openshift-numaresources <target-pod>` | Pod terminates; Deployment creates replacement |
| 4 | Wait for replacement pod to appear | New pod exists; phase **Pending** |
| 5 | Inspect pod events / conditions: `oc describe pod <recreated-pod>` | `PodScheduled=False`, reason **Unschedulable** |
| 6 | Read scheduling failure message | Message contains **`didn't match pod topology spread constraints`** (exact count may vary; e2e expects `(replicas - 1) node(s) didn't match...`) |
| 7 | Hold ~2 minutes; recheck pod phase | Pod **remains Pending** (no spurious schedule onto occupied node) |
| 8 | Uncordon all cordoned nodes | Nodes become schedulable |
| 9 | Wait for replacement pod | Pod transitions to **Running** |

---

## TP-79418-04: Explicit replicas exceed node count — Degraded status

**Tier:** 1 (proposed — not yet automated)  
**Maps to:** R3 — replica validation  
**Automation reference:** Unit tests in `numaresourcesscheduler_controller_test.go`; **E2E gap**

### Setup

1. Cluster with **N** schedulable control-plane nodes (OpenShift) or worker nodes (HyperShift); note **N**.
2. NRS CR healthy; **`spec.replicas` unset** initially.
3. Record current Deployment replica count and NRS status conditions for cleanup.

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Count target-role nodes: `oc get nodes -l node-role.kubernetes.io/control-plane --no-headers \| wc -l` (OpenShift) | Value **N** recorded |
| 2 | Set invalid replicas: patch NRS `spec.replicas: N + 1` | Patch accepted |
| 3 | Wait for operator reconcile (≤ 5 min) | NRS status shows **Degraded=True** |
| 4 | Read Degraded condition message | Contains **`explicitly set replicas count should not be greater than the number of the nodes with role`** |
| 5 | Check Deployment replicas | **Not** scaled to `N + 1` (unchanged from pre-test or operator does not apply invalid count) |
| 6 | Verify scheduler pods still running (if any before test) | Existing pods remain **Running**; no mass Pending deadlock |
| 7 | **Cleanup:** unset `spec.replicas` (nil) or restore original value | NRS returns to non-Degraded; Deployment reconciles to valid replica count |

---

## TP-79418-05: Worker fallback when control-plane slot unavailable

**Tier:** 1 (proposed — not yet automated)  
**Maps to:** R6 — multi-node cluster resilience  
**Notes:** Requires **worker nodes**. Disruptive (cordon one CP). Run serially.

### Setup

1. Cluster with **≥ 3 control-plane** and **≥ 2 worker** nodes.
2. Scheduler autodetect → 3 replicas on **3 distinct CP nodes** (TP-79418-01).
3. Identify scheduler pod on CP node to simulate failure (`targetPod`, `targetCP`).
4. Workers are **schedulable** (not cordoned).

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Confirm 3 scheduler pods Running on 3 CP nodes | Unique node per pod |
| 2 | Cordon **only** `targetCP`: `oc adm cordon <targetCP>` | Node `SchedulingDisabled` |
| 3 | Delete scheduler pod on `targetCP` | Pod deleted; replacement created |
| 4 | Wait for replacement pod scheduling (≤ 5 min) | New pod phase **Running** |
| 5 | Check replacement pod node | Pod scheduled on a **worker** node (soft CP affinity allows fallback) **OR** remains Pending if cluster policy prevents workers — document actual behavior |
| 6 | If Running on worker: verify no two scheduler pods on same node | **Max one scheduler pod per hostname** still holds |
| 7 | **Cleanup:** uncordon `targetCP` | Node schedulable again |

---

## TP-79418-06: Image rollout preserves spread across nodes

**Tier:** 1 (proposed — extend existing image-change test)  
**Maps to:** R8 — rollout-safe spread (no podAntiAffinity deadlock)  
**Automation reference:** Partial overlap with `It("should be able to handle plugin image change without remove/rename")`

### Setup

1. 3+ CP cluster; scheduler autodetect with **3 replicas** spread one-per-node.
2. Alternate scheduler image available for test (e.g. CI test image used in existing e2e).
3. Record UIDs and node names of current scheduler pods.

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Record pre-rollout placement: node name per scheduler pod | 3 unique nodes |
| 2 | Update NRS `spec.schedulerImage` to test image | CR update succeeds |
| 3 | Wait for Deployment rollout complete (≤ 10 min) | Deployment `Available=True`; updatedReplicaSet ready |
| 4 | List post-rollout scheduler pods | Count = autodetected replicas; all **Running** |
| 5 | Verify new pod UIDs differ from pre-rollout | Rollout occurred (new pods created) |
| 6 | Verify post-rollout node placement | **Each Running pod on a distinct node** |
| 7 | Confirm no pods stuck Pending beyond rollout timeout | Zero Pending pods after rollout settles |
| 8 | Verify `topologySpreadConstraints` unchanged on new template | Same spread spec as TP-79418-02 |
| 9 | **Cleanup:** revert `spec.schedulerImage` to original | Cluster returns to prior image; spread still holds |

---

## TP-79418-07: Operator restores spread after Deployment tampering

**Tier:** 1 (proposed — not yet automated)  
**Maps to:** R9 — reconcile enforces spread  
**Automation reference:** Partial overlap with `It("should react to owned objects changes")`

### Setup

1. Healthy scheduler Deployment with spread constraints (TP-79418-02).
2. 3 replicas Running, one per node (TP-79418-01).
3. Ability to patch Deployment directly (simulates manual drift).

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Export current Deployment generation and spread constraints | Baseline recorded |
| 2 | Patch Deployment: remove `spec.template.spec.topologySpreadConstraints` (set to `[]` or null) | Patch succeeds |
| 3 | Wait for operator reconcile (≤ 2 min, poll ~30 s) | Operator detects drift |
| 4 | Re-read Deployment spread constraints | **Constraints restored** to TP-79418-02 expected values |
| 5 | If rollout triggered, wait for Deployment complete | All desired replicas **Running** |
| 6 | Verify pod placement | Still **one pod per node** (or spread restored after rollout) |

---

## TP-79418-08: Two control-plane nodes — autodetect single replica

**Tier:** 2 (optional / environment-specific)  
**Maps to:** R4 — odd-size autodetect preference  
**Notes:** Requires 2-CP test cluster or simulated node count.

### Setup

1. Cluster with **exactly 2 schedulable control-plane nodes** (OpenShift).
2. NRS `spec.replicas` unset.

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Wait for NRS/Deployment reconcile | Deployment `spec.replicas: 1` |
| 2 | List scheduler pods | **1** Running pod |
| 3 | Verify spread constraints still on template | TP-79418-02 constraints present |
| 4 | Verify placement | Single pod on one CP node (spread trivially satisfied) |

---

## TP-79418-09: Four or more control-plane nodes — replica cap at 3 with spread

**Tier:** 2 (optional / large cluster)  
**Maps to:** R4 — `MaxSchedulerReplicas = 3`

### Setup

1. Cluster with **≥ 4 schedulable control-plane nodes**.
2. NRS `spec.replicas` unset.

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Get Deployment replicas | `spec.replicas: 3` (capped, not 4+) |
| 2 | List scheduler pods | **3** Running pods |
| 3 | Verify node placement | **3 distinct nodes** — no colocation |
| 4 | Verify spread constraints | TP-79418-02 |

---

## TP-79418-10: HyperShift — autodetect on workers with spread

**Tier:** 2 (HyperShift lane only)  
**Maps to:** R4 + R1 on HyperShift platform

### Setup

1. **HyperShift** cluster with ≥ 3 schedulable **worker** nodes.
2. NRO installed; platform detection = HyperShift.
3. NRS `spec.replicas` unset.

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Count worker nodes | **W** recorded (≥ 3) |
| 2 | Get Deployment replicas | `min(W, 3)` |
| 3 | List scheduler pods `-o wide` | All Running; count matches Deployment |
| 4 | Verify node placement | Each pod on a **distinct worker** hostname |
| 5 | Verify spread constraints on Deployment | TP-79418-02 |

---

## TP-79418-11: Customer workaround — explicit replicas when one CP is down

**Tier:** 2 (manual / customer repro)  
**Maps to:** Jira workaround; validates operational guidance  

### Setup

1. 3-CP cluster; scheduler autodetect → 3 replicas on 3 CP nodes.
2. One CP node marked unschedulable or failed (simulate one master down).

### Test steps

| Step | Action | Expected output |
|------|--------|-----------------|
| 1 | Cordon or drain one CP hosting a scheduler pod | Node unavailable for new schedules |
| 2 | Set NRS `spec.replicas: 2` explicitly | CR update succeeds |
| 3 | Wait for Deployment scale-down | **2** Running scheduler pods |
| 4 | Verify placement | **At most one pod per node**; pods on healthy nodes |
| 5 | Uncordon/recover failed CP | Node Ready and schedulable |
| 6 | Unset NRS `spec.replicas` (nil) — restore autodetect | Operator sets replicas back to 3 (if 3 CP healthy) |
| 7 | Wait for reconcile | 3 Running pods spread across 3 CP nodes |

---

## Test execution summary

| ID | Tier | Disruptive | Existing E2E | Priority to automate |
|----|------|------------|--------------|----------------------|
| TP-79418-01 | 0 | No | Yes | Done — add test_id label |
| TP-79418-02 | 0 | No | Yes (BeforeEach) | Done |
| TP-79418-03 | 0 | Yes | Yes | Done — mark Serial |
| TP-79418-04 | 1 | No | No | High |
| TP-79418-05 | 1 | Yes | No | High |
| TP-79418-06 | 1 | No | Partial | High |
| TP-79418-07 | 1 | No | No | Medium |
| TP-79418-08 | 2 | No | No | Low |
| TP-79418-09 | 2 | No | No | Low |
| TP-79418-10 | 2 | No | No | HyperShift lane |
| TP-79418-11 | 2 | Yes | No | Manual QA |

---

## Sign-off checklist (downstream / backport QA)

Use after running Tier 0 + applicable Tier 1 tests on target release (e.g. 4.20.z, 4.21.z):

- [ ] TP-79418-01 passed — no colocated scheduler pods
- [ ] TP-79418-02 passed — `topologySpreadConstraints` present (not `podAntiAffinity`)
- [ ] TP-79418-03 passed — Pending + spread message on compact failure; recovery works
- [ ] TP-79418-04 passed — invalid replica count Degraded
- [ ] TP-79418-06 passed — rollout does not break spread or deadlock
- [ ] NRS CR not Degraded in steady state
- [ ] Jira clone updated with cluster version, operator version, and `oc get pods -o wide` evidence
