# Fast Mode (`kubernetes/fast` & `kubernetes/logs_fast`) and Selective Tool Configuration

This guide explains how to use **Fast Mode** (`kubernetes/fast` and `kubernetes/logs_fast`) to drastically reduce LLM token usage by running deterministic health and log analysis in Python, and how to use **`disableAllByDefault`** to disable all default toolsets and only enable the specific tools you want.

---

## 1. Fast Cluster Scanner (`kubernetes/fast`)

**`kubernetes/fast`** (`holmes/plugins/toolsets/kubernetes_fast/`) runs a comprehensive, read-only Kubernetes health scan locally in Python before any data reaches the LLM:
* Collects a single in-memory snapshot of the Kubernetes API via the Python client.
* Runs deterministic domain scanners across **17 health categories**:
  * **Pods & Containers**: `CrashLoopBackOff`, `OOMKilled` (exit code 137), `ImagePullBackOff`, `CreateContainerConfigError`, non-zero exit codes, elevated restarts, stuck `Terminating` pods (with blocking finalizers), `Running` pods with `Ready=False`.
  * **Workloads**: `Deployments`, `ReplicaSets`, `StatefulSets` (missing ordinals, governing Service), `DaemonSets`, `Jobs`, and `CronJobs`.
  * **Nodes**: `NotReady`/`Unknown`, `MemoryPressure`, `DiskPressure`, `PIDPressure`, `NetworkUnavailable`, cordoned nodes, CPU/memory request commitment vs allocatable, and live `metrics.k8s.io` usage.
  * **Scheduling**: `Pending`/`Unschedulable` pods with parsed reasons (insufficient CPU/memory/GPU, taint/affinity/topology conflicts, unbound PVCs).
  * **Networking & DNS**: `Services` with 0 matching pods or 0 ready endpoints, `targetPort` vs `containerPort` mismatches, `CoreDNS`/`kube-dns` availability, `Ingress`/`Gateway` broken backends or missing TLS Secrets, and `NetworkPolicies` (e.g. accidental DNS port 53 blocks).
  * **Storage**: `PVCs` (`Pending`, `Lost`, missing `StorageClass`), `PVs` (`Failed`, `Released`), `StorageClasses`, and `VolumeAttachments`.
  * **Quotas & Autoscaling**: `ResourceQuotas` near/at 100%, `HPAs` (`AbleToScale=False`, `ScalingActive=False`, maxed out), and `PDBs` (`disruptionsAllowed=0`).
  * **Config, Security, Certificates & Webhooks**: Dangling `ConfigMap`/`Secret`/`ServiceAccount`/`RBAC` references, TLS certificate expiry countdowns, and `Validating`/`MutatingWebhookConfigurations` with `failurePolicy: Fail` and 0 ready endpoints.
  * **Cluster Ops**: `Namespaces` stuck `Terminating`, `kube-system` control-plane/system components, grouped `Warning` `Events` (filtering out stale events), and dynamic `CustomResourceDefinition` condition checks.
  * **Cross-Resource Root-Cause Correlation**: Automatically links cascading failures (e.g. a single `NotReady` node degrading 12 pods, or a missing `Secret` stalling a `Deployment` and `Service`) into `correlatedRootCauses`.
* **Minimal Token Output**: Healthy categories collapse to a single key/value (e.g. `"ingress_and_gateway": "healthy"`), and only discovered issues are returned in `findings`.

---

## 2. Fast Log Analysis Engine (`kubernetes/logs_fast`)

**`kubernetes/logs_fast`** (`holmes/plugins/toolsets/kubernetes_logs_fast/`, tool name: `logs_fast`) scrapes container logs (current, `--previous`, and init containers) in parallel, sifts them in Python, and returns **only** deduplicated error/warning findings:
* **Declarative YAML Pattern Library**:
  * [`default_rules.yaml`](file:///Users/strawbs/holmesgpt/holmes/plugins/toolsets/kubernetes_logs_fast/rules/default_rules.yaml): 17 built-in categories (`memory`, `kubernetes`, `disk_filesystem`, `container_runtime`, `control_plane`, `database`, `network`, `dns_discovery`, `certificate_tls`, `auth_security`, `storage_volume`, `app_lifecycle`, `messaging_queue`, `http_application`, `cpu_performance`, `general_error`, `warning`).
  * [`language_rules.yaml`](file:///Users/strawbs/holmesgpt/holmes/plugins/toolsets/kubernetes_logs_fast/rules/language_rules.yaml): Toggleable runtime rules for `java`, `python`, `nodejs`, `go`, and `dotnet`.
* **Structured JSON & Multiline Stack Trace Parsing**:
  * Understands JSON log fields (`level`, `severity`, `message`, `error`, `exception`, `error_code`, `stack`) so `level="info"` with `"error": null` is never misclassified as an error.
  * Coalesces multiline stack traces (Java, Python, Go, Node.js, .NET) into a single finding.
* **Fingerprint Deduplication**: Collapses hundreds of repeated error lines into 1 finding with `occurrences`, `firstTimestamp`, `lastTimestamp`, and a sample log.
* **Behavioural Anomaly Detection**: Detects rapid retry/backoff loops (`BEHAV-001`), connection/readiness flapping (`BEHAV-002`), auth failure spikes (`BEHAV-003`), startup-then-immediate-exit (`BEHAV-004`), and transaction rollbacks (`BEHAV-005`).
* **Collection Failure Tracking**: Reports RBAC denials, `ContainerCreating`, deleted pods, or timeouts in `collectionErrors` so failed log collection never produces a false `"healthy"` report.

---

## 3. Using `disableAllByDefault` in Helm

To turn off all default tools and only enable `kubernetes/fast` and `kubernetes/logs_fast`:

```yaml
# Disable all default toolsets
disableAllByDefault: true

# Only enable the fast Python scanners
toolsets:
  kubernetes/fast:
    enabled: true
    config:
      restart_warning_threshold: 3
      restart_critical_threshold: 10
      pending_pod_minutes: 5
      event_lookback_minutes: 30
      include_config_risks: false
  kubernetes/logs_fast:
    enabled: true
    config:
      lines_per_container: 500
      lines_per_pod: 1500
      lines_per_namespace: 10000
      total_lines_per_scan: 30000
      max_log_size_mb: 20
      since_seconds: 3600
      concurrent_workers: 8
      include_warnings: true
      enabled_languages: ["java", "python", "nodejs", "go", "dotnet"]
      custom_rules:
        - id: CUSTOM-001
          name: Custom payment gateway failure
          category: billing
          severity: critical
          patterns: ["PAYMENT_GATEWAY_REJECTED"]
          description: "Payment gateway rejected transaction."
```

---

## 4. Using Fast Mode in Health Checks (CRDs)

### Scheduled Health Check Example (`ScheduledHealthCheck`):

```yaml
apiVersion: holmesgpt.dev/v1alpha1
kind: ScheduledHealthCheck
metadata:
  name: hourly-fast-cluster-and-log-check
  namespace: holmes
spec:
  schedule: "0 * * * *"
  query: "Run a fast cluster health scan and check container logs for any errors"
  disableAllByDefault: true
  toolsets:
    kubernetes/fast:
      enabled: true
    kubernetes/logs_fast:
      enabled: true
```

### Triggered Health Check Example (`TriggeredHealthCheck`):

```yaml
apiVersion: holmesgpt.dev/v1alpha1
kind: TriggeredHealthCheck
metadata:
  name: rollout-fast-check
  namespace: holmes
spec:
  deploymentRollout:
    selector:
      matchLabels:
        app: backend
  delaySeconds: 120
  query: "Did the rollout of {{ .deployment }} cause any pod failures or log errors?"
  disableAllByDefault: true
  toolsets:
    kubernetes/fast:
      enabled: true
    kubernetes/logs_fast:
      enabled: true
```

---

## 5. Running from the CLI & Viewing Raw Scanner Output

```bash
# Run holmes ask and display raw JSON output from kubernetes_fast and logs_fast:
poetry run holmes ask --show-tool-output "Scan the cluster and logs for any problems"

# Run the fast log scanner directly in Python (without calling the LLM):
poetry run python -c "
import json, logging
from holmes.plugins.toolsets.kubernetes_logs_fast import run_log_scan

logging.basicConfig(level=logging.INFO)
print(json.dumps(run_log_scan(), indent=2))
"
```
