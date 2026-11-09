# Fast Mode & Selective Tool Configuration

This guide explains how to use **Fast Mode** (`kubernetes/fast`) to drastically reduce LLM token usage, and how to use the **`disableAllByDefault`** setting to disable all default toolsets and only enable the specific tools you want.

---

## 1. What is Fast Mode (`kubernetes/fast`)?

By default, HolmesGPT uses `kubernetes/core` which provides broad `kubectl get ... | jq` and tabular query capabilities. When troubleshooting or running health checks, large language models often fetch entire clusters or namespaces, consuming **thousands of tokens** scanning healthy pods.

**Fast Mode (`kubernetes/fast`)** runs preliminary filtering locally in Python before any data reaches the LLM:
* Queries the Kubernetes API directly via the client library.
* Scans all pods in the cluster or a target namespace.
* Discards healthy pods completely.
* Returns a condensed JSON report containing **only** crashed, failing, or restarting pods:
  * `CrashLoopBackOff`, `ImagePullBackOff`, `ErrImagePull`, `CreateContainerConfigError`
  * Terminated containers with non-zero exit codes (e.g. `OOMKilled` / exit code 137)
  * Containers with non-zero restart counts
  * Pods in `Failed`, `Unknown`, or `Evicted` states
* If the cluster is healthy, it returns an empty list, allowing the LLM to verify health in **~30 tokens**.

---

## 2. Using `disableAllByDefault` in Helm

Normally, HolmesGPT enables 8 default toolsets (`kubernetes/core`, `kubernetes/logs`, `robusta`, `internet`, `prometheus/metrics`, `skills`, `connectivity_check`, `bash`).

To turn off all tools and only enable `kubernetes/fast`:

### In `values.yaml` or your custom Helm values:

```yaml
# Disable all default toolsets
disableAllByDefault: true

# Only enable the toolsets you explicitly want
toolsets:
  kubernetes/fast:
    enabled: true
  # Optionally enable logs if you want Holmes to inspect pod logs for crashed pods:
  # kubernetes/logs:
  #   enabled: true
```

With this setting, Holmes will **only** load `kubernetes/fast`. No other tools will be loaded, eliminating unneeded API calls and prompt overhead.

---

## 3. Using Fast Mode in Health Checks (CRDs)

You can also control toolsets per health check, allowing full toolsets for general investigation while keeping automated checks fast and cheap.

### Scheduled Health Check Example (`ScheduledHealthCheck`):

```yaml
apiVersion: holmesgpt.dev/v1alpha1
kind: ScheduledHealthCheck
metadata:
  name: hourly-crashed-pods
  namespace: holmes
spec:
  schedule: "0 * * * *"
  query: "Check for any crashed or restarting pods in the cluster"
  # Disables all other toolsets for this check:
  disableAllByDefault: true
  toolsets:
    kubernetes/fast:
      enabled: true
```

### Triggered Health Check Example (`TriggeredHealthCheck`):

```yaml
apiVersion: holmesgpt.dev/v1alpha1
kind: TriggeredHealthCheck
metadata:
  name: rollout-crashed-pod-check
  namespace: holmes
spec:
  deploymentRollout:
    selector:
      matchLabels:
        app: backend
  delaySeconds: 120
  query: "Did the rollout of {{ .deployment }} cause any crashed or restarting pods?"
  disableAllByDefault: true
  toolsets:
    kubernetes/fast:
      enabled: true
```

---

## 4. Using Fast Mode from the Command Line (`holmes ask`)

### Local Config File (`~/.holmes/config.yaml`):

```yaml
toolsets:
  kubernetes/fast:
    enabled: true
  kubernetes/core:
    enabled: false
  bash:
    enabled: false
```

### Run a query:

```bash
# Ask Holmes using kubernetes_fast:
holmes ask "Are there any crashed pods in the cluster?"
```

Holmes will invoke `kubernetes_fast` and return an immediate, token-efficient diagnosis.

