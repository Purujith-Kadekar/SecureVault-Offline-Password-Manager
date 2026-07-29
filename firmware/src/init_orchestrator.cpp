// ═══════════════════════════════════════════════════════════════════════════════
//  init_orchestrator.cpp — F14: Initialization Orchestrator for Boot Sequence
// ═══════════════════════════════════════════════════════════════════════════════
#include "init_orchestrator.h"
#include <cstring>

bool InitOrchestrator::addComponent(const char* name, bool (*initFn)(void),
                                     bool required, const char* deps) {
  if (_count >= IO_MAX_COMPONENTS) {
    Serial.printf("[F14-ERROR] Cannot add component '%s' — max %d reached\n", name, IO_MAX_COMPONENTS);
    return false;
  }
  if (!name) return false;

  _components[_count].name = name;
  _components[_count].initFn = initFn;
  _components[_count].required = required;
  _components[_count].status = InitStatus::PENDING;
  _components[_count].depCount = 0;

  // Parse comma-separated dependency names.
  // CRITICAL FIX: Store OWNED copies of dependency strings in depStorage[],
  // not dangling pointers into a local stack buf[]. The previous version used
  // strtok() on a local buf[64] and stored the resulting pointers directly in
  // deps[]. When addComponent() returned, buf was destroyed, making all deps[]
  // pointers dangling. This caused _findComponent() to compare garbage strings,
  // which silently skipped INA219 (→ battery=0%) and Vault (→ empty vault).
  if (deps && strlen(deps) > 0) {
    char buf[64];
    strncpy(buf, deps, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char* tok = strtok(buf, ",");
    while (tok && _components[_count].depCount < IO_MAX_DEPS_PER) {
      while (*tok == ' ') tok++;
      // Store an OWNED copy in depStorage[] — survives after addComponent() returns.
      int di = _components[_count].depCount;
      strncpy(_components[_count].depStorage[di], tok, IO_MAX_DEP_LEN - 1);
      _components[_count].depStorage[di][IO_MAX_DEP_LEN - 1] = '\0';
      _components[_count].deps[di] = _components[_count].depStorage[di];  // pointer into owned storage
      _components[_count].depCount++;
      tok = strtok(nullptr, ",");
    }
  }

  _count++;
  return true;
}

int InitOrchestrator::_findComponent(const char* name) const {
  if (!name) return -1;
  for (int i = 0; i < _count; i++) {
    if (strcmp(_components[i].name, name) == 0) return i;
  }
  return -1;
}

void InitOrchestrator::_resolveDependencies() {
  // Nothing to resolve — deps are stored as name strings, resolved
  // at runtime by _findComponent().
}

bool InitOrchestrator::_depsSatisfied(int idx) const {
  const InitComponent& c = _components[idx];
  for (int d = 0; d < c.depCount; d++) {
    int depIdx = _findComponent(c.deps[d]);
    if (depIdx < 0) {
      // Dependency not registered at all. For a hard (required=true) component,
      // missing deps are fatal. For a soft (required=false) component, just warn.
      // This shouldn't happen if all components are registered before run().
      if (c.required) return false;
      continue;
    }
    InitStatus depStatus = _components[depIdx].status;
    if (depStatus != InitStatus::OK) {
      // Dependency failed/unavailable. Use the CURRENT component's `required`
      // flag to decide if this is fatal — NOT the dependency's `required` flag.
      // A soft component (INA219, required=false) should proceed even if its
      // hard dependency (RTC, required=true) failed. The `required` flag means
      // "is THIS component essential for the system", not "is its dependency
      // essential". Hard components (Vault) must have all deps satisfied.
      if (c.required) return false;
      // Soft component — dependency failure is a warning, not a blocker.
    }
  }
  return true;
}

// ── Topological sort (Kahn's algorithm) ──────────────────────────────────
int InitOrchestrator::_topoSort(int out[], int outLen) const {
  if (outLen < _count) return 0;

  // Build in-degree array.
  int inDegree[IO_MAX_COMPONENTS] = {0};
  for (int i = 0; i < _count; i++) {
    for (int d = 0; d < _components[i].depCount; d++) {
      int depIdx = _findComponent(_components[i].deps[d]);
      if (depIdx >= 0) {
        // i depends on depIdx, so depIdx must come before i.
        // Increment i's in-degree (it has one more prerequisite).
        inDegree[i]++;
      }
    }
  }

  // Start with nodes that have in-degree 0 (no prerequisites).
  int queue[IO_MAX_COMPONENTS];
  int queueLen = 0;
  for (int i = 0; i < _count; i++) {
    if (inDegree[i] == 0) {
      queue[queueLen++] = i;
    }
  }

  int outIdx = 0;
  while (queueLen > 0) {
    // Dequeue front.
    int node = queue[0];
    // Shift queue left.
    for (int i = 1; i < queueLen; i++) queue[i - 1] = queue[i];
    queueLen--;

    out[outIdx++] = node;

    // For each node that depends on this one, decrement in-degree.
    for (int i = 0; i < _count; i++) {
      for (int d = 0; d < _components[i].depCount; d++) {
        int depIdx = _findComponent(_components[i].deps[d]);
        if (depIdx == node) {
          inDegree[i]--;
          if (inDegree[i] == 0) {
            queue[queueLen++] = i;
          }
        }
      }
    }
  }

  // If not all nodes were processed, there's a cycle.
  if (outIdx < _count) {
    Serial.printf("[F14-ERROR] Dependency cycle detected — only %d/%d components sorted\n",
                 outIdx, _count);
  }

  return outIdx;
}

void InitOrchestrator::run() {
  Serial.println("═══════════ F14: Initialization Orchestrator ═══════════");
  Serial.printf("  Registered components: %d\n", _count);

  // Print the dependency graph.
  Serial.println("  Dependency graph:");
  for (int i = 0; i < _count; i++) {
    Serial.printf("    %s ← [", _components[i].name);
    for (int d = 0; d < _components[i].depCount; d++) {
      if (d > 0) Serial.print(", ");
      Serial.print(_components[i].deps[d]);
    }
    Serial.printf("] (required=%s)\n", _components[i].required ? "yes" : "no");
  }

  // Topological sort.
  int order[IO_MAX_COMPONENTS];
  int orderLen = _topoSort(order, _count);

  Serial.printf("  Init order: ");
  for (int i = 0; i < orderLen; i++) {
    if (i > 0) Serial.print(" → ");
    Serial.print(_components[order[i]].name);
  }
  Serial.println();

  // Execute initialization in topological order.
  for (int i = 0; i < orderLen; i++) {
    int idx = order[i];
    InitComponent& c = _components[idx];

    // Check dependencies.
    if (!_depsSatisfied(idx)) {
      c.status = InitStatus::SKIPPED;
      Serial.printf("[F14-SKIP] %s — dependency not satisfied\n", c.name);
      continue;
    }

    // Check if a soft dependency failed (warn but proceed).
    for (int d = 0; d < c.depCount; d++) {
      int depIdx = _findComponent(c.deps[d]);
      if (depIdx >= 0 && _components[depIdx].status != InitStatus::OK) {
        Serial.printf("[F14-WARN] %s — soft dependency '%s' is unavailable (status=%d)\n",
                     c.name, _components[depIdx].name,
                     (int)_components[depIdx].status);
      }
    }

    // Call init function.
    if (!c.initFn) {
      // No init function — assume already initialized externally.
      c.status = InitStatus::OK;
      Serial.printf("[F14-OK]   %s — (no initFn, assumed OK)\n", c.name);
      continue;
    }

    Serial.printf("[F14-INIT] %s — calling begin()...\n", c.name);
    bool ok = c.initFn();
    if (ok) {
      c.status = InitStatus::OK;
      Serial.printf("[F14-OK]   %s — initialized successfully\n", c.name);
    } else {
      c.status = InitStatus::UNAVAILABLE;
      Serial.printf("[F14-FAIL] %s — initialization FAILED\n", c.name);
    }
  }

  Serial.println("═══════════════════════════════════════════════════════════");
  printResults();
}

InitStatus InitOrchestrator::getStatus(const char* name) const {
  int idx = _findComponent(name);
  if (idx < 0) return InitStatus::UNAVAILABLE;
  return _components[idx].status;
}

bool InitOrchestrator::isAvailable(const char* name) const {
  return getStatus(name) == InitStatus::OK;
}

void InitOrchestrator::printResults() const {
  Serial.println("═══════════ F14: Initialization Results ═══════════");
  for (int i = 0; i < _count; i++) {
    const InitComponent& c = _components[i];
    const char* statusStr;
    switch (c.status) {
      case InitStatus::PENDING:     statusStr = "PENDING"; break;
      case InitStatus::OK:          statusStr = "OK"; break;
      case InitStatus::UNAVAILABLE: statusStr = "UNAVAILABLE"; break;
      case InitStatus::SKIPPED:     statusStr = "SKIPPED"; break;
      default:                      statusStr = "???"; break;
    }
    Serial.printf("  %-16s %s\n", c.name, statusStr);
  }
  Serial.println("═══════════════════════════════════════════════════════════");
}
