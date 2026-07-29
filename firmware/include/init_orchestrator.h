#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  init_orchestrator.h — F14: Initialization Orchestrator for Boot Sequence
// ═══════════════════════════════════════════════════════════════════════════════
//  Purpose: Replaces the 200-line procedural init chain in main.cpp setup()
//  with a dependency-aware initialization sequence. Each component declares
//  its dependencies as a directed graph. The orchestrator initializes
//  components in topological order, skipping those whose dependencies
//  failed. Failed components are marked unavailable; dependent components
//  adapt (e.g., vault skips SD if SD init failed, UI shows "no RTC" if
//  RTC init failed).
//
//  Design:
//    - Directed acyclic graph (DAG) of component dependencies.
//    - Topological sort for initialization order.
//    - Each component: name, init function, dependencies list, status.
//    - Failed init → component marked UNAVAILABLE, dependent components
//      warned but allowed to proceed (they must adapt).
//    - Initialization graph and any failures logged at boot.
//
//  The orchestrator does NOT own the component instances. It only calls
//  their begin() methods in the correct order and tracks status.
//  Component instances (disp, rtc, mpu, etc.) are still globals in
//  main.cpp, as they were before — the orchestrator just sequences them.
//
//  Dependency graph (current firmware):
//
//    Serial ──────────────────────────────────────────────┐
//    LittleFS ────────────────────────────────────────────┤
//    Display ─────────────────────────────────────────────┤
//    RTC ─────────────────────────────────────────────────┤
//    I2C (shared bus) ← RTC brings up I2C ───────────────┤
//    MPU ← I2C ──────────────────────────────────────────┤
//    EEPROM ← I2C ───────────────────────────────────────┤
//    INA219 ← I2C ───────────────────────────────────────┤
//    Buttons ─────────────────────────────────────────────┤
//    SD ──────────────────────────────────────────────────┤
//    Audio ───────────────────────────────────────────────┤
//    BLE ─────────────────────────────────────────────────┤
//    Vault ← SD ──────────────────────────────────────────┤
//    SessionContext ──────────────────────────────────────┤
//    UI ← Vault, Display, RTC, MPU, Buttons, BLE, Audio, │
//         SerialProtocol, Duress, INA219, SessionContext  │
//    SettingsManager ← LittleFS, SD, NVS ────────────────┘
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

// ── Maximum components and dependencies ────────────────────────────────────
#define IO_MAX_COMPONENTS  32   // v11.0: increased from 20 (was at exact capacity)
#define IO_MAX_DEPS_PER    5
#define IO_MAX_DEP_LEN     16   // max length of a dependency name string

// ── Component init result ──────────────────────────────────────────────────
enum class InitStatus : uint8_t {
  PENDING     = 0,   // not yet initialized
  OK          = 1,   // initialized successfully
  UNAVAILABLE = 2,   // init failed or dependency failed
  SKIPPED     = 3,   // skipped because a dependency is UNAVAILABLE
};

// ── Component descriptor ──────────────────────────────────────────────────
// Each component has:
//   - name: for logging (e.g. "RTC", "SD", "Vault")
//   - initFn: function pointer to call for initialization. Returns bool.
//     nullptr = no init needed (component is already initialized externally).
//   - deps: array of dependency names (indices into the component array).
//   - depCount: number of dependencies.
//   - required: if true, dependent components will be SKIPPED if this one
//     is UNAVAILABLE. If false, dependent components will just be warned.
//   - status: current init status (tracked by the orchestrator).
struct InitComponent {
  const char* name;
  bool (*initFn)(void);                  // returns true on success
  char depStorage[IO_MAX_DEPS_PER][IO_MAX_DEP_LEN]; // OWNED copies of dep names
  const char* deps[IO_MAX_DEPS_PER];     // pointers into depStorage[] (not dangling!)
  int depCount;
  bool required;                          // true = hard dependency, false = soft
  InitStatus status;
};

// ── Init orchestrator class ────────────────────────────────────────────────
class InitOrchestrator {
public:
  InitOrchestrator() = default;

  // ── Registration ──────────────────────────────────────────────────────
  // Add a component to the initialization graph. Must be called before run().
  // Parameters:
  //   name: unique component name (used for dependency matching)
  //   initFn: the begin() function to call (returns bool)
  //   required: true = hard dependency (dependent components skip if this fails)
  //   deps: comma-separated dependency names (e.g. "RTC,I2C" or nullptr)
  bool addComponent(const char* name, bool (*initFn)(void),
                    bool required = true,
                    const char* deps = nullptr);

  // ── Execution ─────────────────────────────────────────────────────────
  // Run the initialization sequence in dependency order (topological sort).
  // For each component:
  //   1. Check all dependencies are OK (or not required).
  //   2. If a hard dependency is UNAVAILABLE, mark this component SKIPPED.
  //   3. Call initFn(). If it returns false, mark UNAVAILABLE.
  //   4. If initFn() returns true, mark OK.
  // Prints the init graph and results to Serial.
  void run();

  // ── Query ─────────────────────────────────────────────────────────────
  // Get the init status of a component by name.
  InitStatus getStatus(const char* name) const;

  // Check if a component is available (OK status).
  bool isAvailable(const char* name) const;

  // Print the initialization results summary to Serial.
  void printResults() const;

private:
  InitComponent _components[IO_MAX_COMPONENTS];
  int _count = 0;

  // Find a component by name. Returns -1 if not found.
  int _findComponent(const char* name) const;

  // Resolve dependency names into component indices.
  void _resolveDependencies();

  // Check if all dependencies of a component are satisfied.
  // Returns true if all hard deps are OK and all soft deps are OK/UNAVAILABLE.
  bool _depsSatisfied(int idx) const;

  // Topological sort — returns indices in init order.
  // Uses Kahn's algorithm (BFS-based, O(V+E)).
  int _topoSort(int out[], int outLen) const;
};
