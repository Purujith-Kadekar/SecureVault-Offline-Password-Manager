#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  state_coordinator.h — F10: State Machine Coordination Layer
// ═══════════════════════════════════════════════════════════════════════════════
//  Purpose: Provides formal coordination for the 5+ informal state machines
//  that operate concurrently (Screen, HidMode, ModeSwitchState, SecState,
//  RxState). Before a mode transition (BLE→AP, BLE→Dashboard, etc.), the
//  coordinator validates that all dependent state machines are in a valid
//  state. If a transition fails midway, the coordinator rolls back to the
//  previous state and logs the failure.
//
//  Design:
//    - Lightweight: no dynamic allocation, no FreeRTOS primitives beyond
//      what the individual state machines already use.
//    - Transition logging: each attempt is logged to Serial for debugging.
//    - Rollback: on failure, the coordinator restores the previous state
//      machine states from a saved snapshot.
//    - Each state machine registers itself with the coordinator so it can
//      be queried for validity before transitions.
//
//  Usage:
//    StateMachineCoordinator coord;
//    coord.registerStateMachine("screen", ...);
//    coord.registerStateMachine("hidMode", ...);
//    bool ok = coord.beginTransition(HidMode::AP, Screen::AP_INFO);
//    if (!ok) coord.rollback();  // restores previous state
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

// Maximum number of state machines the coordinator can track.
#define SC_MAX_STATE_MACHINES 8

// Maximum transition log entries (ring buffer for diagnostics).
#define SC_LOG_SIZE 16

// ── State machine descriptor ────────────────────────────────────────────────
// Each state machine provides a name, a current-state query, and a
// validation function that returns true if the state machine is in a
// state that allows the requested transition.
struct StateMachineDesc {
  const char* name;                          // human-readable name for logging
  bool (*isValidForTransition)(void* ctx);   // returns true if ready for transition
  void* ctx;                                 // opaque context (usually the manager instance)
  bool registered;                           // true if this slot is occupied
};

// ── Transition log entry ────────────────────────────────────────────────────
struct TransitionLogEntry {
  unsigned long timestamp;
  const char* fromState;    // e.g. "BLE" or "LOCK"
  const char* toState;      // e.g. "AP" or "AP_INFO"
  bool success;
  const char* failureReason; // nullptr on success, descriptive on failure
};

class StateMachineCoordinator {
public:
  StateMachineCoordinator() = default;

  // ── Registration ────────────────────────────────────────────────────────
  // Register a state machine with the coordinator. Returns true on success.
  // Each state machine must provide:
  //   - name: for logging (e.g. "screen", "hidMode", "serialRx")
  //   - isValidFn: predicate that returns true when the state machine
  //     is in a valid state for the upcoming transition
  //   - ctx: opaque pointer passed to isValidFn (usually the manager)
  bool registerStateMachine(const char* name,
                            bool (*isValidFn)(void*),
                            void* ctx = nullptr);

  // ── Transition lifecycle ────────────────────────────────────────────────
  // beginTransition(): saves a snapshot of all registered state machine
  //   validity states, then checks that ALL registered machines are valid
  //   for the transition. Returns true if all checks pass.
  //   If any check fails, logs the failure and returns false — the caller
  //   should call rollback() to restore the previous state.
  //
  // completeTransition(): marks the transition as successful and logs it.
  //   Call this AFTER the new mode has been fully initialized.
  //
  // rollback(): restores state machine states to the snapshot saved by
  //   beginTransition(). Intended for use when a transition fails midway.
  //   The rollback mechanism is cooperative — each state machine must
  //   implement its own rollback logic. This coordinator provides the
  //   bookkeeping and logging.
  bool beginTransition(const char* fromState, const char* toState);
  void completeTransition(const char* fromState, const char* toState);
  void rollback();

  // ── Diagnostics ─────────────────────────────────────────────────────────
  // Print the transition log to Serial (for debugging).
  void printLog() const;

  // Returns the number of registered state machines.
  int getRegisteredCount() const;

  // Returns true if a transition is currently in progress.
  bool isTransitionInProgress() const { return _transitionInProgress; }

private:
  StateMachineDesc _machines[SC_MAX_STATE_MACHINES];
  int _machineCount = 0;

  // Snapshot of validity states saved at beginTransition() for rollback.
  bool _snapshot[SC_MAX_STATE_MACHINES];
  int _snapshotCount = 0;

  // Transition log ring buffer.
  TransitionLogEntry _log[SC_LOG_SIZE];
  int _logHead = 0;
  int _logCount = 0;

  bool _transitionInProgress = false;
  const char* _pendingFrom = nullptr;
  const char* _pendingTo = nullptr;

  void _addLogEntry(const char* from, const char* to, bool success,
                    const char* reason = nullptr);
};

// ── Global coordinator instance ────────────────────────────────────────────
// Created in main.cpp, passed by reference/pointer to components that
// need to register or query it.
extern StateMachineCoordinator stateCoord;
