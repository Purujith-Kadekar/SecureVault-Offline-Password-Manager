// ═══════════════════════════════════════════════════════════════════════════════
//  state_coordinator.cpp — F10: State Machine Coordination Layer
// ═══════════════════════════════════════════════════════════════════════════════
#include "state_coordinator.h"

StateMachineCoordinator stateCoord;

bool StateMachineCoordinator::registerStateMachine(const char* name,
                                                    bool (*isValidFn)(void*),
                                                    void* ctx) {
  if (_machineCount >= SC_MAX_STATE_MACHINES) return false;
  if (!name || !isValidFn) return false;

  _machines[_machineCount].name = name;
  _machines[_machineCount].isValidForTransition = isValidFn;
  _machines[_machineCount].ctx = ctx;
  _machines[_machineCount].registered = true;
  _machineCount++;

  Serial.printf("[F10] Registered state machine: %s\n", name);
  return true;
}

bool StateMachineCoordinator::beginTransition(const char* fromState, const char* toState) {
  if (_transitionInProgress) {
    Serial.printf("[F10-ERROR] Transition already in progress (%s → %s), cannot start %s → %s\n",
                 _pendingFrom ? _pendingFrom : "?", _pendingTo ? _pendingTo : "?",
                 fromState, toState);
    _addLogEntry(fromState, toState, false, "transition already in progress");
    return false;
  }

  // Save snapshot of all validity states for rollback.
  _snapshotCount = _machineCount;
  for (int i = 0; i < _machineCount; i++) {
    _snapshot[i] = _machines[i].isValidForTransition(_machines[i].ctx);
  }

  // Check all registered state machines are valid for this transition.
  bool allValid = true;
  for (int i = 0; i < _machineCount; i++) {
    bool valid = _machines[i].isValidForTransition(_machines[i].ctx);
    if (!valid) {
      Serial.printf("[F10-BLOCK] State machine '%s' is NOT valid for transition %s → %s\n",
                   _machines[i].name, fromState, toState);
      allValid = false;
    }
  }

  if (!allValid) {
    _addLogEntry(fromState, toState, false, "one or more state machines not valid");
    // Don't set _transitionInProgress — the transition was rejected.
    return false;
  }

  // All checks passed — mark transition as in progress.
  _transitionInProgress = true;
  _pendingFrom = fromState;
  _pendingTo = toState;

  Serial.printf("[F10] Transition %s → %s: all state machines valid, proceeding\n",
               fromState, toState);
  return true;
}

void StateMachineCoordinator::completeTransition(const char* fromState, const char* toState) {
  if (!_transitionInProgress) return;
  _transitionInProgress = false;
  _pendingFrom = nullptr;
  _pendingTo = nullptr;
  _addLogEntry(fromState, toState, true);
  Serial.printf("[F10] Transition %s → %s: completed successfully\n", fromState, toState);
}

void StateMachineCoordinator::rollback() {
  if (!_transitionInProgress) return;

  Serial.printf("[F10-ROLLBACK] Rolling back transition %s → %s\n",
               _pendingFrom ? _pendingFrom : "?", _pendingTo ? _pendingTo : "?");
  _addLogEntry(_pendingFrom, _pendingTo, false, "rolled back by caller");

  // Mark transition as no longer in progress.
  _transitionInProgress = false;
  _pendingFrom = nullptr;
  _pendingTo = nullptr;

  // The actual state restoration is cooperative — each state machine
  // must implement its own rollback logic. The coordinator's role here
  // is to log the rollback and clear the in-progress flag.
  // Components that called beginTransition() should restore their own
  // state from their saved snapshot.
  Serial.println("[F10-ROLLBACK] Coordinator cleared; components must restore own state");
}

int StateMachineCoordinator::getRegisteredCount() const {
  return _machineCount;
}

void StateMachineCoordinator::_addLogEntry(const char* from, const char* to,
                                            bool success, const char* reason) {
  _log[_logHead].timestamp = millis();
  _log[_logHead].fromState = from;
  _log[_logHead].toState = to;
  _log[_logHead].success = success;
  _log[_logHead].failureReason = reason;
  _logHead = (_logHead + 1) % SC_LOG_SIZE;
  if (_logCount < SC_LOG_SIZE) _logCount++;
}

void StateMachineCoordinator::printLog() const {
  Serial.println("═══════════ F10: State Coordinator Transition Log ═══════════");
  int start = (_logHead - _logCount + SC_LOG_SIZE) % SC_LOG_SIZE;
  for (int i = 0; i < _logCount; i++) {
    int idx = (start + i) % SC_LOG_SIZE;
    const TransitionLogEntry& e = _log[idx];
    Serial.printf("  [%lu] %s → %s: %s",
                 e.timestamp,
                 e.fromState ? e.fromState : "?",
                 e.toState ? e.toState : "?",
                 e.success ? "OK" : "FAIL");
    if (!e.success && e.failureReason) {
      Serial.printf(" (%s)", e.failureReason);
    }
    Serial.println();
  }
  Serial.println("═════════════════════════════════════════════════════════════");
}
