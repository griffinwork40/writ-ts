/**
 * Types shared between the executor and the scenario driver.
 */

// A scripted application outcome from the scenario
export interface AppOutcome {
  st: "ok" | "failed" | "canceled" | ""; // "" means held/no-op
  code?: string;        // err.code when st != ok
  res?: unknown;        // result body
  used?: Record<string, number>;
  rev?: number;         // rev.until time
  hold?: boolean;       // operation does not return yet
}

// What the call store holds per (leaf-writ-id, call-id)
export interface CallRecord {
  state: "pending" | "final";
  acc: number;
  // final tally bytes (canonical) when state=final
  tallyObj?: Record<string, unknown>;
  resObj?: unknown;
  // pending: writs issued and sub-tallies received (for crash-then-resolve)
  pendingWrts?: Record<string, unknown>[];
  pendingSubs?: Record<string, unknown>[];
  // which call-id key we used (the actual call object)
  callObj?: Record<string, unknown>;
  leafWritId?: string;
  callId?: string;
}

// What the reversal store holds per target-tally-id
export interface ReversalRecord {
  state: "begun" | "succeeded";
  underCallId?: string; // the undo call's id
  resultBody?: unknown;
}
