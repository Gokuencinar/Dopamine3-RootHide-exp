#ifndef RH3_PID1_DEFERRED_STATE_H
#define RH3_PID1_DEFERRED_STATE_H

#include <stdbool.h>
#include <stdatomic.h>

// The watchdog and daemon worker race only to decide who owns recovery.
// Exactly one may transition pending -> finished/expired. No unbounded
// request queue is allowed to accumulate in PID1 if jailbreakd hangs.
static bool rh3_pid1_deferred_finish(_Atomic int *state, int outcome)
{
    int pending = 0;
    return outcome > 0 && atomic_compare_exchange_strong(state, &pending, outcome);
}

static bool rh3_pid1_deferred_reserve(_Atomic int *outstanding, int limit)
{
    int count = atomic_load_explicit(outstanding, memory_order_relaxed);
    do {
        if (count < 0 || count >= limit) return false;
    } while (!atomic_compare_exchange_weak(outstanding, &count, count + 1));
    return true;
}

#endif
