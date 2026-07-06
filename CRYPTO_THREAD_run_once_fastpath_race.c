/*
 * ---------------------------------------------------------------------------
 * Faithful reproduction of the *reader-side* memory-ordering hole that remains
 * in OpenSSL's Windows CRYPTO_THREAD_run_once() AFTER PR #31713 (which only
 * adds a write-side MemoryBarrier()).
 *
 *
 * This file mirrors OpenSSL's CRYPTO_THREAD_run_once() implementation and its usage
 *
 * The outcome:
 *   The producer puts a full MemoryBarrier() BETWEEN filling the struct and
 *   storing ONCE_DONE, so a reader that observes ONCE_DONE must also
 *   observe glob_register != NULL. Observing (once==DONE && glob==NULL) is
 *   therefore only possible via reader-side LoadLoad reordering:
 *     - the missing acquire on the run_once fast path
 *
 * Execution model:
 *   A writer thread and N reader threads loop for millions of iterations.
 *   Each iteration: writer resets the globals, both sides synchronize via a
 *   lightweight barrier, then the writer publishes (via run_once) while readers
 *   poll the flag and race to read the guarded pointer. The tight polling loop
 *   lets the CPU speculatively execute the pointer load ahead of the flag load
 *   that ends the spin -- surfacing the LoadLoad reorder.
 *
 * Runtime knobs:
 *   --fix             enable the reader-side acquire inside the run_once fast
 *                     path (expect NO violations).
 *
 * Requirements:
 *  1. The flag and the published pointer to live on separate cache lines
 *  (done here via __declspec(align)) AND
 *  2. a NATIVE weakly-ordered machine like windows arm64 (Apple Silicon, Qualcomm Snapdragon, etc)
 * ---------------------------------------------------------------------------
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ===================================================================== */
/* Mirror of crypto/threads_win.c + include/crypto/cryptlib.h            */
/* ===================================================================== */

#define ONCE_UNINITED 0
#define ONCE_ININIT   1
#define ONCE_DONE     2

typedef LONG CRYPTO_ONCE;                 /* the pre-INIT_ONCE Windows CRYPTO_ONCE */
#define CRYPTO_ONCE_STATIC_INIT 0

static int g_reader_acquire = 0;          /* toggled by --fix */

/*
 * Verbatim CRYPTO_THREAD_run_once() from crypto/threads_win.c, with the
 * PR #31713 write-side MemoryBarrier(), and an OPTIONAL reader-side acquire
 * (guarded by g_reader_acquire) that represents the real fix.
 *
 * Kept noinline exactly like the shipped library function reached via RUN_ONCE.
 */
static __declspec(noinline)
int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    LONG volatile *lock = (LONG *)once;
    LONG result;

    if (*lock == ONCE_DONE) {             /* <-- the fast path (the unsafe one) */
        if (g_reader_acquire)
            MemoryBarrier();              /* the acquire the fast path is MISSING */
        return 1;
    }

    do {
        result = InterlockedCompareExchange(lock, ONCE_ININIT, ONCE_UNINITED);
        if (result == ONCE_UNINITED) {
            init();
            MemoryBarrier();              /* PR #31713 write-side barrier (release) */
            *lock = ONCE_DONE;
            return 1;
        }
    } while (result == ONCE_ININIT);

    /*
     * Spin path: the loop only exits here after an InterlockedCompareExchange
     * (a full barrier) observed ONCE_DONE, so this read is already ordered.
     * The fast path above is the ONLY unsynchronized reader.
     */
    return (*lock == ONCE_DONE);
}

/* ===================================================================== */
/* Mirror of crypto/initthread.c (the code that actually crashed)        */
/* ===================================================================== */

#define GLOBAL_REGISTER void

/*
 * CRITICAL: put the flag and the published pointer on SEPARATE cache lines.
 * If they share a line (being adjacent globals), coherence delivers both updates
 * to a reader atomically and the reorder is physically unobservable. Cache-line
 * isolation is what lets the flag update and the pointer update arrive independently.
 */
#ifndef CACHELINE
# define CACHELINE 128
#endif

/* Backing storage (pre-allocated so we don't malloc per round in the test). */

/* mirrors: static GLOBAL_TEVENT_REGISTER *glob_tevent_reg = NULL;  (NON-volatile) */
__declspec(align(CACHELINE)) static GLOBAL_REGISTER *glob_register = NULL;

/* mirrors: static CRYPTO_ONCE tevent_register_runonce = CRYPTO_ONCE_STATIC_INIT; */
__declspec(align(CACHELINE)) static CRYPTO_ONCE register_once = CRYPTO_ONCE_STATIC_INIT;

/* mirrors DEFINE_RUN_ONCE_STATIC(create_global_tevent_register): fill then publish */
static void create_global_register(void)
{
    glob_register = (void *)(intptr_t)0xA5A5A5A5;        /* publish the pointer LAST */
}

/* ===================================================================== */
/* N-party barrier: all threads must arrive before any can proceed.       */
/*                                                                       */
/* Uses "sense-reversing" so it can be reused across iterations without   */
/* a reset step.  Each thread keeps a local sense bit that alternates     */
/* 0/1 each time it enters the barrier:                                  */
/*                                                                       */
/*   arrivals  - atomic counter; incremented by each arriving thread.    */
/*   go_signal - flipped by the LAST thread to arrive, releasing others. */
/*   local     - per-thread sense bit (caller-owned).                    */
/*                                                                       */
/* The last thread to arrive (arrivals == party_size) resets the counter  */
/* and flips go_signal, waking everyone. Others spin until go_signal      */
/* matches their expected sense.                                         */
/* ===================================================================== */

static volatile LONG arrivals;
static volatile LONG go_signal;
static LONG          party_size; /* 1 writer + N readers */

static void sync_barrier(int *local_sense)
{
    int expected = !*local_sense;
    *local_sense = expected;

    if (InterlockedIncrement(&arrivals) == party_size) {
        /* Last to arrive: reset counter and release everyone */
        arrivals = 0;
        MemoryBarrier();
        go_signal = expected;
    } else {
        /* Wait for the last thread to flip go_signal */
        while (go_signal != expected) {
            YieldProcessor();
        }
        MemoryBarrier();
    }
}

/* ===================================================================== */
/* Counters                                                              */
/* ===================================================================== */

#define ITERATIONS 50000000

static volatile LONG g_violations;

/* ===================================================================== */
/* Writer: resets globals between rounds, then calls run_once             */
/* ===================================================================== */

static DWORD WINAPI writer_thread(LPVOID p)
{
    int local_sense = 0;
    for (LONG i = 0; i < ITERATIONS; i++) {
        /* Wait for all readers to finish reading from the previous round,
         * so it's safe to NULL out the globals without causing false positives. */
        sync_barrier(&local_sense);

        glob_register     = NULL;
        register_once     = ONCE_UNINITED;
        MemoryBarrier();                  /* ensure reset visible */

        /* Wait for everyone to see the reset before racing. */
        sync_barrier(&local_sense);

        /* same call as readers */
        (void)CRYPTO_THREAD_run_once(&register_once, create_global_register);
    }
    return 0;
}

/* ===================================================================== */
/* Reader: same run_once call, then dereferences the guarded pointer      */
/* ===================================================================== */

static DWORD WINAPI reader_thread(LPVOID p)
{
    int local_sense = 0;
    for (LONG i = 0; i < ITERATIONS; i++) {
        sync_barrier(&local_sense);            /* wait: writer needs us done reading */
        sync_barrier(&local_sense);            /* wait: writer done resetting, race! */

        /* similar to get_global_tevent_register() in OpenSSL */
        if (CRYPTO_THREAD_run_once(&register_once, create_global_register) != 1) {
            printf("ERROR: The impossible happened: CRYPTO_THREAD_run_once failed\n");
            continue;
        }

        GLOBAL_REGISTER *gtr = glob_register;
        if (!gtr) {
            InterlockedIncrement(&g_violations);
        }
    }
    return 0;
}


int main(int argc, char **argv)
{
    HANDLE hw;
    HANDLE *hr;

    for (int arg = 1; arg < argc; arg++) {
        if (strcmp(argv[arg], "--fix") == 0) {
            g_reader_acquire = 1;
        }
    }

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    DWORD ncpu = si.dwNumberOfProcessors;
    if (ncpu <= 1) {
        printf("ERROR: must run on a multi-core CPU (ncpu=%lu)\n", ncpu);
        return 2;
    }

    /* one reader per core, leaving one for the writer */
    int nreaders = (int)ncpu - 1;
    party_size = ncpu;

    printf("CRYPTO_THREAD_run_once reader asymmetry\n");
    printf("Reader acquire barrier: %s\n", g_reader_acquire ? "ON  (fix)" : "OFF (OpenSSL state)");
    printf("CPUs: %lu | Readers: %d | Iterations: %d\n\n", ncpu, nreaders, ITERATIONS);

    hr = (HANDLE *)calloc((size_t)nreaders, sizeof(HANDLE));
    if (!hr) {
        return 2;
    }

    hw = CreateThread(NULL, 0, writer_thread, NULL, CREATE_SUSPENDED, NULL);
    if (!hw) {
        return 2;
    }
    /* use 1st CPU for the writer thread */
    SetThreadAffinityMask(hw, (DWORD_PTR)1u << 0);
    SetThreadPriority(hw, THREAD_PRIORITY_HIGHEST);

    for (int r = 0; r < nreaders; r++) {
        hr[r] = CreateThread(NULL, 0, reader_thread, NULL, CREATE_SUSPENDED, NULL);
        if (!hr[r]) {
            return 2;
        }

        /* spread readers acores the rest CPUs */
        SetThreadAffinityMask(hr[r], (DWORD_PTR)1u << (1 + (r % nreaders)));
        SetThreadPriority(hr[r], THREAD_PRIORITY_HIGHEST);
    }

    /* resume threads */
    ResumeThread(hw);
    for (int r = 0; r < nreaders; r++) {
        ResumeThread(hr[r]);
    }

    WaitForSingleObject(hw, INFINITE);
    for (int r = 0; r < nreaders; r++) {
        WaitForSingleObject(hr[r], INFINITE);
        CloseHandle(hr[r]);
    }
    CloseHandle(hw);
    free(hr);

    printf("VIOLATIONS: %ld\n", g_violations);
    if (g_violations > 0)
    {
        printf("=> REORDERING OBSERVED (NULL glob_register while once==DONE)\n");
    }
    else
    {
        printf("=> No violation\n");
    }

    return g_violations > 0 ? 1 : 0;
}
