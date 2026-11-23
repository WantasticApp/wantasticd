// Provide 64-bit atomic operations for 32-bit MIPS using a spinlock.
// tinygo's compiler-rt for MIPS doesn't include these.
#include <stdint.h>

static volatile int _atomic_lock = 0;

static inline void _lock(void) {
    while (__sync_lock_test_and_set(&_atomic_lock, 1)) {}
}

static inline void _unlock(void) {
    __sync_lock_release(&_atomic_lock);
}

uint64_t __atomic_fetch_add_8(volatile uint64_t *ptr, uint64_t val, int memorder) {
    _lock();
    uint64_t old = *ptr;
    *ptr = old + val;
    _unlock();
    return old;
}

void __atomic_store_8(volatile uint64_t *ptr, uint64_t val, int memorder) {
    _lock();
    *ptr = val;
    _unlock();
}

uint64_t __atomic_load_8(volatile uint64_t *ptr, int memorder) {
    _lock();
    uint64_t val = *ptr;
    _unlock();
    return val;
}

int __atomic_compare_exchange_8(volatile uint64_t *ptr, uint64_t *expected,
                                uint64_t desired, int success_memorder,
                                int failure_memorder) {
    _lock();
    uint64_t current = *ptr;
    if (current == *expected) {
        *ptr = desired;
        _unlock();
        return 1;
    }
    *expected = current;
    _unlock();
    return 0;
}

uint64_t __atomic_exchange_8(volatile uint64_t *ptr, uint64_t val, int memorder) {
    _lock();
    uint64_t old = *ptr;
    *ptr = val;
    _unlock();
    return old;
}
