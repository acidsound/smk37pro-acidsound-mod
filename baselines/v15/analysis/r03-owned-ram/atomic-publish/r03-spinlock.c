typedef unsigned char u8;

__attribute__((noinline, used))
void r03_lock(volatile u8 *lock)
{
    __asm__ volatile(
        "csync\n\t"
        "1:\n\t"
        "testset b[%0]\n\t"
        "ifeq goto 1b\n\t"
        "csync\n\t"
        :
        : "r"(lock)
        : "memory");
}

__attribute__((noinline, used))
void r03_unlock(volatile u8 *lock)
{
    __asm__ volatile("csync" ::: "memory");
    *lock = 0;
    __asm__ volatile("csync" ::: "memory");
}
