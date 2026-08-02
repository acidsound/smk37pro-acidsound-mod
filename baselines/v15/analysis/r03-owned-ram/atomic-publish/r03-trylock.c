typedef unsigned char u8;

__attribute__((naked, noinline, used))
int r03_try_lock(volatile u8 *lock)
{
    __asm__ volatile(
        "csync\n\t"
        "testset b[r0]\n\t"
        "ifeq goto 1f\n\t"
        "csync\n\t"
        "r0 = 1\n\t"
        "rts\n\t"
        "1:\n\t"
        "r0 = 0\n\t"
        "rts\n\t"
        ::: "memory");
}
