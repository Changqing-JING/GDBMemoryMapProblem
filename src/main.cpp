#include <cassert>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef uint32_t (*JITFunction)();

#define PAGE_SIZE 4096

#if (defined __x86_64__) || (defined _M_X64)
uint8_t machineCode[] = {
    0xb8, 0x05, 0, 0, 0, // mov eax, 5
    0xc3,                // ret
};
#elif (defined __arm64__) || (defined __aarch64__) || (defined _M_ARM64)
uint32_t machineCode[] = {
    0x528000a0, // mov w0, 5
    0xd65f03c0, // ret
};
#endif

JITFunction createRWXMachineCode() {

  void *mem = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  memcpy(mem, &machineCode[0], sizeof(machineCode));
  return (JITFunction)mem;
}

JITFunction createRXMachineCode() {

  void *mem = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  memcpy(mem, &machineCode[0], sizeof(machineCode));

  mprotect(mem, PAGE_SIZE, PROT_READ | PROT_EXEC);
  return (JITFunction)mem;
}

JITFunction createMemFdFunction() {
  const int32_t jitCodeMapFile = static_cast<int32_t>(syscall(__NR_memfd_create, "temp_memory_file", 0));

  assert(jitCodeMapFile >= 0);

  int32_t error = ftruncate(jitCodeMapFile, PAGE_SIZE);

  assert(error == 0);

  void *rwMem = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, jitCodeMapFile, 0);

  memcpy(rwMem, &machineCode[0], sizeof(machineCode));

  error = msync(rwMem, PAGE_SIZE, MS_SYNC);
  assert(error == 0);

  void *rxMem = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE, jitCodeMapFile, 0);

  error = munmap(rwMem, PAGE_SIZE);
  assert(error == 0);
  return (JITFunction)rxMem;
}

void testRWX() {
  JITFunction rwxFunction = createRWXMachineCode();

  printf("rwxFunction address is %p\n", rwxFunction);

  uint32_t rwxRes = rwxFunction();

  printf("rwxRes is %d\n", rwxRes);
}

void testRX() {
  JITFunction rxFunction = createRXMachineCode();

  printf("rxFunction address is %p\n", rxFunction);

  uint32_t rxRes = rxFunction();

  printf("rxRes is %d\n", rxRes);
}

void testMemFD() {
  JITFunction memFdFunction = createMemFdFunction();

  printf("memFdFunction address is %p\n", memFdFunction);

#if (defined __x86_64__) || (defined _M_X64)
  asm("int3");
#elif (defined __arm64__) || (defined __aarch64__) || (defined _M_ARM64)
  // asm("brk 1000");
#endif

  uint32_t memFdRes = memFdFunction();

  printf("memFdRes is %d\n", memFdRes);
}

int main() {
  testMemFD();
  return 0;
}