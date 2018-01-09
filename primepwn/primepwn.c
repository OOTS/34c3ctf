#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>

#define MAP_ADDR ((void*) 0x1337000)
#define MAP_LEN (0x1000)

char is_prime(unsigned char c) {
  if (c < 2) return 0;
  for (int i = 2; i < 256 && i < c; i++) {
    if (c % i == 0) return 0;
  };
  return 1;
};

extern void jump_to(void *);

void test_prime() {
  unsigned char * r = mmap(MAP_ADDR, MAP_LEN, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (r != MAP_ADDR) {
    perror("error on mmap");
    exit(1);
  };
  size_t len = fread(r, 1, MAP_LEN, stdin);
  for (int i = 0; i < len; i++) {
    if (!is_prime(r[i])) {
      printf("Byte %d (value: %u) is not prime.\n", i, r[i]);
      exit(0);
    };
  };
  puts("All bytes are prime!");
  jump_to(r);
};

int main() {
  test_prime();
  return 0;
};
  
