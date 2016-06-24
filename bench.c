#include <string.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include "sha256.h"

unsigned char result[32];

int test1(char* data) {
  return strncmp("asd", data, 3);
}

void test2(unsigned char* data) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, strlen((char*)data)+1);
  sha256_final(&ctx, result);
}

int main()
{
	return 0;
}
