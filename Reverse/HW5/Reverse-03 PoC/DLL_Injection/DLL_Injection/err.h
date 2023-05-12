#pragma once

#define ERR(msg)                     \
  do {                               \
    printf("[-] %s failed!\n", msg); \
    exit(1);                         \
  } while (0)

