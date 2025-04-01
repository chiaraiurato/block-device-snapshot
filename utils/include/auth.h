#ifndef AUTH_H
#define AUTH_H

#include <linux/types.h>

#define HASH_LEN 32

int compute_hash_password(const char *password, size_t len, unsigned char *output);
int authenticate(const unsigned char *input_password, const unsigned char *expected_hash);

#endif