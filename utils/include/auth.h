#ifndef AUTH_H
#define AUTH_H

#include <linux/types.h>

#define HASH_LEN 32 
#define SALT_LEN 16

struct salted_hash {
    unsigned char salt[SALT_LEN];
    unsigned char hash[HASH_LEN];
};

int compute_salted_hash(const char *password, size_t len,  struct salted_hash *output);
int authenticate(const unsigned char *input_password, const struct salted_hash *expected_hash);

#endif