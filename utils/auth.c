#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/slab.h> 
#include <linux/err.h>
#include <linux/scatterlist.h>
#include "include/auth.h"


int compute_salted_hash(const char *password, size_t len, struct salted_hash *output)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;
    unsigned char *salted_password = NULL;

    /* Allocate buffer for salted password */
    salted_password = kmalloc(len + SALT_LEN, GFP_KERNEL);
    if (!salted_password)
        return -ENOMEM;

    /* Generate random salt (only if output salt is empty) */
    if (output->salt[0] == 0) {
        get_random_bytes(output->salt, SALT_LEN);
    }

    /* Combine salt and password */
    memcpy(salted_password, output->salt, SALT_LEN);
    memcpy(salted_password + SALT_LEN, password, len);

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        goto out;
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto free_tfm;
    }

    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret)
        goto free_desc;

    ret = crypto_shash_update(desc, salted_password, len + SALT_LEN);
    if (ret)
        goto free_desc;

    ret = crypto_shash_final(desc, output->hash);

free_desc:
    kfree(desc);
free_tfm:
    crypto_free_shash(tfm);
out:
    kfree(salted_password);
    return ret;
}

int authenticate(const unsigned char *input_password, const struct salted_hash *expected_hash)
{
    if (!input_password || !expected_hash)
        return -EINVAL;

    struct salted_hash input_hash;
    // Copy the salt from expected_hash to our input_hash
    memcpy(input_hash.salt, expected_hash->salt, SALT_LEN);

    int ret = compute_salted_hash(input_password, strlen(input_password), &input_hash);
    if (ret < 0) {
        printk("Hash computation failed\n");
        return ret;
    }
    
    return memcmp(input_hash.hash, expected_hash->hash, HASH_LEN) ? -EACCES : 0;
}
