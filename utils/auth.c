#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/slab.h> 
#include <linux/err.h>
#include <linux/scatterlist.h>
#include "include/auth.h"


#define HASH_LEN 32  

int compute_hash_password(const char *password, size_t len, unsigned char *output)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret)
        goto out;

    ret = crypto_shash_update(desc, password, len);
    if (ret)
        goto out;

    ret = crypto_shash_final(desc, output);

out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

int authenticate(const unsigned char *input_password, const unsigned char *expected_hash)
{
    if (!input_password || !expected_hash)
        return -EINVAL;

    unsigned char *input_hash = kmalloc(HASH_LEN, GFP_KERNEL);
    if(!input_hash) {
        printk("Couldn't allocate memory to store input hash\n");
        return -ENOMEM;
    }
    int ret = compute_hash_password(input_password, strlen(input_password), input_hash);
    if (ret < 0) {
        printk("Hash computation failed\n");
        kfree(input_hash);
        return ret;
    }

    int comparison_result = memcmp(input_hash, expected_hash, HASH_LEN);
    kfree(input_hash);  
    
    return comparison_result ? -EACCES : 0;
}
