#include "ckvs.h"
#include "ckvs_crypto.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"

/**
 * Computes an HMAC using key and a string message (d) and stores it in md
 * @param key  : the sha to use to compute the HMAC
 * @param d    : the message to compute the HMAC
 * @param md   : the location to store the computed HMAC in
 * @return int : ERR_NONE if the HMAC was computed correctly, ERR_INVALID_COMMAND if the computation
 *          failed or the result doesn't have the expected size
 */
int ckvs_compute_HMAC(const void *key, const unsigned char *d, size_t len_d, unsigned char *md){
    M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(d); M_REQUIRE_NON_NULL(md);

    unsigned int outputSize = 0;
    unsigned char* ptr = HMAC(EVP_sha256(),key, SHA256_DIGEST_LENGTH,d,
               len_d,md,&outputSize);
    //verifies if HMAC worked correctly
    if(ptr == NULL){
        M_EXIT(ERR_INVALID_COMMAND,"ERROR when computing HMAC of %s, ckvs_crypto",d);
    }
    if(outputSize != SHA256_DIGEST_LENGTH){
        M_EXIT(ERR_INVALID_COMMAND,
               "HMAC of %s doesn't have correct value : "
               "(obtained) %d != %d (wanted) (ckvs_crypto)",d, outputSize, SHA_DIGEST_LENGTH);
    }
    return ERR_NONE;
}

/**
* @brief Generates stretched_key, auth_key and c1 and stores them into the memrecord.
*
* @param mr (struct ckvs_memrecord*) the record which will hold the keys
* @param key (const char*) the key used to compute stretched_key
* @param pwd (const char*) the password used to compute stretched_key
* @return int, error code
*/
int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd) {
    M_REQUIRE_NON_NULL(mr); M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(pwd);

    //initializes the memrecord's sha-s
    memset(mr,'\0',sizeof(ckvs_memrecord_t));

    //computes the stretched key to be used
    char* stretched = calloc(2*CKVS_MAXKEYLEN+2, sizeof(char));
    if(stretched == NULL){
        M_EXIT(ERR_OUT_OF_MEMORY, "%s","Erreur lors de l'allocation du pointeur (ckvs_client_encrypt_pwd)");
    }
    strncat(stretched, key, strlen(key));
    strncat(stretched,"|",1);
    strncat(stretched, pwd, strlen(pwd));
    
    //computes sha of the concat string and stores it in stretched_key struct
    unsigned char* ptr = SHA256((unsigned char*)stretched,strlen(stretched),(mr->stretched_key.sha));
    free(stretched); stretched = NULL;
    if(ptr == NULL){
        M_EXIT(ERR_INVALID_COMMAND,"%s", "ERROR when computing SHA256, ckvs_encrypt_pwd");
    }

    int ret_value = ERR_NONE;
    //computes the auth_key using HMAC
    ret_value = ckvs_compute_HMAC(mr->stretched_key.sha,(const unsigned char*)AUTH_MESSAGE,
                                  strlen(AUTH_MESSAGE),mr->auth_key.sha);
    if(ret_value) { return ret_value;}

    //computes c1 using HMAC
    ret_value = ckvs_compute_HMAC(mr->stretched_key.sha,(const unsigned char*)C1_MESSAGE,
                                  strlen(C1_MESSAGE),mr->c1.sha);
    return ret_value;
}

/**
 * @brief Generates master key from c1 stored in mr and the given c2.
 *
 * @param mr (struct ckvs_memrecord*) the record which will hold master_key. It must contains c1.
 * @param c2 (const struct ckvs_sha*) the value of c2, taken from ckvs_entry
 * @return int, error code
 */
int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2){
    M_REQUIRE_NON_NULL(mr); M_REQUIRE_NON_NULL(c2);
    //computes the masterkey using HMAC and stores it in mr.master_key.sha
    return ckvs_compute_HMAC(mr->c1.sha,c2->sha,SHA256_DIGEST_LENGTH,mr->master_key.sha);
}


/**
 * @brief Performs symmetric encryption/decryption using AES256_CBC.
 *
 * @param mr (struct ckvs_memrecord*), must contain the master_key
 * @param do_encrypt (int) 1 for encryption, 0 for decryption
 * @param inbuf (const unsigned char*) byte array to encrypt/decrypt
 * @param inbuflen (size_t) length of inbuf
 * @param outbuf (unsigned char*) byte array of length at least inbuflen+EVP_MAX_BLOCK_LENGTH
 * @param outbuflen (size_t*) actual number of bytes that was written in the output
 * @return int, error code
 */
int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen )
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen)) {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}
