#include <stdio.h>
#include "ckvs.h"
#include "ckvs_utils.h"
#include "util.h"
#include <stdint.h>
#include <inttypes.h>

/**
 * @brief Prints the given header to the standard output,
 *
 * @param header (const struct ckvs_header*) the header to print
 */
void print_header(const struct ckvs_header* header){
    if(header == NULL){
        return;
    }
    pps_printf("CKVS Header type       : " STR_LENGTH_FMT(CKVS_HEADERSTRINGLEN) "\n", header -> header_string);
    pps_printf("CKVS Header version    : %" PRIu32 "\n", header -> version);
    pps_printf("CKVS Header table_size : %" PRIu32 "\n", header -> table_size);
    pps_printf("CKVS Header threshold  : %" PRIu32 "\n", header -> threshold_entries);
    pps_printf("CKVS Header num_entries: %" PRIu32 "\n", header -> num_entries);
}

/**
 * @brief Prints the given entry to the standard output,
 *
 * @param entry (const struct ckvs_entry*) the entry to print
 */
void print_entry(const struct ckvs_entry* entry){
    if(entry == NULL){
        return;
    }
    pps_printf("    Key   : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n", entry -> key);
    pps_printf("    Value : off %" PRIu64 " len %" PRIu64 "\n", entry -> value_off, entry -> value_len);
    print_SHA( "    Auth  ", &(entry -> auth_key));
    print_SHA( "    C2    ", &(entry -> c2));
}

/**
 * @brief Prints the given prefix and SHA (hex-encoded) to the standard output.
 *
 * @param prefix (const char*) the prefix to prepend to the SHA
 * @param sha (const struct ckvs_sha*) the SHA to print
 */
void print_SHA(const char *prefix, const struct ckvs_sha *sha){
    if(prefix == NULL || sha == NULL){
        return;
    }
    char buffer[SHA256_PRINTED_STRLEN] = {'\0'};
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

/**
 * @brief Encodes a ckvs_sha into its printable hex-encoded representation.
 *
 * @param sha (const struct ckvs_sha*) pointer to the input hash
 * @param buf (char*) pointer to the char buffer,
 *            assumed to be large enough to store the full representation (+ a null byte)
 *
 * @see SHA256_from_string for the inverse operation
 */
void SHA256_to_string(const struct ckvs_sha *sha, char *buf){
    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}

/**
 * @brief Encodes a byte array into a printable hex-encoded string.
 *
 * @param in (const uint8_t*) pointer to the input byte buffer
 * @param len (size_t) length of the input byte buffer
 * @param buf (char*) pointer to the output char buffer,
 *            assumed to be large enough to store the full representation (+ a null byte)
 *
 * @see hex_decode for the inverse operation
 */
void hex_encode(const uint8_t *in, size_t len, char *buf){
    if (in == NULL || buf == NULL) { // Safety protection
        return;
    }
    for(size_t i = 0; i < len; i++){
        sprintf(&buf[2*i], "%02x", in[i]);
    }

}

/**
 * @brief Compares two SHA.
 *
 * @param a (const struct ckvs_sha*) the first SHA to compare
 * @param b (const struct ckvs_sha*) the second SHA to compare
 * @return int, a negative value if a < b ;
 *         0 if a == b ;
 *         and a positive value if a > b.
 */
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b){
    return memcmp(a->sha,b->sha, SHA256_DIGEST_LENGTH);
}
