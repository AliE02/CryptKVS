/**
 * @file unit-test-crypto.c
 * @brief Unit tests for the ckvs_crypt functions
 *
 * @author A. Clergeot, EPFL
 * @date 2021
 */

#ifdef WITH_RANDOM
// for thread-safe randomization (useless here, but kept in case we'd like to have random generation inside the tests)
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#endif

#include <check.h>
#include <inttypes.h>

#include "tests.h"
#include "error.h"
#include "ckvs.h"
#include "ckvs_utils.h"
#include "ckvs_crypto.h"

#include "ckvs_test_util.h"

IMPLEMENT_MUTED_PPS_PRINTF

typedef struct ckvs_memrecord ckvs_mr_t;

// ======================================================================
START_TEST(ckvs_memrecord_struct_offsets)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // In the struct ckvs_memrecord, please respect the order : stretched_key, auth_key, c1, master_key
    ck_assert_int_eq(offsetof(struct ckvs_memrecord, stretched_key), 0);
    ck_assert_int_eq(offsetof(struct ckvs_memrecord, auth_key), sizeof(ckvs_sha_t));
    ck_assert_int_eq(offsetof(struct ckvs_memrecord, c1), 2 * sizeof(ckvs_sha_t));
    ck_assert_int_eq(offsetof(struct ckvs_memrecord, master_key), 3 * sizeof(ckvs_sha_t));
    ck_assert_int_eq(sizeof(struct ckvs_memrecord), 4 * sizeof(ckvs_sha_t));

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(client_encrypt_pwd_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    ckvs_mr_t mr;
    const char* key = "hello";
    const char* pwd = "1234";

    ck_assert_int_eq(ckvs_client_encrypt_pwd(NULL, NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_client_encrypt_pwd(NULL, key, pwd), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_client_encrypt_pwd(&mr, NULL, pwd), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_client_encrypt_pwd(&mr, key, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(client_encrypt_pwd_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    ckvs_mr_t mr;
    const char* key = "hello";
    const char* pwd = "1234";

    ckvs_sha_t expected_streched_key = { { 
        0x82, 0x48, 0x43, 0x66, 0x15, 0xfc, 0xe7, 0x79, 0xbf, 0x0b, 0x60, 0x11, 0xb4, 0x80, 0x4a, 0x9e, 
        0x4f, 0x75, 0xa0, 0xcc, 0x77, 0xc1, 0xf1, 0xf9, 0x62, 0x14, 0x07, 0xa5, 0x5b, 0xc1, 0x84, 0x20 
    } };
    ckvs_sha_t expected_auth_key = { { 
        0xce, 0x16, 0x3f, 0x69, 0x85, 0x42, 0x45, 0x64, 0xbe, 0x99, 0x7d, 0x6f, 0x90, 0x09, 0x9a, 0x46,
        0xd7, 0xa2, 0xf3, 0x9c, 0x79, 0x78, 0x6b, 0x54, 0x5c, 0x15, 0x82, 0xe5, 0x49, 0xd1, 0x50, 0x7a 
    } };
    ckvs_sha_t expected_c1 = { { 
        0x73, 0xb0, 0x77, 0x91, 0xe2, 0x7c, 0x72, 0x1d, 0x2c, 0x03, 0x85, 0x2f, 0x16, 0x31, 0x62, 0xca,
        0x69, 0x8e, 0xfe, 0xd7, 0x98, 0x40, 0x11, 0xfa, 0xa4, 0x81, 0x18, 0xe1, 0x3f, 0x0d, 0x0d, 0x61 
    } };
    ck_assert_int_eq(ckvs_client_encrypt_pwd(&mr, key, pwd), ERR_NONE);

    ck_assert_int_eq(memcmp(&mr.stretched_key, &expected_streched_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(memcmp(&mr.auth_key, &expected_auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(memcmp(&mr.c1, &expected_c1, sizeof(ckvs_sha_t)), 0);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(client_compute_masterkey_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    ckvs_mr_t mr;
    ckvs_sha_t c2;

    ck_assert_int_eq(ckvs_client_compute_masterkey(NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_client_compute_masterkey(NULL, &c2), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_client_compute_masterkey(&mr, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(client_compute_masterkey_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    ckvs_mr_t mr = {
        .stretched_key = { { 
            0x82, 0x48, 0x43, 0x66, 0x15, 0xfc, 0xe7, 0x79, 0xbf, 0x0b, 0x60, 0x11, 0xb4, 0x80, 0x4a, 0x9e, 
            0x4f, 0x75, 0xa0, 0xcc, 0x77, 0xc1, 0xf1, 0xf9, 0x62, 0x14, 0x07, 0xa5, 0x5b, 0xc1, 0x84, 0x20 
        } },
        .auth_key = { { 
            0xce, 0x16, 0x3f, 0x69, 0x85, 0x42, 0x45, 0x64, 0xbe, 0x99, 0x7d, 0x6f, 0x90, 0x09, 0x9a, 0x46,
            0xd7, 0xa2, 0xf3, 0x9c, 0x79, 0x78, 0x6b, 0x54, 0x5c, 0x15, 0x82, 0xe5, 0x49, 0xd1, 0x50, 0x7a 
        } },
        .c1 = { { 
            0x73, 0xb0, 0x77, 0x91, 0xe2, 0x7c, 0x72, 0x1d, 0x2c, 0x03, 0x85, 0x2f, 0x16, 0x31, 0x62, 0xca,
            0x69, 0x8e, 0xfe, 0xd7, 0x98, 0x40, 0x11, 0xfa, 0xa4, 0x81, 0x18, 0xe1, 0x3f, 0x0d, 0x0d, 0x61 
        } },
    };
    ckvs_sha_t c2 = { { 0x2 } };

    ckvs_sha_t expected_master_key = { {
        0x21, 0xc6, 0x42, 0x7c, 0x76, 0x02, 0x02, 0x33, 0xa2, 0x6a, 0xfc, 0x43, 0x3d, 0xc7, 0x6b, 0x85, 
        0x77, 0xd4, 0xef, 0x19, 0x3e, 0xcc, 0x96, 0x46, 0xab, 0x67, 0xeb, 0xad, 0x13, 0x66, 0xfa, 0xf5
    } };

    ck_assert_int_eq(ckvs_client_compute_masterkey(&mr, &c2), ERR_NONE);
    ck_assert_int_eq(memcmp(&mr.master_key, &expected_master_key, sizeof(ckvs_sha_t)), 0);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
Suite* crypto_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests for crypto operations (may not be exhaustive!)");

    Add_Case(s, tc1, "Crypto tests");
    tcase_add_test(tc1, ckvs_memrecord_struct_offsets);
    tcase_add_test(tc1, client_encrypt_pwd_NULL);
    tcase_add_test(tc1, client_encrypt_pwd_1);
    tcase_add_test(tc1, client_compute_masterkey_NULL);
    tcase_add_test(tc1, client_compute_masterkey_1);

    return s;
}

TEST_SUITE(crypto_test_suite)