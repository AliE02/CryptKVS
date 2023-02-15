/**
 * @file unit-test-util.c
 * @brief Unit tests for the ckvs_util.h functions
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
#include <stdarg.h>
#include <stdio.h>

#include "tests.h"
#include "error.h"
#include "ckvs_utils.h"

#include "ckvs_test_util.h"

static char output_buffer[1024] = { '\0' };

// ------------------------------------------------------------
int pps_printf(const char* __restrict__ format, ...) {
    va_list argp;
    va_start(argp, format);

    int written = vsnprintf(output_buffer, sizeof(output_buffer) - 1, format, argp);
    output_buffer[written >= 0 ? written : 0] = '\0';

    va_end(argp);
    return written;
}

// ======================================================================
START_TEST(SHA256_to_string_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;
    char buf[SHA256_PRINTED_STRLEN];

    // should not segfault
    SHA256_to_string(&sha, NULL);
    SHA256_to_string(NULL, buf);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(SHA256_to_string_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;
    for (size_t i = 0 ; i < SHA256_DIGEST_LENGTH ; ++i)
        sha.sha[i] = 0x80 + i * 3;
    const char* expected = "808386898c8f9295989b9ea1a4a7aaadb0b3b6b9bcbfc2c5c8cbced1d4d7dadd";

    char buf[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&sha, buf);

    ck_assert_str_eq(buf, expected);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(print_SHA_null)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;

    // should not segfault
    print_SHA("Prefix", NULL);
    print_SHA(NULL, &sha);
    print_SHA(NULL, NULL);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(print_SHA_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;
    for (size_t i = 0 ; i < SHA256_DIGEST_LENGTH ; ++i)
        sha.sha[i] = i;
    
    const char* expected = "Long prefix: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";
    print_SHA("Long prefix", &sha);

    ck_assert_str_eq(expected, output_buffer);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(print_SHA_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha = { { 0 } };    
    const char* const expected = "sha  : 0000000000000000000000000000000000000000000000000000000000000000\n";
    print_SHA("sha", &sha);

    ck_assert_str_eq(expected, output_buffer);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
START_TEST(cmp_sha_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t s1 = { { 0x1 } };
    ckvs_sha_t s2 = { { 0x1 } };

    ck_assert_int_eq(ckvs_cmp_sha(&s1, &s1), 0);
    ck_assert_int_eq(ckvs_cmp_sha(&s1, &s2), 0);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(cmp_sha_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t s1  = { { 0x1 } };
    ckvs_sha_t s2;
    for (size_t i = 0 ; i < SHA256_DIGEST_LENGTH ; ++i)
        s2.sha[i] = i;

    // s1 > s2
    ck_assert_int_gt(ckvs_cmp_sha(&s1, &s2), 0);
    ck_assert_int_lt(ckvs_cmp_sha(&s2, &s1), 0);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_encode_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const uint8_t in[] = { 1, 2, 3 };
    char out[7] = { 0 };

    hex_encode(NULL, 0, NULL);
    hex_encode(in, 3, NULL);
    hex_encode(NULL, 1, out);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_encode_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const uint8_t in[] = { 1, 2 };
    char out[5] = { 0 };

    hex_encode(in, 2, out);

    ck_assert_str_eq("0102", out);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_encode_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const uint8_t in[] = { 0xf2, 0x2, 0x93 };
    char out[7] = { 0 };

    hex_encode(in, 3, out);

    ck_assert_str_eq("f20293", out);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_encode_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const uint8_t in[] = { 0x1 };
    char out[3] = { 0 };

    hex_encode(in, 0, out);

    ck_assert_str_eq("", out);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_decode_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const char in[] = "0123";
    uint8_t out[2] = { 0 };

    ck_assert_int_eq(hex_decode(NULL, NULL), -1);
    ck_assert_int_eq(hex_decode(in, NULL), -1);
    ck_assert_int_eq(hex_decode(NULL, out), -1);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_decode_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const char in[] = "0123";
    uint8_t expected[] = { 0x1, 0x23 };
    uint8_t out[2] = { 0 };

    ck_assert_int_eq(hex_decode(in, out), 2);
    ck_assert_int_eq(memcmp(expected, out, 2), 0);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_decode_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const char in[] = "fe599acd";
    uint8_t expected[] = { 0xfe, 0x59, 0x9a, 0xcd };
    uint8_t out[4] = { 0 };

    ck_assert_int_eq(hex_decode(in, out), 4);
    ck_assert_int_eq(memcmp(expected, out, 4), 0);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(hex_decode_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    const char in[] = "abc";
    uint8_t expected[] = { 0x0a, 0xbc };
    uint8_t out[2] = { 0 };

    ck_assert_int_eq(hex_decode(in, out), 2);
    ck_assert_int_eq(memcmp(expected, out, 2), 0);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
Suite* util_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests for hexadecimal convertion operations (may not be exhaustive!)");

    Add_Case(s, tc1, "util tests");
    tcase_add_test(tc1, SHA256_to_string_NULL);
    tcase_add_test(tc1, SHA256_to_string_1);
    tcase_add_test(tc1, print_SHA_null);
    tcase_add_test(tc1, print_SHA_1);
    tcase_add_test(tc1, print_SHA_2);
    tcase_add_test(tc1, cmp_sha_1);
    tcase_add_test(tc1, cmp_sha_2);
    tcase_add_test(tc1, hex_encode_NULL);
    tcase_add_test(tc1, hex_encode_1);
    tcase_add_test(tc1, hex_encode_2);
    tcase_add_test(tc1, hex_encode_3);
    tcase_add_test(tc1, hex_decode_NULL);
    tcase_add_test(tc1, hex_decode_1);
    tcase_add_test(tc1, hex_decode_2);
    tcase_add_test(tc1, hex_decode_3);

    return s;
}

TEST_SUITE(util_test_suite)
