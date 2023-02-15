/**
 * @file unit-test-get.c
 * @brief Unit tests for the local 'get' command
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
#include <stdio.h>
#include <string.h>

#include "tests.h"
#include "error.h"
#include "ckvs.h"
#include "ckvs_local.h"

#include "ckvs_test_util.h"

IMPLEMENT_MUTED_PPS_PRINTF

// ======================================================================
START_TEST(get_NULL_arguments)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ck_assert_int_eq(ckvs_local_get(NULL, NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_get(NULL, "key", "pwd"), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_get(NON_EXISTING_CKVS, NULL, "pwd"), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_get(NON_EXISTING_CKVS, "key", NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(get_non_present_key_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 16);
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    char key[] = "does not exist";
    char pwd[] = "never use 1234";

    ck_assert_int_eq(ckvs_local_get(DUMMY_NAME, key, pwd), ERR_KEY_NOT_FOUND);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(get_non_present_key_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 16);
    strcpy(ckvs.entries[10].key, "zzm");
    ckvs.header.num_entries = 1;
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    char key[] = "zz";
    char pwd[] = "1234";

    ck_assert_int_eq(ckvs_local_get(DUMMY_NAME, key, pwd), ERR_KEY_NOT_FOUND);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(get_present_key_invalid_sha_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 16);
    char pwd[] = "0000";
    const uint8_t encrypted[] = { 127, 0, 0, 1 };
    ckvs_entry_t expected = { 
        .key = "hello", 
        .auth_key = { { 
            0x23, 0x20, 0x33, 0x80, 0x9c, 0xe6, 0x16, 0x68, 0x5a, 0x90, 0x82, 0x7e, 0x53, 0x66, 0x9f, 0x0d, 
            0xbd, 0x99, 0x24, 0xad, 0xeb, 0x58, 0x43, 0x4d, 0xb1, 0x6f, 0xe9, 0x80, 0x0f, 0x88, 0x0a, 0x11 ^ 0x1 // error bit in auth_key
        } }, 
        .value_off = sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size,
        .value_len = sizeof(encrypted),
    };
    memcpy(ckvs.entries + 44, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;
    
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);
    // ckvs_local_get() should return before attempting to read the encrypted secret,
    // so we don't even write it in the file
    // ck_assert_int_eq(fwrite(encrypted, expected.value_len, 1, file), 1);

    ck_assert_int_eq(ckvs_local_get(DUMMY_NAME, expected.key, pwd), ERR_DUPLICATE_ID);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(get_present_key_invalid_sha_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 16);
    char pwd[] = "0000";
    // value "secret!", encrypted with c2 (+ c1, master_key derived from stretched_key)
    const uint8_t encrypted[] = { 127, 43, 228, 107, 2, 150, 63, 178, 0, 157, 145, 42, 12, 89, 108, 134 };
    ckvs_entry_t expected = { 
        .key = "hello", 
        .auth_key = { { 
            0x23, 0x20, 0x33, 0x80, 0x9c, 0xe6, 0x16, 0x68, 0x5a, 0x90, 0x82, 0x7e, 0x53, 0x66, 0x9f, 0x0d, 
            0xbd, 0x99, 0x24, 0xad, 0xeb, 0x58, 0x43, 0x4d, 0xb1, 0x6f, 0xe9, 0x80, 0x0f, 0x88, 0x0a, 0x11 
        } }, 
        .c2 = { { 
            0xc0, 0xcd, 0x05, 0xaf, 0x7d, 0x3b, 0x32, 0x16, 0x21, 0x3b, 0x78, 0x2d, 0x7a, 0x1d, 0xc8, 0x7b, 
            0x12, 0x53, 0x03, 0xcc, 0xc6, 0x24, 0x1a, 0x0e, 0xcc, 0x97, 0xdb, 0x9f, 0x8c, 0x95, 0x48, 0x09 ^ 0x1 // error bit in c2
        } }, 
        .value_off = sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size,
        .value_len = sizeof(encrypted)
    };
    memcpy(ckvs.entries + 44, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;
    
    FILE* file = fopen(DUMMY_NAME, "wb");
    dump_db(file, &ckvs.header, ckvs.entries);
    ck_assert_int_eq(fwrite(encrypted, expected.value_len, 1, file), 1);
    fclose(file);

    ck_assert_int_eq(ckvs_local_get(DUMMY_NAME, expected.key, pwd), ERR_INVALID_ARGUMENT);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(get_present_key_invalid_value_offset_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 16);
    char pwd[] = "0000";
    // value "secret!", encrypted with c2 (+ c1, master_key derived from stretched_key)
    const uint8_t encrypted[] = { 127, 43, 228, 107, 2, 150, 63, 178, 0, 157, 145, 42, 12, 89, 108, 134 };
    ckvs_entry_t expected = { 
        .key = "hello", 
        .auth_key = { { 
            0x23, 0x20, 0x33, 0x80, 0x9c, 0xe6, 0x16, 0x68, 0x5a, 0x90, 0x82, 0x7e, 0x53, 0x66, 0x9f, 0x0d, 
            0xbd, 0x99, 0x24, 0xad, 0xeb, 0x58, 0x43, 0x4d, 0xb1, 0x6f, 0xe9, 0x80, 0x0f, 0x88, 0x0a, 0x11 
        } }, 
        .c2 = { { 
            0xc0, 0xcd, 0x05, 0xaf, 0x7d, 0x3b, 0x32, 0x16, 0x21, 0x3b, 0x78, 0x2d, 0x7a, 0x1d, 0xc8, 0x7b, 
            0x12, 0x53, 0x03, 0xcc, 0xc6, 0x24, 0x1a, 0x0e, 0xcc, 0x97, 0xdb, 0x9f, 0x8c, 0x95, 0x48, 0x09
        } }, 
        .value_off = sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size,
        .value_len = sizeof(encrypted)
    };
    memcpy(ckvs.entries + 44, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;
    
    // encrypted value not present at the given offset
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    ck_assert_int_eq(ckvs_local_get(DUMMY_NAME, expected.key, pwd), ERR_IO);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
START_TEST(get_present_key_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 16);
    char pwd[] = "0000";
    // value "secret!", encrypted with c2 (+ c1, master_key derived from stretched_key)
    const uint8_t encrypted[] = { 127, 43, 228, 107, 2, 150, 63, 178, 0, 157, 145, 42, 12, 89, 108, 134 };
    ckvs_entry_t expected = { 
        .key = "hello", 
        .auth_key = { { 
            0x23, 0x20, 0x33, 0x80, 0x9c, 0xe6, 0x16, 0x68, 0x5a, 0x90, 0x82, 0x7e, 0x53, 0x66, 0x9f, 0x0d, 
            0xbd, 0x99, 0x24, 0xad, 0xeb, 0x58, 0x43, 0x4d, 0xb1, 0x6f, 0xe9, 0x80, 0x0f, 0x88, 0x0a, 0x11 
        } }, 
        .c2 = { { 
            0xc0, 0xcd, 0x05, 0xaf, 0x7d, 0x3b, 0x32, 0x16, 0x21, 0x3b, 0x78, 0x2d, 0x7a, 0x1d, 0xc8, 0x7b, 
            0x12, 0x53, 0x03, 0xcc, 0xc6, 0x24, 0x1a, 0x0e, 0xcc, 0x97, 0xdb, 0x9f, 0x8c, 0x95, 0x48, 0x09 
        } }, 
        .value_off = sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size,
        .value_len = sizeof(encrypted)
    };
    memcpy(ckvs.entries + 44, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;
    
    FILE* file = fopen(DUMMY_NAME, "wb");
    dump_db(file, &ckvs.header, ckvs.entries);
    ck_assert_int_eq(fwrite(encrypted, expected.value_len, 1, file), 1);
    fclose(file);

    ck_assert_int_eq(ckvs_local_get(DUMMY_NAME, expected.key, pwd), ERR_NONE);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
Suite* get_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests of the 'get' command (may not be exhaustive!)");

    Add_Case(s, tc1, "Get tests");
    tcase_add_test(tc1, get_NULL_arguments);
    tcase_add_test(tc1, get_non_present_key_1);
    tcase_add_test(tc1, get_non_present_key_2);
    tcase_add_test(tc1, get_present_key_invalid_sha_1);
    tcase_add_test(tc1, get_present_key_invalid_sha_2);
    tcase_add_test(tc1, get_present_key_invalid_value_offset_1);
    tcase_add_test(tc1, get_present_key_1);

    return s;
}

TEST_SUITE(get_test_suite)
