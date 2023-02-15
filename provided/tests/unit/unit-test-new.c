/**
 * @file unit-test-new.c
 * @brief Unit tests for the local 'new' command
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
START_TEST(new_NULL_arguments)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char key[] = "key";
    char pwd[] = "pwd";

    ck_assert_int_eq(ckvs_local_new(NULL, NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_new(NULL, key, pwd), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_new(NON_EXISTING_CKVS, NULL, pwd), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_new(NON_EXISTING_CKVS, key, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_already_existing_key_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char key[] = "key";
    char pwd[] = "pwd";

    init_ckvs(ckvs, 64, 10);
    strcpy(ckvs.entries[44].key, key);
    ckvs.header.num_entries = 1;
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    ck_assert_int_eq(ckvs_local_new(DUMMY_NAME, key, pwd), ERR_DUPLICATE_ID);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_already_existing_key_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char k1[] = "sham"; // hash = 7
    char k2[] = "says";
    char pwd[] = "pwd";

    init_ckvs(ckvs, 64, 10);
    strcpy(ckvs.entries[7].key, k1);
    strcpy(ckvs.entries[8].key, k2);
    ckvs.header.num_entries = 2;
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    ck_assert_int_eq(ckvs_local_new(DUMMY_NAME, k2, pwd), ERR_DUPLICATE_ID);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_non_existing_key_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char key[] = "a-b-c-d-e"; // hash = 1
    char pwd[] = "00001111";

    init_ckvs(ckvs, 64, 10);
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    ck_assert_int_eq(ckvs_local_new(DUMMY_NAME, key, pwd), ERR_NONE);

    ckvs_entry_t e;
    FILE* f = fopen(DUMMY_NAME, "rb");
    ck_assert_ptr_nonnull(f);
    ck_assert_int_eq(fseek(f, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t), SEEK_SET), 0);
    ck_assert_int_eq(fread(&e, sizeof(ckvs_entry_t), 1, f), 1);
    fclose(f);

    ckvs_sha_t auth_key = { {
        0x21, 0x45, 0xc1, 0xc6, 0x56, 0x98, 0x18, 0x83, 0x65, 0x02, 0x40, 0x5c, 0xc5, 0xeb, 0xf9, 0x51, 
        0xb4, 0xe9, 0x57, 0x1b, 0x90, 0x17, 0x53, 0xd0, 0x5e, 0x13, 0xd8, 0xc2, 0xdc, 0x81, 0x3b, 0xc6
    } };

    ck_assert_str_eq(e.key, key);
    ck_assert_int_eq(memcmp(&e.auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e.value_off, 0);
    ck_assert_int_eq(e.value_len, 0);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_non_existing_key_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char k1[] = "sham"; // hash = 7
    char k2[] = "says";
    char pwd[] = "00001111";

    init_ckvs(ckvs, 64, 10);
    strcpy(ckvs.entries[7].key, k1);
    ckvs.header.num_entries = 1;
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    ck_assert_int_eq(ckvs_local_new(DUMMY_NAME, k2, pwd), ERR_NONE);

    ckvs_entry_t e[2];
    FILE* f = fopen(DUMMY_NAME, "rb");
    ck_assert_ptr_nonnull(f);
    ck_assert_int_eq(fseek(f, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * 7, SEEK_SET), 0);
    ck_assert_int_eq(fread(e, sizeof(ckvs_entry_t), 2, f), 2);
    fclose(f);

    ckvs_sha_t auth_key = { {
        0x7c, 0x02, 0x25, 0xd5, 0x49, 0x0c, 0x1b, 0xbf, 0xcc, 0xa9, 0x6a, 0x2e, 0x02, 0x5d, 0x61, 0x6a, 
        0x66, 0xe2, 0x66, 0x99, 0x7d, 0xca, 0xd3, 0x55, 0x05, 0x07, 0x6e, 0x5f, 0x1d, 0x58, 0xfe, 0x31
    } };

    ck_assert_str_eq(e[0].key, k1);
    ck_assert_str_eq(e[1].key, k2);
    ck_assert_int_eq(memcmp(&e[1].auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e[1].value_off, 0);
    ck_assert_int_eq(e[1].value_len, 0);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
Suite* new_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests of the 'new' command (may not be exhaustive!)");

    Add_Case(s, tc1, "New tests");
    tcase_add_test(tc1, new_NULL_arguments);
    tcase_add_test(tc1, new_already_existing_key_1);
    tcase_add_test(tc1, new_already_existing_key_2);
    tcase_add_test(tc1, new_non_existing_key_1);
    tcase_add_test(tc1, new_non_existing_key_2);

    return s;
}

TEST_SUITE(new_test_suite)
