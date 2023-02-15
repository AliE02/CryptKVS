/**
 * @file unit-test-set.c
 * @brief Unit tests for the local 'set' command
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

char value_filename[] = "./value.txt";

// ======================================================================
START_TEST(set_NULL_arguments)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char key[] = "key";
    char pwd[] = "pwd";

    ck_assert_int_eq(ckvs_local_set(NULL, NULL, NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_set(NULL, key, pwd, value_filename), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_set(NON_EXISTING_CKVS, NULL, pwd, value_filename), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_set(NON_EXISTING_CKVS, key, NULL, value_filename), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_local_set(NON_EXISTING_CKVS, key, pwd, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(set_non_existing_key_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char buffer[] = "decrypted value";

    init_ckvs(ckvs, 64, 1);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries), 0);
    ck_assert_int_eq(create_file_and_dump_value(value_filename, buffer, strlen(buffer)), 0);

    char key[] = "key";
    char pwd[] = "pwd";

    ck_assert_int_eq(ckvs_local_set(DUMMY_NAME, key, pwd, value_filename), ERR_KEY_NOT_FOUND);

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(set_non_existing_key_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char buffer[] = "decrypted value";

    init_ckvs(ckvs, 64, 1);
    strcpy(ckvs.entries[44].key, "key");
    ckvs.header.num_entries = 1;

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries), 0);
    ck_assert_int_eq(create_file_and_dump_value(value_filename, buffer, strlen(buffer)), 0);
    
    char key[] = "key2";
    char pwd[] = "pwd";

    ck_assert_int_eq(ckvs_local_set(DUMMY_NAME, key, pwd, value_filename), ERR_KEY_NOT_FOUND);

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(set_non_existing_key_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char buffer[] = "decrypted value";

    init_ckvs(ckvs, 64, 1);
    ckvs_sha_t auth_key = { { // auth_key of "key|pwd"
        0xc1, 0x1c, 0x38, 0xd8, 0xeb, 0xc1, 0xe6, 0x0c, 0x6f, 0xe6, 0x7e, 0xa5, 0x25, 0x68, 0x23, 0x0c,
        0xa0, 0x1e, 0x89, 0x12, 0x2a, 0x1e, 0x8f, 0x13, 0xb5, 0xac, 0xad, 0x03, 0xa5, 0x69, 0x46, 0xac 
    } };
    strcpy(ckvs.entries[44].key, "xxo"); // hash = 44
    memcpy(&ckvs.entries[44].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 1;

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries), 0);
    ck_assert_int_eq(create_file_and_dump_value(value_filename, buffer, strlen(buffer)), 0);
    
    char key[] = "key"; // hash = 44
    char pwd[] = "pwd";

    ck_assert_int_eq(ckvs_local_set(DUMMY_NAME, key, pwd, value_filename), ERR_KEY_NOT_FOUND);

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(set_existing_key_wrong_pwd_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char buffer[] = "decrypted value";    
    char key[] = "key";
    char pwd[] = "pwd-wrong";

    init_ckvs(ckvs, 64, 1);
    ckvs_sha_t auth_key = { { // auth_key of "key|pwd"
        0xc1, 0x1c, 0x38, 0xd8, 0xeb, 0xc1, 0xe6, 0x0c, 0x6f, 0xe6, 0x7e, 0xa5, 0x25, 0x68, 0x23, 0x0c,
        0xa0, 0x1e, 0x89, 0x12, 0x2a, 0x1e, 0x8f, 0x13, 0xb5, 0xac, 0xad, 0x03, 0xa5, 0x69, 0x46, 0xac 
    } };
    strcpy(ckvs.entries[44].key, key); // hash = 44
    memcpy(&ckvs.entries[44].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 1;

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries), 0);
    ck_assert_int_eq(create_file_and_dump_value(value_filename, buffer, strlen(buffer)), 0);

    ck_assert_int_eq(ckvs_local_set(DUMMY_NAME, key, pwd, value_filename), ERR_DUPLICATE_ID);

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(set_existing_key_correct_pwd_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char buffer[] = "decrypted value";    
    char key[] = "key";
    char pwd[] = "pwd";

    init_ckvs(ckvs, 64, 1);
    ckvs_sha_t auth_key = { { // auth_key of "key|pwd"
        0xc1, 0x1c, 0x38, 0xd8, 0xeb, 0xc1, 0xe6, 0x0c, 0x6f, 0xe6, 0x7e, 0xa5, 0x25, 0x68, 0x23, 0x0c,
        0xa0, 0x1e, 0x89, 0x12, 0x2a, 0x1e, 0x8f, 0x13, 0xb5, 0xac, 0xad, 0x03, 0xa5, 0x69, 0x46, 0xac 
    } };
    strcpy(ckvs.entries[44].key, key); // hash = 44
    memcpy(&ckvs.entries[44].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 1;

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries), 0);
    ck_assert_int_eq(create_file_and_dump_value(value_filename, buffer, strlen(buffer)), 0);

    ck_assert_int_eq(ckvs_local_set(DUMMY_NAME, key, pwd, value_filename), ERR_NONE);

    ckvs_entry_t e;
    FILE* f = fopen(DUMMY_NAME, "rb");
    ck_assert_int_eq(fseek(f, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * 44, SEEK_SET), 0);
    ck_assert_int_eq(fread(&e, sizeof(ckvs_entry_t), 1, f), 1);
    fclose(f);

    ck_assert_str_eq(e.key, key);
    ck_assert_int_eq(memcmp(&e.auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e.value_off, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size);
    ck_assert_int_eq(e.value_len, 32);

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(set_existing_key_correct_pwd_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char buffer[] = "decrypted val!";    
    char k1[] = "boy"; // hash=12
    char k2[] = "tye"; // hash=12
    char pwd[] = "123456789";

    init_ckvs(ckvs, 64, 2);
    ckvs_sha_t auth_key = { { // auth_key of "tye|123456789"
        0x09, 0xc5, 0xf9, 0xe4, 0xd4, 0xaa, 0x41, 0x43, 0xc7, 0x3f, 0x6e, 0xaf, 0x48, 0xd3, 0x53, 0xb2, 
        0xd9, 0xeb, 0x77, 0x9c, 0x22, 0x17, 0x4a, 0x96, 0x72, 0x63, 0x00, 0x4a, 0x11, 0xf3, 0x26, 0xe5
    } };
    strcpy(ckvs.entries[12].key, k1);
    strcpy(ckvs.entries[13].key, k2);
    memcpy(&ckvs.entries[13].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 2;

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries), 0);
    ck_assert_int_eq(create_file_and_dump_value(value_filename, buffer, strlen(buffer)), 0);

    ck_assert_int_eq(ckvs_local_set(DUMMY_NAME, k2, pwd, value_filename), ERR_NONE);

    ckvs_entry_t e;
    FILE* f = fopen(DUMMY_NAME, "rb");
    ck_assert_int_eq(fseek(f, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * 13, SEEK_SET), 0);
    ck_assert_int_eq(fread(&e, sizeof(ckvs_entry_t), 1, f), 1);
    fclose(f);

    ck_assert_str_eq(e.key, k2);
    ck_assert_int_eq(memcmp(&e.auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e.value_off, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size);
    ck_assert_int_eq(e.value_len, 16);

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(set_existing_key_correct_pwd_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    char buffer[] = "101 97 89 83 79 73 71 67 61 59 53 47 43 41 37 31 29 23 19 17 13 11 7 5 3 2";
    // add some padding at the end of the ckvs file
    uint8_t padding[] = { 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39 };
    char k1[] = "avon"; // hash=63
    char k2[] = "avos"; // hash=63
    char pwd[] = "1234";

    init_ckvs(ckvs, 64, 2);
    ckvs_sha_t auth_key = { { // auth_key of "avos|1234"
        0xdb, 0xb8, 0x6a, 0xe4, 0x6f, 0x97, 0x69, 0x60, 0xf2, 0x2c, 0xdc, 0x53, 0x9b, 0x28, 0x37, 0x8f, 
        0x37, 0x47, 0xb9, 0xbe, 0xc9, 0x2d, 0x15, 0xaf, 0x5c, 0x5e, 0xa1, 0x9f, 0x8c, 0x52, 0x9d, 0xfc
    } };
    strcpy(ckvs.entries[63].key, k1);
    strcpy(ckvs.entries[0].key, k2);
    memcpy(&ckvs.entries[0].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 2;

    FILE* f = fopen(DUMMY_NAME, "wb");
    ck_assert_ptr_nonnull(f);
    ck_assert_int_eq(dump_db(f, &ckvs.header, ckvs.entries), 0);
    ck_assert_int_eq(fwrite(padding, sizeof(padding), 1, f), 1);
    ck_assert_int_eq(create_file_and_dump_value(value_filename, buffer, strlen(buffer)), 0);
    fclose(f);

    ck_assert_int_eq(ckvs_local_set(DUMMY_NAME, k2, pwd, value_filename), ERR_NONE);

    ckvs_entry_t e;
    f = fopen(DUMMY_NAME, "rb");
    ck_assert_int_eq(fseek(f, sizeof(ckvs_header_t), SEEK_SET), 0);
    ck_assert_int_eq(fread(&e, sizeof(ckvs_entry_t), 1, f), 1);
    fclose(f);

    ck_assert_str_eq(e.key, k2);
    ck_assert_int_eq(memcmp(&e.auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e.value_off, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size + sizeof(padding));
    ck_assert_int_eq(e.value_len, 80);

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
Suite* set_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests of the 'set' command (may not be exhaustive!)");

    Add_Case(s, tc1, "Set tests");
    tcase_add_test(tc1, set_NULL_arguments);
    tcase_add_test(tc1, set_non_existing_key_1);
    tcase_add_test(tc1, set_non_existing_key_2);
    tcase_add_test(tc1, set_non_existing_key_3);
    tcase_add_test(tc1, set_existing_key_wrong_pwd_1);
    tcase_add_test(tc1, set_existing_key_correct_pwd_1);
    tcase_add_test(tc1, set_existing_key_correct_pwd_2);
    tcase_add_test(tc1, set_existing_key_correct_pwd_3);

    return s;
}

TEST_SUITE(set_test_suite)
