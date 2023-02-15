/**
 * @file unit-test-ios.c
 * @brief Unit tests for the ckvs_io functions
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
#include "ckvs_io.h"

#include "ckvs_test_util.h"

IMPLEMENT_MUTED_PPS_PRINTF


// ======================================================================
START_TEST(CKVS_struct_offsets)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // In the struct CKVS, please respect the order : header, entries, file, listening_addr
    ck_assert_int_eq(offsetof(struct CKVS, header), 0);
    ck_assert_int_eq(offsetof(struct CKVS, entries), sizeof(struct ckvs_header));
    ck_assert_int_eq(offsetof(struct CKVS, file), sizeof(struct ckvs_header) + sizeof(struct ckvs_entry*));
    ck_assert_int_eq(offsetof(struct CKVS, listening_addr), sizeof(struct ckvs_header) + sizeof(struct ckvs_entry*) + sizeof(FILE*));
    ck_assert_int_eq(sizeof(struct CKVS), sizeof(struct ckvs_header) + sizeof(struct ckvs_entry*) + sizeof(FILE*) + sizeof(char*));

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_null_arguments)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(NULL, &ckvs), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_open(NON_EXISTING_CKVS, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_non_existing_file)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(NON_EXISTING_CKVS, &ckvs), ERR_IO);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
START_TEST(open_invalid_header_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 Crypt", 1, 64, 10, 0); // invalid header_str
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);


    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 2, 64, 16, 0); // version != 1
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);


    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 66, 10, 0); // not a power of 2 (and != 64 for weeks < 8)
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_4)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 64, 10, 0);

    FILE* f = fopen(DUMMY_NAME, "wb");
    ck_assert_ptr_nonnull(f);
    ck_assert_int_eq(fwrite(&header, sizeof(ckvs_header_t) / 2, 1, f), 1); // write half the header only
    fclose(f);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_IO);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_5)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 64, 10, 0);

    ckvs_entry_t* entries = calloc(63, sizeof(ckvs_entry_t)); // do not write enough entries
    ck_assert_ptr_nonnull(entries);

    FILE* f = fopen(DUMMY_NAME, "wb");
    ck_assert_ptr_nonnull(f);

    ck_assert_int_eq(fwrite(&header, sizeof(ckvs_header_t), 1, f), 1);
    ck_assert_int_eq(fwrite(entries, sizeof(ckvs_entry_t), 63, f), 63);
    fclose(f);
    free(entries);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_IO);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_valid_header_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(h, "CS212 CryptKVS001", 1, 64, 10, 1);

    ckvs_entry_t* entries = calloc(h.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    strcpy(entries[h.table_size / 2].key, "Test key");
    strcpy((char*) entries[h.table_size / 2].auth_key.sha, "hello world");
    strcpy((char*) entries[h.table_size / 2].c2.sha, "foo bar baz qux");
    entries[h.table_size / 2].value_off = 1235;
    entries[h.table_size / 2].value_len = 81321;

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &h, entries), 0);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_NONE);

    // header & entries should be the same
    ck_assert_int_eq(memcmp(&ckvs.header, &h, sizeof(ckvs_header_t)), 0);
    ck_assert_int_eq(memcmp(ckvs.entries, entries, h.table_size * sizeof(ckvs_entry_t)), 0);
    // file should stay open and not null:
    ck_assert_ptr_nonnull(ckvs.file); 
    ck_assert_int_ne(ftell(ckvs.file), -1);

    free(entries);
    ckvs_close(&ckvs);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(close_NULL_file)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    struct CKVS ckvs;
    ckvs.entries = NULL;
    ckvs.file = NULL;

    // should not segfault
    ckvs_close(NULL);
    ckvs_close(&ckvs);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(close_open_file)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(h, "CS212 CryptKVS001", 1, 64, 10, 0);

    ckvs_entry_t* entries = calloc(h.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &h, entries), 0);
    free(entries);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_NONE);


    ckvs_close(&ckvs);
    ck_assert_ptr_null(ckvs.file);
    // in weeks >= 8, entries should be freed as well
    ck_assert_ptr_null(ckvs.entries);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
START_TEST(find_entry_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    struct CKVS ckvs;
    const char* key = "some key";
    ckvs_sha_t auth_key;
    ckvs_entry_t* e_out = NULL;

    ck_assert_int_eq(ckvs_find_entry(NULL, NULL, NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_find_entry(NULL, key, &auth_key, &e_out), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_find_entry(&ckvs, NULL, &auth_key, &e_out), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_find_entry(&ckvs, key, NULL, &e_out), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_find_entry(&ckvs, key, &auth_key, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(find_entry_present_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // create empty CKVS struct:
    init_ckvs(ckvs, 64, 16);

    const char* key = "some key";
    const uint32_t idx = 46; // not at random, compatible with hash (weeks >= 7)
    ckvs_sha_t auth_key;
    ckvs_entry_t* e_out = NULL;


    strcpy(ckvs.entries[idx].key, key);
    memcpy(&ckvs.entries[idx].auth_key, &auth_key, SHA256_DIGEST_LENGTH);
    ckvs.header.num_entries = 1; // shouldn't matter, but for consistency
    
    ck_assert_int_eq(ckvs_find_entry(&ckvs, key, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_eq(e_out, ckvs.entries + idx);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(find_entry_present_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // create empty CKVS struct:
    init_ckvs(ckvs, 64, 16);

    const char* key = "test_key";
    const uint32_t idx = 18; // not at random, compatible with hash (weeks >= 7)
    ckvs_sha_t auth_key = { { 1 } };
    ckvs_sha_t stored_key = { { 0xFF } };
    ckvs_entry_t* e_out = NULL;

    strcpy(ckvs.entries[idx].key, key);
    memcpy(&ckvs.entries[idx].auth_key, &stored_key, SHA256_DIGEST_LENGTH);
    ckvs.header.num_entries = 1; // shouldn't matter, but for consistency
    
    ck_assert_int_eq(ckvs_find_entry(&ckvs, key, &auth_key, &e_out), ERR_DUPLICATE_ID);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(find_entry_present_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // create empty CKVS struct:
    init_ckvs(ckvs, 64, 16);
    ckvs.header.num_entries = 2; // shouldn't matter, but for consistency

    // setup a collision on hash(key)
    const uint32_t idx = 6;
    const char* k1 = "izkz"; // hash mod 64 = 6
    const char* k2 = "ilcm"; // hash mod 64 = 6
    ckvs_sha_t auth_key = { { 1 } };
    ckvs_entry_t* e_out = NULL;

    strcpy(ckvs.entries[idx].key, k1);
    memcpy(&ckvs.entries[idx].auth_key, &auth_key, SHA256_DIGEST_LENGTH);
    strcpy(ckvs.entries[idx + 1].key, k2);
    memcpy(&ckvs.entries[idx + 1].auth_key, &auth_key, SHA256_DIGEST_LENGTH);
    
    ck_assert_int_eq(ckvs_find_entry(&ckvs, k2, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_eq(e_out, ckvs.entries + idx + 1);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(find_entry_present_4)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // create empty CKVS struct:
    init_ckvs(ckvs, 64, 16);
    ckvs.header.num_entries = 2; // shouldn't matter, but for consistency

    // setup a collision on hash(key)
    const char* k1 = "two"; // hash mod 64 = 63
    const char* k2 = "phi"; // hash mod 64 = 63
    ckvs_sha_t auth_key = { { 1 } };
    ckvs_entry_t* e_out = NULL;

    // k1 is at idx 63, then k2 at idx 0 (we cycled back)
    strcpy(ckvs.entries[63].key, k1);
    memcpy(&ckvs.entries[63].auth_key, &auth_key, SHA256_DIGEST_LENGTH);
    strcpy(ckvs.entries[0].key, k2);
    memcpy(&ckvs.entries[0].auth_key, &auth_key, SHA256_DIGEST_LENGTH);
    
    ck_assert_int_eq(ckvs_find_entry(&ckvs, k2, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_eq(e_out, ckvs.entries);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(find_entry_present_5)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // create empty CKVS struct:
    init_ckvs(ckvs, 1024, 16); // should work with table_size != 64
    ckvs.header.num_entries = 1; // shouldn't matter, but for consistency

    // setup a collision on hash(key)
    const uint32_t idx = 3;
    const char* key = "1234";
    ckvs_sha_t auth_key = { { 1 } };
    ckvs_entry_t* e_out = NULL;

    strcpy(ckvs.entries[idx].key, key);
    memcpy(&ckvs.entries[idx].auth_key, &auth_key, SHA256_DIGEST_LENGTH);
    
    ck_assert_int_eq(ckvs_find_entry(&ckvs, key, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_eq(e_out, ckvs.entries + idx);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(write_encrypted_value_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    struct CKVS ckvs;
    const uint64_t buflen = 10;
    const unsigned char buff[buflen];

    ckvs_write_encrypted_value(NULL, NULL, NULL, 0);
    ckvs_write_encrypted_value(NULL, ckvs.entries, buff, buflen);
    ckvs_write_encrypted_value(&ckvs, NULL, buff, buflen);
    ckvs_write_encrypted_value(&ckvs, ckvs.entries, NULL, buflen);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(write_encrypted_value_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    FILE* dummy = fopen(DUMMY_NAME, "w+b");
    ck_assert_ptr_nonnull(dummy);
    
    init_ckvs(ckvs, 64, 16);
    ck_assert_int_eq(dump_db(dummy, &ckvs.header, ckvs.entries), 0);
    ckvs.file = dummy;

    const unsigned char buff[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const uint64_t len = sizeof(buff);
    ckvs_entry_t expected = { "ABCDEFGHIJKLMNOPQRST", { { 0x7 } }, { { 0x1 } }, 0, 0 };
    memcpy(ckvs.entries, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;
    expected.value_off = sizeof(ckvs_header_t) + ckvs.header.table_size * sizeof(ckvs_entry_t);
    expected.value_len = len;


    ck_assert_int_eq(ckvs_write_encrypted_value(&ckvs, ckvs.entries, buff, len), ERR_NONE);

    // ckvs_write_encrypted_value should set value offset and length in entries array
    ck_assert_int_eq(ckvs.entries[0].value_off, expected.value_off);
    ck_assert_int_eq(ckvs.entries[0].value_len, len);

    // data appended at the end of the file should be == to buff
    ck_assert_int_eq(fseek(dummy, ckvs.entries[0].value_off, SEEK_SET), 0);
    unsigned char read_data[len];
    ck_assert_int_eq(fread(read_data, 1, len, dummy), len);
    ck_assert_int_eq(memcmp(read_data, buff, len), 0);    

    // entry should have been overwritten in the file
    assert_stored_entry_eq(dummy, 0, &expected);

    fclose(dummy);
    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(write_encrypted_value_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    FILE* dummy = fopen(DUMMY_NAME, "w+b");
    ck_assert_ptr_nonnull(dummy);
    
    init_ckvs(ckvs, 64, 16);
    ck_assert_int_eq(dump_db(dummy, &ckvs.header, ckvs.entries), 0);
    const uint8_t padding[] = { 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233 };
    ck_assert_int_eq(fwrite(padding, sizeof(padding), 1, dummy), 1); // append some bytes after entries
    ckvs.file = dummy;

    const size_t idx = 41;
    const uint64_t len = 32767; // 32KB
    unsigned char* buff = malloc(len);
    ckvs_entry_t expected = { { 0 }, { { 0xF } }, { { 0xA } }, 15, 10 };
    strcpy(expected.key, "ABCD");
    memcpy(ckvs.entries + idx, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;
    expected.value_off = sizeof(ckvs_header_t) + ckvs.header.table_size * sizeof(ckvs_entry_t) + sizeof(padding);
    expected.value_len = len;

    ck_assert_int_eq(ckvs_write_encrypted_value(&ckvs, ckvs.entries + idx, buff, len), ERR_NONE);

    // ckvs_write_encrypted_value should set value offset and length in entries array
    ck_assert_int_eq(ckvs.entries[idx].value_off, expected.value_off);
    ck_assert_int_eq(ckvs.entries[idx].value_len, len);

    // data appended at the end of the file should be == to buff
    ck_assert_int_eq(fseek(dummy, ckvs.entries[idx].value_off, SEEK_SET), 0);
    unsigned char read_data[len];
    ck_assert_int_eq(fread(read_data, 1, len, dummy), len);
    ck_assert_int_eq(memcmp(read_data, buff, len), 0);    

    // entry should have been overwritten in the file
    assert_stored_entry_eq(dummy, idx, &expected);

    free(buff);
    fclose(dummy);
    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(write_encrypted_value_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    FILE* dummy = fopen(DUMMY_NAME, "w+b");
    ck_assert_ptr_nonnull(dummy);
    
    init_ckvs(ckvs, 256, 30); // table_size != 64
    ck_assert_int_eq(dump_db(dummy, &ckvs.header, ckvs.entries), 0);
    const uint8_t padding[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59 };
    ck_assert_int_eq(fwrite(padding, sizeof(padding), 1, dummy), 1); // append some bytes after entries
    ckvs.file = dummy;

    const size_t idx = 245;
    char buff[] = "My super secret value is 42";
    const uint64_t len = sizeof(buff); // 32KB
    ckvs_entry_t expected = { { 0 }, { { 0xF } }, { { 0xA } }, 15, 10 };
    strcpy(expected.key, "yet another key");
    memcpy(ckvs.entries + idx, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;
    expected.value_off = sizeof(ckvs_header_t) + ckvs.header.table_size * sizeof(ckvs_entry_t) + sizeof(padding);
    expected.value_len = len;

    ck_assert_int_eq(ckvs_write_encrypted_value(&ckvs, ckvs.entries + idx, (unsigned char*) buff, len), ERR_NONE);

    // ckvs_write_encrypted_value should set value offset and length in entries array
    ck_assert_int_eq(ckvs.entries[idx].value_off, expected.value_off);
    ck_assert_int_eq(ckvs.entries[idx].value_len, len);

    // data appended at the end of the file should be == to buff
    ck_assert_int_eq(fseek(dummy, ckvs.entries[idx].value_off, SEEK_SET), 0);
    unsigned char read_data[len];
    ck_assert_int_eq(fread(read_data, 1, len, dummy), len);
    ck_assert_int_eq(memcmp(read_data, buff, len), 0);    

    // entry should have been overwritten in the file
    assert_stored_entry_eq(dummy, idx, &expected);

    fclose(dummy);
    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 30);
    const char* key = "key";
    ckvs_sha_t auth_key;
    ckvs_entry_t* e_out = NULL;

    ck_assert_int_eq(ckvs_new_entry(NULL, NULL, NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_new_entry(NULL, key, &auth_key, &e_out), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_new_entry(&ckvs, NULL, &auth_key, &e_out), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_new_entry(&ckvs, key, NULL, &e_out), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_new_entry(&ckvs, key, &auth_key, NULL), ERR_INVALID_ARGUMENT);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_on_full_table)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 10);
    ckvs.header.num_entries = 10;
    const char* key = "key";
    ckvs_sha_t auth_key;
    ckvs_entry_t* e_out = NULL;

    ck_assert_int_eq(ckvs_new_entry(&ckvs, key, &auth_key, &e_out), ERR_MAX_FILES);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_key_already_present_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 2);
    // setup a conflicting entry
    const size_t idx = 44;
    const char* key = "key";
    ckvs_sha_t auth_key = { { 0x02 } };
    strcpy(ckvs.entries[idx].key, key);
    memcpy(&ckvs.entries[idx].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 1;

    // there's already an entry with same key (and auth_key)
    ckvs_entry_t* e_out = NULL;
    ck_assert_int_eq(ckvs_new_entry(&ckvs, key, &auth_key, &e_out), ERR_DUPLICATE_ID);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_key_already_present_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    init_ckvs(ckvs, 64, 10);
    // setup 2 entries with same hash
    const size_t idx = 26;
    const char* k1 = "rom";
    const char* k2 = "ooo";
    ckvs_sha_t auth_key = { { 0xF0 } };
    strcpy(ckvs.entries[idx].key, k1);
    memcpy(&ckvs.entries[idx].auth_key, &auth_key, sizeof(ckvs_sha_t));
    strcpy(ckvs.entries[idx + 1].key, k2);
    memcpy(&ckvs.entries[idx + 1].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 2;

    // this time with same key (k2) but auth_key different
    auth_key.sha[SHA256_DIGEST_LENGTH - 1] = 0;
    ckvs_entry_t* e_out = NULL;
    ck_assert_int_eq(ckvs_new_entry(&ckvs, k2, &auth_key, &e_out), ERR_DUPLICATE_ID);

    release_ckvs(ckvs);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_key_not_present_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    FILE* dummy = fopen(DUMMY_NAME, "w+b");
    ck_assert_ptr_nonnull(dummy);
    
    init_ckvs(ckvs, 64, 1);
    ck_assert_int_eq(dump_db(dummy, &ckvs.header, ckvs.entries), 0);
    ckvs.file = dummy;

    const size_t idx = 13;
    const char* key = "ABC-123";
    ckvs_sha_t auth_key = { { 0x1 } };
    ckvs_entry_t* e_out = NULL;

    ck_assert_int_eq(ckvs_new_entry(&ckvs, key, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_nonnull(e_out);

    assert_stored_entry_eq(dummy, idx, e_out);
    ck_assert_str_eq(e_out->key, key);
    ck_assert_int_eq(memcmp(&e_out->auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e_out->value_off, 0);
    ck_assert_int_eq(e_out->value_len, 0);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_key_not_present_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    FILE* dummy = fopen(DUMMY_NAME, "w+b");
    ck_assert_ptr_nonnull(dummy);
    
    init_ckvs(ckvs, 64, 5);
    ck_assert_int_eq(dump_db(dummy, &ckvs.header, ckvs.entries), 0);
    ckvs.file = dummy;

    // already existing entry
    const size_t idx = 36;
    const char* k1 = "pane"; // hash mod 64 = 36
    strcpy(ckvs.entries[idx].key, k1);

    const char* k2 = "poem"; // hash mod 64 = 36
    ckvs_sha_t auth_key = { { 0x1 } };
    ckvs_entry_t* e_out = NULL;

    ck_assert_int_eq(ckvs_new_entry(&ckvs, k2, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_nonnull(e_out);
    assert_stored_entry_eq(dummy, idx + 1, e_out);

    ck_assert_str_eq(e_out->key, k2);
    ck_assert_int_eq(memcmp(&e_out->auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e_out->value_off, 0);
    ck_assert_int_eq(e_out->value_len, 0);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_key_not_present_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    FILE* dummy = fopen(DUMMY_NAME, "w+b");
    ck_assert_ptr_nonnull(dummy);
    
    init_ckvs(ckvs, 64, 5);
    ck_assert_int_eq(dump_db(dummy, &ckvs.header, ckvs.entries), 0);
    ckvs.file = dummy;

    // already existing entry
    const char* k1 = "cawzy"; // hash mod 64 = 63
    strcpy(ckvs.entries[63].key, k1);

    const char* k2 = "damne"; // hash mod 64 = 63
    ckvs_sha_t auth_key = { { 0x1 } };
    ckvs_entry_t* e_out = NULL;

    ck_assert_int_eq(ckvs_new_entry(&ckvs, k2, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_nonnull(e_out);
    assert_stored_entry_eq(dummy, 0, e_out);

    ck_assert_str_eq(e_out->key, k2);
    ck_assert_int_eq(memcmp(&e_out->auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e_out->value_off, 0);
    ck_assert_int_eq(e_out->value_len, 0);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(new_entry_key_not_present_4)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    FILE* dummy = fopen(DUMMY_NAME, "w+b");
    ck_assert_ptr_nonnull(dummy);
    
    init_ckvs(ckvs, 16, 4);
    ck_assert_int_eq(dump_db(dummy, &ckvs.header, ckvs.entries), 0);
    ckvs.file = dummy;

    // already existing entry
    const char* k1 = "aaaan"; // hash mod 16 = 15
    strcpy(ckvs.entries[15].key, k1);

    const char* k2 = "aaaci"; // hash mod 16 = 15
    ckvs_sha_t auth_key = { { 0x1 } };
    ckvs_entry_t* e_out = NULL;

    ck_assert_int_eq(ckvs_new_entry(&ckvs, k2, &auth_key, &e_out), ERR_NONE);
    ck_assert_ptr_nonnull(e_out);
    assert_stored_entry_eq(dummy, 0, e_out);

    ck_assert_str_eq(e_out->key, k2);
    ck_assert_int_eq(memcmp(&e_out->auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
    ck_assert_int_eq(e_out->value_off, 0);
    ck_assert_int_eq(e_out->value_len, 0);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST



// ======================================================================
Suite* ios_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests for IO operations (may not be exhaustive!)");

    Add_Case(s, tc1, "IOs tests");
    tcase_add_test(tc1, CKVS_struct_offsets);
    tcase_add_test(tc1, open_null_arguments);
    tcase_add_test(tc1, open_non_existing_file);
    tcase_add_test(tc1, open_invalid_header_1);
    tcase_add_test(tc1, open_invalid_header_2);
    tcase_add_test(tc1, open_invalid_header_3);
    tcase_add_test(tc1, open_invalid_header_4);
    tcase_add_test(tc1, open_invalid_header_5);
    tcase_add_test(tc1, open_valid_header_1);
    tcase_add_test(tc1, close_NULL_file);
    tcase_add_test(tc1, close_open_file);
    tcase_add_test(tc1, find_entry_NULL);
    tcase_add_test(tc1, find_entry_present_1);
    tcase_add_test(tc1, find_entry_present_2);
    tcase_add_test(tc1, find_entry_present_3);
    tcase_add_test(tc1, find_entry_present_4);
    tcase_add_test(tc1, find_entry_present_5);
    tcase_add_test(tc1, write_encrypted_value_NULL);
    tcase_add_test(tc1, write_encrypted_value_1);
    tcase_add_test(tc1, write_encrypted_value_2);
    tcase_add_test(tc1, write_encrypted_value_3);
    tcase_add_test(tc1, new_entry_NULL);
    tcase_add_test(tc1, new_entry_on_full_table);
    tcase_add_test(tc1, new_entry_key_already_present_1);
    tcase_add_test(tc1, new_entry_key_already_present_2);
    tcase_add_test(tc1, new_entry_key_not_present_1);
    tcase_add_test(tc1, new_entry_key_not_present_2);
    tcase_add_test(tc1, new_entry_key_not_present_3);
    tcase_add_test(tc1, new_entry_key_not_present_4);

    return s;
}

TEST_SUITE(ios_test_suite)
