/**
 * @file unit-test-rpc.c
 * @brief Unit tests for the ckvs_rpc.h functions
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
#include "ckvs_rpc.h"

#include "ckvs_test_util.h"

IMPLEMENT_MUTED_PPS_PRINTF


// ======================================================================
START_TEST(rpc_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_connection_t conn;
    const char get[] = "abc";
    ck_assert_int_eq(ckvs_rpc(NULL, NULL), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_rpc(NULL, get), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_rpc(&conn, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(rpc_valid_url_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_connection_t conn;
    ckvs_rpc_init(&conn, "https://cs212.epfl.ch");
    const char get[] = "/stats";
    ck_assert_int_eq(ckvs_rpc(&conn, get), ERR_NONE);

    ck_assert_ptr_nonnull(conn.resp_buf);
    ckvs_rpc_close(&conn);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(rpc_invalid_curl_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_connection_t conn;
    ckvs_rpc_init(&conn, "https://cs212.epfl.ch");
    const char get[] = "/abc";
    ck_assert_int_eq(ckvs_rpc(&conn, get), ERR_NONE);

    ck_assert_ptr_nonnull(conn.resp_buf);
    ck_assert_str_eq(conn.resp_buf, "Error: Invalid command");
    ckvs_rpc_close(&conn);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
Suite* rpc_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests for rpc module (may not be exhaustive!)");

    Add_Case(s, tc1, "Rpc tests");
    tcase_add_test(tc1, rpc_NULL);
    tcase_add_test(tc1, rpc_valid_url_1);
    tcase_add_test(tc1, rpc_invalid_curl_1);

    return s;
}

TEST_SUITE(rpc_test_suite)
