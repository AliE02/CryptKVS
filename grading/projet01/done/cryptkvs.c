/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"

/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */

/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        pps_printf("- cryptkvs <database> stats\n"); // penser à mettre les messages comme global constants utile??
        pps_printf("- cryptkvs <database> get <key> <password>\n");
        pps_printf("- cryptkvs <database> set <key> <password> <filename>");
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) { //should we change the >= to > (is NO_ERROR an error??)
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{
    if(argv == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (argc < 3) return ERR_INVALID_COMMAND;

    const char* db_filename = argv[1];
    const char* cmd = argv[2];

    if(strcmp(cmd, "stats") == 0){
        //if (argc < 3) return ERR_NOT_ENOUGH_ARGUMENTS;
        //if (argc > 3) return ERR_TOO_MANY_ARGUMENTS;
        return ckvs_local_stats(db_filename);
    }
    if(strcmp(cmd,"get") == 0){
        if(argc < 5) { return ERR_NOT_ENOUGH_ARGUMENTS;}
        if(argc > 5) { return ERR_TOO_MANY_ARGUMENTS;}
        return ckvs_local_get(db_filename,argv[3],argv[4]);
    }
    if(strcmp(cmd,"set") == 0){
        if(argc < 6) { return ERR_NOT_ENOUGH_ARGUMENTS;}
        if(argc > 6) { return ERR_TOO_MANY_ARGUMENTS;}
        return ckvs_local_set(db_filename,argv[3],argv[4],argv[5]);
    }
    return ERR_INVALID_COMMAND;
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[])
{
    int ret = ckvs_do_one_cmd(argc, argv);
    //printf("ret = %d\n", ret);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
