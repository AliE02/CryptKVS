/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include <math.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"

typedef int (*ckvs_command)(const char* filename, int optargc, char* optargv[]);

typedef struct ckvs_command_mapping {
    const char* name;
    const char* description;
    ckvs_command function;
} ckvs_command_mapping_t;

const ckvs_command_mapping_t commands[4] = {{"stats","- cryptkvs <database> stats", *ckvs_local_stats},
                                            {"get","- cryptkvs <database> get <key> <password>",*ckvs_local_get},
                                            {"set","- cryptkvs <database> set <key> <password> <filename>",*ckvs_local_set},
                                            {"new","- cryptkvs <database> new <key> <password>",*ckvs_local_new}};

static void usage(const char *execname, int err){
    if (err == ERR_INVALID_COMMAND) {
        size_t sizeTab = sizeof(commands)/sizeof(ckvs_command_mapping_t);
        pps_printf("Available commands:\n");
        for(size_t i = 0; i < sizeTab; ++i) {
            pps_printf("%s %s\n",commands[i].name,commands[i].description);
        }
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}


/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */

int ckvs_do_one_cmd(int argc, char *argv[]){
    M_REQUIRE_NON_NULL(argv);
    if (argc < 3) return ERR_INVALID_COMMAND;

    const char* db_filename = argv[1];
    const char* cmd = argv[2];

    int optargc = argc - 3;
    char** optargv = argv + 3;

    size_t sizeTab = sizeof(commands)/sizeof(ckvs_command_mapping_t);
    size_t i = 0;
    while(i < sizeTab && strncmp(cmd, commands[i].name,strlen(cmd)) != 0) {++i;}
    return (i < sizeTab) ? commands[i].function(db_filename,optargc,optargv) : ERR_INVALID_COMMAND;

}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[]){
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
