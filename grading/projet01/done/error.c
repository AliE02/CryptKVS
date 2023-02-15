/**
 * @file error.c
 * @brief PPS (CS-212) error messages
 */

const char * const ERR_MESSAGES[] = {
    "", // no error
    "I/O Error",
    "(re|m|c)alloc failled",
    "Not enough arguments",
    "Too many arguments",
    "Invalid filename",
    "Invalid command",
    "Invalid argument",
    "Invalid max_files number",
    "Key not found",
    "No value",
    "Not implemented (yet?)",
    "Incorrect key/password",
    "Corrupt database file",
    "Timeout in network operation",
    "Protocol error",
    "no error (shall not be displayed)" // ERR_LAST
};


