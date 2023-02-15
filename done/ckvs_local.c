#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "error.h"
#include "ckvs.h"

#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

/**
 * @brief executes the 'get' command i.e gets the decrypted content of entry's value.
 *
 * @param ckvs (struct CKVS*) the ckvs database to read
 * @param mr (struct ckvs_memrecord*) the record which holds the keys
 * @param entry (struct cvks_entry*) the entry whose value is to be read
 * @return int, an error code
 */
static int do_get(const CKVS_t* ckvs, const ckvs_memrecord_t* mr, const ckvs_entry_t* entry){
    if(entry->value_len == 0){
        M_EXIT(ERR_NO_VALUE, "%s", "value_len = 0 in local_get");
    }

    //initializes the input buffer to store the encrypted value in
    unsigned char* bufferIn = calloc(entry->value_len + 1, sizeof(unsigned char));
    if(bufferIn == NULL) {
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "could not allocate memory for bufferIn (locagetset (get))");
    }
    //reads encrypted value of the entry and stores it in bufferIn
    size_t nbElem = fread(bufferIn, entry->value_len, 1, ckvs->file);
    if(nbElem != 1) {
        free(bufferIn); bufferIn = NULL;
        M_EXIT(ERR_IO, "%s", "nbElem != 1 (ckvs_local_getset");
    }

    //initializes the output buffer
    size_t len = entry->value_len + EVP_MAX_BLOCK_LENGTH;
    unsigned char* bufferOut = calloc(len + 1, sizeof(unsigned char));
    if(bufferOut == NULL) {
        free(bufferIn); bufferIn = NULL;
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "could not allocate memory for bufferOut (locagetset (get))");
    }

    //decrypts the value
    int ret_value = ckvs_client_crypt_value(mr, 0, bufferIn, entry->value_len,
                                            bufferOut, &len);
    free(bufferIn); bufferIn = NULL;
    if(ret_value) {
        free(bufferOut); bufferOut = NULL;
        return ret_value;
    }
    //outputs the decrypted value
    pps_printf("%s\n", bufferOut);
    free(bufferOut);  bufferOut = NULL;
    return ERR_NONE;
}

/**
 * @brief executes the 'set' command i.e sets the encrypted content of valuefilename as new content.
 *
 * @param ckvs (struct CKVS*) the ckvs database to modify
 * @param mr (struct ckvs_memrecord*) the record which holds the keys
 * @param entry (struct cvks_entry*) the entry whose value is to be set
 * @param set_value (const char*) the value to set
 * @return int, an error code
 */
static int do_set(CKVS_t* ckvs, const ckvs_memrecord_t* mr, ckvs_entry_t* entry, const char* set_value){
    //initializes the output buffer
    size_t len = strlen(set_value) + EVP_MAX_BLOCK_LENGTH;
    unsigned char* bufferOut = calloc(len + 1,sizeof(unsigned char));
    if(bufferOut == NULL) {
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "could not allocate memory for bufferIn (locagetset (get))");
    }

    int ret_value = ckvs_client_crypt_value(mr, 1, (const unsigned char*)set_value,
                                            strlen(set_value) + 1, bufferOut,&len);
    if(ret_value) {
        free(bufferOut); bufferOut = NULL;
        return ret_value;
    }

    ret_value = ckvs_write_encrypted_value(ckvs,entry,bufferOut,len);
    free(bufferOut); bufferOut = NULL;
    if(ret_value) {
        return ret_value;
    }
    return ERR_NONE;
}

/**
 * @brief Utilitary function used by the functions get/set, opens the CKVS database at
 * the given filename and executes the 'get' or 'set' command, depending on value of set_value
 * 
 * @param filename  (const char*) the path to the CKVS database to open
 * @param key       (const char*) the key of the entry to get
 * @param pwd       (const char*) the password of the entry to get
 * @param set_value (const char*) if NULL then get else set
 * @return int, an error code
 */
static int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value){
    M_REQUIRE_NON_NULL(filename); M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(pwd);
    int ret_value = 0;

    //opens and init the ckvs
    CKVS_t ckvs;
    ret_value = ckvs_open(filename, &ckvs);
    if(ret_value) {
        return ret_value;
    }

    //initializes the memrecord
    struct ckvs_memrecord mr;
    ret_value = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(ret_value) {
        ckvs_close(&ckvs);
        return ret_value;
    }

    //finds the entry at the given key
    ckvs_entry_t* entry = NULL;
    ret_value = ckvs_find_entry(&ckvs, key, &mr.auth_key, &entry);
    if(ret_value) {
        ckvs_close(&ckvs);
        return ret_value;
    }

    //generates C2 of the entry randomly
    if(set_value != NULL){
        if(RAND_bytes(entry->c2.sha, sizeof(entry->c2.sha)) != 1) {
            ckvs_close(&ckvs);
            M_EXIT(ERR_IO, "%s", "RAND_bytes seems not to work properly (ckvs_local_getset)");
        }
    }

    //computes the client masterkey with the entry's c2 key
    ret_value = ckvs_client_compute_masterkey(&mr, &entry->c2);
    if(ret_value) {
        ckvs_close(&ckvs);
        return ret_value;
    }

    //places the file pointer at the entry's offset
    ret_value = fseek(ckvs.file, (long)entry->value_off, SEEK_SET);
    if (ret_value) {
        ckvs_close(&ckvs);
        M_EXIT(ERR_IO, "%s", "fseek bugs in ckvs_local_getset");
    }

    if(set_value == NULL){
        ret_value = do_get(&ckvs,&mr,entry);
        ckvs_close(&ckvs);
        return ret_value;
    }else{
        ret_value = do_set(&ckvs,&mr,entry,set_value);
        ckvs_close(&ckvs);
        return ret_value;
    }
}

/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * 
 * @param filename : name of the database to open
 * @param optargc : number of optional arguments
 * @param optargv : optional arguments after
 * @return int 
 */
int ckvs_local_stats(char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);

    if(optargc > 0){ return ERR_TOO_MANY_ARGUMENTS;}
    if(optargc < 0){ return ERR_NOT_ENOUGH_ARGUMENTS;}
    CKVS_t ckvs;
    int res = ckvs_open(filename, &ckvs);
    if(res){return res;}
    print_header(&ckvs.header);
    for(uint32_t i = 0; i <  ckvs.header.table_size; ++i){
        if(strlen(ckvs.entries[i].key) != 0) {
            print_entry(&ckvs.entries[i]);
        }
    }
    ckvs_close(&ckvs);
    return res;
}

/**
 * @brief Opens the CKVS database at the given filename and executes the 'get' command,
 * ie. fetches, decrypts and prints the entry corresponding to the key and password.
 * 
 * @param filename : name of the database to open
 * @param optargc : number of optional arguments
 * @param optargv : optional arguments after
 * @return int 
 */
int ckvs_local_get(const char *filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename); M_REQUIRE_NON_NULL(optargv);

    if(optargc < 2) { return ERR_NOT_ENOUGH_ARGUMENTS;}
    if(optargc > 2) { return ERR_TOO_MANY_ARGUMENTS;}
    
    const char *key = optargv[0];
    const char *pwd = optargv[1];

    M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(pwd);
    return ckvs_local_getset(filename, key, pwd, NULL);
}

/**
 * @brief Opens the CKVS database at the given filename and executes the 'set' command,
 * ie. fetches the entry corresponding to the key and password and
 * then sets the encrypted content of valuefilename as new content.
 * 
 * @param filename : name of the database to open
 * @param optargc : number of optional arguments
 * @param optargv : optional arguments after
 * @return int 
 */
int ckvs_local_set(const char *filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename); M_REQUIRE_NON_NULL(optargv);

    if(optargc < 3) { return ERR_NOT_ENOUGH_ARGUMENTS;}
    if(optargc > 3) { return ERR_TOO_MANY_ARGUMENTS;}

    const char *key = optargv[0];
    const char *pwd = optargv[1];
    const char *valuefilename = optargv[2];
    
    M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_NON_NULL(valuefilename);

    char* buff = NULL;
    size_t buff_size = 0;

    int ret_value = read_value_file_content(valuefilename, &buff, &buff_size);
    if(ret_value) {
        return ret_value;
    }

    ret_value = ckvs_local_getset(filename, key, pwd, buff);
    free(buff); buff = NULL;
    return ret_value;
}

/**
 * @brief Opens the CKVS database at the given filename and executes the 'new' command,
 * ie. creates a new entry with the given key and password.
 * 
 * @param filename : name of the database to open
 * @param optargc : number of optional arguments
 * @param optargv : optional arguments after
 * @return int 
 */
int ckvs_local_new(const char *filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename); M_REQUIRE_NON_NULL(optargv);

    if(optargc < 2) { return ERR_NOT_ENOUGH_ARGUMENTS;}
    if(optargc > 2) { return ERR_TOO_MANY_ARGUMENTS;}

    const char *key = optargv[0];
    const char *pwd = optargv[1];
    M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(pwd);

    CKVS_t ckvs;
    ckvs_memrecord_t mr;
    ckvs_entry_t* new_entry = NULL;
    
    int err = ckvs_open(filename, &ckvs);
    if(err){ 
        M_EXIT(err, "%s", "problem in ckvs_open (ckvs_local_new)");}

    //Generates stretched_key, auth_key and c1 and stores them into mr
    err = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(err){ 
        ckvs_close(&ckvs);
        M_EXIT(err, "%s", "problem in ckvs_client_encrypt_pwd (ckvs_local_new)");
    }

    //checks if it is possible to add an entry and adds it, returns an error otherwise
    err = ckvs_new_entry(&ckvs, key, &mr.auth_key, &new_entry);
    if(err){
        ckvs_close(&ckvs);
        M_EXIT(err, "%s", "problem in ckvs_new_entry (ckvs_local_new)");
    }

    ckvs_close(&ckvs);
    return ERR_NONE;
}
