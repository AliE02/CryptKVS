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
 * @brief Utilitary function used by the functions get/set, opens the CKVS database at
 * the given filename and executes the 'get' or 'set' command, depending on value of set_value
 * 
 * @param filename  (const char*) the path to the CKVS database to open
 * @param key       (const char*) the key of the entry to get
 * @param pwd       (const char*) the password of the entry to get
 * @param set_value (const char*) if NULL then get else set
 * @return int, an error code
 */
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value){
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

    //places the file pointer at the entry's offset
    ret_value = fseek(ckvs.file, (long)entry->value_off, SEEK_SET);
    if (ret_value) {
        ckvs_close(&ckvs);
        M_EXIT(ERR_IO, "%s", "fseek bugs in ckvs_local_getset");
    }

    if(set_value == NULL){
        //reads encrypted value of the entry and stores it in bufferIn
        unsigned char bufferIn[entry->value_len];
        size_t nbElem = fread(&bufferIn, entry->value_len, 1, ckvs.file);
        if(nbElem != 1) {
            ckvs_close(&ckvs);
            M_EXIT(ERR_IO, "%s", "nbElem != 1 (ckvs_local_getset");
        }

        //initializes the output buffer
        size_t len = entry->value_len;
        unsigned char bufferOut[len];

        //computes the client masterkey with the read c2 key
        ret_value = ckvs_client_compute_masterkey(&mr, &entry->c2);
        if(ret_value) {
            ckvs_close(&ckvs);
            return ret_value;
        }

        //decrypts the value
        ret_value = ckvs_client_crypt_value(&mr, 0, bufferIn, entry->value_len,
                                bufferOut, &len);
        if(ret_value) {
            ckvs_close(&ckvs);
            return ret_value;
        }
        pps_printf("%s\n", bufferOut);

        return ERR_NONE;
    }else{
        if(RAND_bytes(entry->c2.sha, sizeof(entry->c2.sha)) != 1) {
            ckvs_close(&ckvs);
            return ERR_IO;
        }

        //computes the masterkey
        ret_value = ckvs_client_compute_masterkey(&mr, &entry->c2);
        if(ret_value) {
            ckvs_close(&ckvs);
            return ret_value;
        }

        //initializes the output buffer
        size_t len = strlen(set_value) + EVP_MAX_BLOCK_LENGTH;
        unsigned char bufferOut[len];

        ret_value = ckvs_client_crypt_value(&mr, 1, (unsigned char*)set_value,
                                            strlen(set_value) + 1, bufferOut,&len);
        if(ret_value) {
            ckvs_close(&ckvs);
            return ret_value;
        }

        ret_value = ckvs_write_encrypted_value(&ckvs,entry,bufferOut,len);
        if(ret_value) {
            ckvs_close(&ckvs);
            return ret_value;
        }

        return ERR_NONE;
    }
}

/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @return int, an error code
 */
int ckvs_local_stats(char* filename){
    CKVS_t ckvs;
    int res = ckvs_open(filename, &ckvs);
    if(res){ return res;}
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
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to get
 * @param pwd (const char*) the password of the entry to get
 * @return int, an error code
 */
int ckvs_local_get(const char *filename, const char *key, const char *pwd){
    M_REQUIRE_NON_NULL(filename); M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(key);
    return ckvs_local_getset(filename, key, pwd, NULL);
}

/**
 * @brief reads the content of filename and stores an encrypted version of it in the ckvs
 * 
 * @param filename 
 * @param key 
 * @param pwd 
 * @param valuefilename 
 * @return int 
 */
int ckvs_local_set(const char *filename, const char *key, const char *pwd, const char *valuefilename){
    M_REQUIRE_NON_NULL(filename);   M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);        M_REQUIRE_NON_NULL(valuefilename);

    char* buff = NULL;
    size_t buff_size = 0;

    int ret_value = read_value_file_content(valuefilename, &buff, &buff_size);
    if(ret_value != ERR_NONE) {
        free(buff);
        buff = NULL;
        return ret_value;
    }

    ret_value = ckvs_local_getset(filename, key, pwd, buff);
    free(buff);
    buff = NULL;
    return ret_value;
}
