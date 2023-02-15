
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <json-c/json_tokener.h>
#include <json-c/json_object.h>
#include <math.h>

#include "error.h"
#include "ckvs.h"
#include "util.h"

#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "ckvs_rpc.h"
#include "ckvs_client.h"
#include "mongoose.h"

/**
 * @brief handles a call to the stats function from the client perspective
 * 
 * @param url : the url to which we want to connect
 * @param optargc : the number of arguments for a stats call
 * @param optargv : the arguments for a stats call
 * @return int : error code
 */
int ckvs_client_stats(const char *url, int optargc, char **optargv){
    M_REQUIRE_NON_NULL(url);
    if(optargc > 0){ return ERR_TOO_MANY_ARGUMENTS;}
    if(optargc < 0){ return ERR_NOT_ENOUGH_ARGUMENTS;}

    //initializes the connection struct
    struct ckvs_connection conn;
    int ret_value = ckvs_rpc_init(&conn, url);
    if(ret_value != ERR_NONE){M_EXIT(ret_value, "%s", "problem while calling ckvs_rpc_init (ckvs_client_stats)");}

    ret_value = ckvs_rpc(&conn, "/stats");
    if(ret_value != ERR_NONE){
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value, "%s", "problem while calling ckvs_rpc (ckvs_client_stats)");}

    //parses the received string into a json_object
    struct json_object* jobjIn = json_tokener_parse(conn.resp_buf);
    if(jobjIn == NULL) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO,"%s","Error in tokener parse stats");
    }

    //gets the different json object's children
    struct json_object* jheaderString = NULL;
    json_object_object_get_ex(jobjIn,"header_string",&jheaderString);
    const char* headerString = json_object_get_string(jheaderString);
    if(headerString == NULL) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of headerstring fail");
    }

    struct json_object* jVersion = NULL;
    json_object_object_get_ex(jobjIn,"version",&jVersion);
    int version = json_object_get_int(jVersion);
    if(!version) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of version fail");
    }

    struct json_object* jTableSize = NULL;
    json_object_object_get_ex(jobjIn,"table_size",&jTableSize);
    int table_size = json_object_get_int(jTableSize);
    if(!table_size) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of table_size fail");
    }

    struct json_object* jTreshhold = NULL;
    json_object_object_get_ex(jobjIn,"threshold_entries",&jTreshhold);
    int treshold = json_object_get_int(jTreshhold);
    if(!treshold) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of treshold fail");
    }

    struct json_object* jNumEntries = NULL;
    json_object_object_get_ex(jobjIn,"num_entries",&jNumEntries);
    int num_entries = json_object_get_int(jNumEntries);
    if(!num_entries) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of table_size fail");
    }

    struct json_object* jKeys = NULL;
    json_object_object_get_ex(jobjIn,"keys",&jKeys);
    size_t length = json_object_array_length(jKeys);
    if(!length) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of length keys fail");
    }

    //construction of the ckvs_header
    ckvs_header_t header;
    strncpy(header.header_string,headerString,CKVS_HEADERSTRINGLEN);
    header.version = version;
    header.table_size = table_size;
    header.threshold_entries = treshold;
    header.num_entries = num_entries;
    print_header(&header);

    //parses and print the keys
    for(size_t i = 0; i < length; ++i){
        struct json_object* jElem = json_object_array_get_idx(jKeys,i);
        if(jElem == NULL) {
            pps_printf("%s", conn.resp_buf);
            ckvs_rpc_close(&conn);
            json_object_put(jobjIn);
            M_EXIT(ERR_IO,"%s","get of json indx fail");
        }
        const char* key = json_object_get_string(jElem);
        if(key == NULL) {
            pps_printf("%s", conn.resp_buf);
            ckvs_rpc_close(&conn);
            json_object_put(jobjIn);
            M_EXIT(ERR_IO,"%s","get of string of index json fail");
        }
        pps_printf("Key       : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n", key);
    }

    //closes the connec
    json_object_put(jobjIn);
    ckvs_rpc_close(&conn);
    return ERR_NONE;
}

/**
 * @brief handles a call to the get function from the client's perspective
 * 
 * @param url : the url to which we want to connect
 * @param optargc : the number of arguments passed for the get call (should be 2)
 * @param optargv : the arguments passed for the get call
 * @return int : error code
 */
int ckvs_client_get(const char *url, int optargc, char **optargv){
    //parsing of arguments
    M_REQUIRE_NON_NULL(optargv);
    if(optargc < 2) { return ERR_NOT_ENOUGH_ARGUMENTS;}
    if(optargc > 2) { return ERR_TOO_MANY_ARGUMENTS;}
    const char *key = optargv[0];
    const char *pwd = optargv[1];
    M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(pwd);

    //init of the connection
    struct ckvs_connection conn;
    int ret_value = ckvs_rpc_init(&conn, url);
    if(ret_value != ERR_NONE){ M_EXIT(ret_value, "%s", "problem while calling ckvs_rpc_init (ckvs_client_stats)");}

    //initializes the memrecord (generates the keys)
    struct ckvs_memrecord mr;
    ret_value = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(ret_value) {
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value, "%s", "problem when calling ckvs_encrypt_pwd (ckvs_client_stats)");
    }

    //call to server
    const char* keyUrl = "/get?key=";
    const char* authKeyUrl = "&auth_key=";

    size_t encodedCount = 2*SHA256_DIGEST_LENGTH;
    char* authEncoded = calloc(encodedCount + 1, sizeof(char));
    if(authEncoded == NULL){
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY,"%s","Calloc failed in get of client");
    }
    //encodes the auth key
    SHA256_to_string(&mr.auth_key,authEncoded);

    char* keyEscaped = curl_easy_escape(conn.curl, key, (int)strlen(key));
    if(keyEscaped == NULL){
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        free(authEncoded);
        authEncoded = NULL;
        M_EXIT(ERR_OUT_OF_MEMORY,"%s","Error in curl easy escape (get ckvs client)");
    }

    char* GET = calloc(strlen(keyUrl) + strlen(authKeyUrl) + strlen(keyEscaped) + encodedCount + 1,sizeof (char));
    if(GET == NULL){
        curl_free(keyEscaped);
        free(authEncoded); authEncoded = NULL;
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY,"%s","Calloc failed in get of client");
    }

    strcat(GET,keyUrl);
    strcat(GET,keyEscaped);
    strcat(GET, authKeyUrl);
    strcat(GET,authEncoded);

    curl_free(keyEscaped);
    free(authEncoded); authEncoded = NULL;
    //contacts the server
    ret_value = ckvs_rpc(&conn, GET);
    free(GET); GET = NULL;
    if(ret_value != ERR_NONE){
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value, "%s", "problem while calling ckvs_rpc (ckvs_client_get)");
    }

    //parses the server's response
    struct json_object* jobjIn = json_tokener_parse(conn.resp_buf);
    if(jobjIn == NULL) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO,"%s","Error in tokener parse get");
    }

    //GETS THE CHILDREN JoBJECT
    //gets jC2
    struct json_object* jc2 = NULL;
    json_object_object_get_ex(jobjIn,"c2",&jc2);
    const char* c2 = json_object_get_string(jc2);
    if(c2 == NULL) {
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of c2 fail");
    }

    //gets jData  
    struct json_object* jdata = NULL;
    json_object_object_get_ex(jobjIn,"data",&jdata);
    const char* data = json_object_get_string(jdata);
    if(data == NULL) {
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_IO,"%s","get of data fail");
    }

    //hexdecodes the c2
    struct ckvs_sha decodedC2 = {{'\0'}};
    ret_value = SHA256_from_string(c2, &decodedC2);
    if(ret_value != SHA256_DIGEST_LENGTH) {
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ret_value, "%s", "SHA from string fails in client get");
    }

    //computes the masterkey
    ret_value = ckvs_client_compute_masterkey(&mr, &decodedC2);
    if(ret_value) {
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ret_value, "%s", "masterkey fails in client get");
    }

    //hexdecodes data
    size_t len = (strlen(data)+1)/2; //changed the by case behavior (even/odd) to single behavior
    unsigned char* dataDecoded = calloc(len + 1, sizeof(unsigned char));
    if(dataDecoded == NULL) {
        ckvs_rpc_close(&conn);
        json_object_put(jobjIn);
        M_EXIT(ERR_OUT_OF_MEMORY,"s","fails to calloc dataEncoded in client get");
    }

    ret_value = hex_decode(data,dataDecoded);
    json_object_put(jobjIn);
    if(ret_value != len) {
        free(dataDecoded); dataDecoded = NULL;
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value, "%s", "hex_decode fails");
    }
 
    //decrypts data
    //initializes the output buffer
    unsigned char* bufferOut = calloc(len + EVP_MAX_BLOCK_LENGTH + 1, sizeof(unsigned char));
    if(bufferOut == NULL) {
        free(dataDecoded); dataDecoded = NULL;
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "could not allocate memory for bufferOut (client (get))");
    }

    size_t out_buff_len = 0;
    //decrypts the value
    ret_value = ckvs_client_crypt_value(&mr, 0, dataDecoded, len,
                                            bufferOut, &out_buff_len);
    free(dataDecoded); dataDecoded = NULL;
    if(ret_value) {
        free(bufferOut); bufferOut = NULL;
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value,"%s","error In client crypt value");
    }
    //outputs the decrypted value
    pps_printf("%s\n", bufferOut);

    //closes the connection
    free(bufferOut);  bufferOut = NULL;
    ckvs_rpc_close(&conn);
    return ERR_NONE;
}

/**
 * @brief handles a call to the set function from the client's perspective
 * 
 * @param url : the url to which we want to connect
 * @param optargc : the number of arguments passed for the set call (should be 3)
 * @param optargv : the arguments passed for the set call
 * @return int : error code
 */
int ckvs_client_set(const char *url, int optargc, char **optargv){

    M_REQUIRE_NON_NULL(url); M_REQUIRE_NON_NULL(optargv);
    if(optargc < 3) { return ERR_NOT_ENOUGH_ARGUMENTS;}
    if(optargc > 3) { return ERR_TOO_MANY_ARGUMENTS;}

    const char *key = optargv[0];
    const char *pwd = optargv[1];
    const char *set_value = optargv[2];
    M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(pwd); M_REQUIRE_NON_NULL(set_value);

    //initializes the memrecord and generates auth_key
    struct ckvs_memrecord mr;
    int ret_value = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(ret_value) {
        return ret_value;
    }

    //generates C2 randomly
    struct ckvs_sha c2 = {{'\0'}};
    if(RAND_bytes(c2.sha, sizeof(c2.sha)) != 1) {
        M_EXIT(ERR_IO, "%s", "RAND_bytes seems not to work properly (ckvs_client_set)");
    }

    //computes the client masterkey with c2
    if((ret_value = ckvs_client_compute_masterkey(&mr, &c2))){
        M_EXIT(ret_value, "%s", "couldn't compute the masterkey correctly (ckvs_client_set)");
    }

    //initiate of the connection
    struct ckvs_connection conn;
    ret_value = ckvs_rpc_init(&conn, url);
    if(ret_value != ERR_NONE){ M_EXIT(ret_value, "%s", "problem while calling ckvs_rpc_init (ckvs_client_set)");}

    //call to server
    const char* nameUrl = "/set?name=data.json";
    const char* offsetUrl = "&offset=0";
    const char* keyUrl = "&key=";
    const char* authKeyUrl = "&auth_key=";

    //hex_encodes the auth_key
    char authKeyEncoded[2*SHA256_DIGEST_LENGTH + 1] = "\0";
    SHA256_to_string(&mr.auth_key, authKeyEncoded);

    //hex_encodes c2
    char hexC2[2*SHA256_DIGEST_LENGTH + 1] = "\0";
    SHA256_to_string(&c2, hexC2);

    //computes the escaped version of the key
    char* keyEscaped = curl_easy_escape(conn.curl, key, CKVS_MAXKEYLEN);
    if(keyEscaped == NULL){
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY,"%s","Error in curl easy escape (get ckvs client)");
    }

    struct json_object* c2DataJson = json_object_new_object();
    if(c2DataJson == NULL){
        curl_free(keyEscaped);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO, "%s", "c2DataJson is null (ckvs_client_set)");
    }

    //adds c2 to the jSon
    ret_value = json_object_object_add(c2DataJson, "c2", json_object_new_string(hexC2));
    if(ret_value < 0) {
        curl_free(keyEscaped);
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO, "%s", "couldn't add c2 to jSon object (ckvs_client_set)");
    }

    //reads data from the file
    char* value_buff = NULL;
    size_t buff_size = 0;
    if((ret_value = read_value_file_content(set_value, &value_buff, &buff_size)) != ERR_NONE) {
        curl_free(keyEscaped);
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value, "%s", "couldn't read the data from the file (ckvs_client_set)");
    }

    //encrypts the data read from the file
    size_t len = strlen(value_buff) + EVP_MAX_BLOCK_LENGTH;
    unsigned char* data_encrypted = calloc(len + 1,sizeof(unsigned char));
    if(data_encrypted == NULL) {
        free(value_buff); value_buff = NULL;
        curl_free(keyEscaped);
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "could not allocate memory for bufferIn (ckvs_client_set)");
    }

    ret_value = ckvs_client_crypt_value(&mr, 1, (const unsigned char*)value_buff,
                                            strlen(value_buff) + 1, data_encrypted,&len);

    free(value_buff); value_buff = NULL;
    if(ret_value) {
        curl_free(keyEscaped);
        free(data_encrypted); data_encrypted = NULL;
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value, "%s", "problem while encrypting the value (ckvs_client_set)");
    }

    //hex_encodes the encrypted data
    char* hex_data_encrypted = calloc(2*len + 1, sizeof(char));
    if(hex_data_encrypted == NULL) {
        curl_free(keyEscaped);
        free(data_encrypted); data_encrypted = NULL;
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "couldn't allocate memory for hexValue (ckvs_client_set)");
    }
    hex_encode((const unsigned char*) data_encrypted, len, hex_data_encrypted);
    if(hex_data_encrypted == NULL){ 
        debug_printf("hex_data_encrypted is null !"); 
        
    }

    free(data_encrypted); data_encrypted = NULL;

    //adds the data to the jSon
    ret_value = json_object_object_add(c2DataJson, "data", json_object_new_string(hex_data_encrypted));
    if(ret_value < 0) {
        curl_free(keyEscaped);
        free(hex_data_encrypted); hex_data_encrypted = NULL;
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO, "%s", "couldn't add value to jSon object (ckvs_client_set)");
    }

    const char* POST = json_object_to_json_string(c2DataJson);

    //Constructing the GET request message
    char* GET = calloc(strlen(nameUrl) + strlen(offsetUrl) + strlen(keyUrl) + strlen(keyEscaped) 
            + strlen(authKeyUrl) + strlen(authKeyEncoded) + 1, sizeof(char));
    if(GET == NULL){
        curl_free(keyEscaped);
        free(hex_data_encrypted); hex_data_encrypted = NULL;
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "couldn't allocate memory for the GET request (ckvs_client_set)");
    }

    strcat(GET, nameUrl); strcat(GET, offsetUrl); strcat(GET, keyUrl); 
    strcat(GET, keyEscaped); strcat(GET, authKeyUrl); strcat(GET, authKeyEncoded);

    ret_value = ckvs_post(&conn, GET, POST);
    if(ret_value != ERR_NONE){
        curl_free(keyEscaped);
        free(GET); GET = NULL;
        free(hex_data_encrypted); hex_data_encrypted = NULL;
        json_object_put(c2DataJson);
        ckvs_rpc_close(&conn);
        M_EXIT(ret_value, "%s", "error in ckvs_post (ckvs_client_set)");
    }

    curl_free(keyEscaped);
    free(GET); GET = NULL;
    free(hex_data_encrypted); hex_data_encrypted = NULL;
    json_object_put(c2DataJson);
    ckvs_rpc_close(&conn);
    return ERR_NONE;
}

/**
 * @brief Performs the 'new' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 2)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_new(const char *url, int optargc, char **optargv){
    return NOT_IMPLEMENTED;
}