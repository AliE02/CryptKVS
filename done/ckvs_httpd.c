/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "libmongoose/mongoose.h"
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"
#include "ckvs_crypto.h"


// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404

#define DIR_NAME "tmp"
#define MAX_NAME_LENGTH 20
#define MAX_PATH_LENGTH (MAX_NAME_LENGTH + 4)



/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

/**
 * @brief initializes multiple jsons for the header's elements
 * 
 * @param ckvs_header const struct ckvs_header*: header for which we want to initialize the json
 * @param parent struct json_object* : the json that will contain all json objects of the header
 * @return int 
 */
static int init_header_json(const struct ckvs_header* ckvs_header,struct json_object* parent){
    M_REQUIRE_NON_NULL(ckvs_header); M_REQUIRE_NON_NULL(parent);

    json_object_object_add(parent, "header_string", json_object_new_string(ckvs_header->header_string));
    json_object_object_add(parent, "version", json_object_new_int(ckvs_header->version));
    json_object_object_add(parent, "table_size", json_object_new_int(ckvs_header->table_size));
    json_object_object_add(parent, "threshold_entries", json_object_new_int(ckvs_header->threshold_entries));
    json_object_object_add(parent, "num_entries", json_object_new_int(ckvs_header->num_entries));

    return ERR_NONE;
}

/**
 * @brief creates a json for the key of each ckvs entry
 * 
 * @param ckvs const struct CKVS*
 * @return struct json_object* 
 */
static struct json_object* init_keys_json(const struct CKVS* ckvs){
    struct json_object* keys_json = json_object_new_array();
    if(keys_json == NULL) { return NULL; }

     for(uint32_t i = 0; i < ckvs->header.table_size; ++i){
        if(strlen(ckvs->entries[i].key)) {
            json_object_array_add(keys_json, json_object_new_string(ckvs->entries[i].key));
        }
    }
    
    return keys_json;
}

/**
 * @brief handles the call to stats function
 * 
 * @param nc struct mg_connection* : the connection between server and client
 * @param ckvs struct CKVS* : 
 * @param hm 
 */
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm){

    if(nc == NULL || hm == NULL || ckvs == NULL){ return; }

    //creates the json ckvs object
    struct json_object* ckvs_json = json_object_new_object();
    if(ckvs_json == NULL){ mg_error_msg(nc,ERR_IO); }

    //creates and adds the children ckvs objects
    int err = init_header_json(&ckvs->header,ckvs_json);
    if(err){ 
        mg_error_msg(nc,ERR_IO); 
        json_object_put(ckvs_json);
    }

    struct json_object* keys_json = init_keys_json(ckvs);
    if(keys_json == NULL){ 
        mg_error_msg(nc,ERR_IO); 
        json_object_put(ckvs_json);
    }

    err = json_object_object_add(ckvs_json, "keys", keys_json);
    if(err < 0){ 
        mg_error_msg(nc,ERR_IO); 
        json_object_put(ckvs_json);
    }

    const char* ckvs_json_string = json_object_to_json_string(ckvs_json);
    if(ckvs_json_string == NULL){ 
        mg_error_msg(nc,ERR_IO); 
        json_object_put(ckvs_json);
    }

    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", ckvs_json_string);

    json_object_put(ckvs_json);
}

/**
 * @brief Get the urldecoded argument object
 * 
 * @param hm struct mg_http_message* : the message from which we extract the argument
 * @param arg const char* : the argument we want to extract
 * @return char* 
 */
static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg){
    char buff[1024] = {'\0'};
    int ret = mg_http_get_var(&hm->query, arg, buff, 1024);
    if(ret <= 0){
        debug_printf("mg_http_get_var fails (get_urldecoded_argument)");
        return NULL;
    }
    
    CURL* curl = curl_easy_init();
    int outLen = 0;
    char* key = curl_easy_unescape(curl, buff, 1024, &outLen);
    curl_easy_cleanup(curl);
    if(key == NULL){
        debug_printf("curl_easy_unescape fails in (get_urldecoded_argument)");
    }
    return key;
}

/**
 * @brief static method to modularize the code, does everything necessary when an error has to be thrown by handle_get_call()
 * 
 * @param key string on which we use curl_free
 * @param nc mg_connection to which we pass the error code
 * @param error the error code to be passed to nc
 * @param ckvs_json the json object to be put
 */
static void end_func_call(char** key, struct mg_connection *nc, int error, struct json_object** ckvs_json){
    if(key != NULL){ curl_free(*key); }
    if(nc != NULL){ mg_error_msg(nc, error); }
    if(ckvs_json != NULL){ json_object_put(*ckvs_json); }
    return;
}

/**
 * @brief handles calls to both get and set functions as they have many commmon parts
 * 
 * @param nc : the connection
 * @param ckvs struct CKVS* : the ckvs used in the get/set
 * @param hm message
 * @param do_set int : if 0 then we want to get, else we want to set
 */
static void handle_getset(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm, int do_set){

    //gets, escapes and stores the key
    char* key = get_urldecoded_argument(hm,"key");
    if(key == NULL) {
        return end_func_call(NULL, nc, ERR_INVALID_ARGUMENT, NULL);
    }

    //gets, decodes and stores teh auth_key
    char auth_key[2*SHA256_DIGEST_LENGTH+1] = "\0";
    mg_http_get_var(&(hm->query), "auth_key", auth_key, 2*SHA256_DIGEST_LENGTH + 1);
    //decodes the auth_key 
    ckvs_sha_t auth_key_SHA = {{'\0'}};
    int ret = SHA256_from_string(auth_key,&(auth_key_SHA));
    if(ret == -1) {
        debug_printf("error in the hexdecoding of auth_key (handle_get_call)");
        debug_printf("ret = %d",ret);
        end_func_call(NULL, nc, ERR_IO, NULL);
        return;
    }

    //finds and stores the entry to get/store the data from/in
    ckvs_entry_t* entry = NULL;
    ret = ckvs_find_entry(ckvs,key,&auth_key_SHA,&entry);
    if(ret) {
        debug_printf("ckvs_find_entry fails (handle_get_call)");
        end_func_call(&key, nc, ret, NULL);
        return;
    }
    if(entry->value_len == 0){
        debug_printf("value_len = 0 (handle_get_call)");
        end_func_call(&key, nc, ERR_NO_VALUE, NULL);
        return;
    }

    if(do_set){
        char name[MAX_NAME_LENGTH] = "\0";
        mg_http_get_var(&(hm->query), "name", name, MAX_NAME_LENGTH);

        char fileName[MAX_PATH_LENGTH] = "\0";
        sprintf(fileName, "%s/%s", DIR_NAME, name);

        debug_printf("voici le nom du file : %s", fileName);

        //reads the file <name> in tmp
        FILE* fileReceived = fopen(fileName,"rb");

        if(fileReceived == NULL){
            debug_printf("file couldn't be opened (handle_getset)");
            end_func_call(&key, nc, ERR_IO, NULL);
            return;
        }

        //computes size of file
        ret = fseek(fileReceived,0, SEEK_END);
        if(ret) {
            debug_printf("fseek for setting the cursor at the end of the file fails (handle_getset)");
            fclose(fileReceived);
            end_func_call(&key, nc, ERR_IO, NULL);
            return;
        }
        long size = ftell(fileReceived);
        if (size == -1L) {
            debug_printf("ftell fails (handle_getset)");
            fclose(fileReceived);
            end_func_call(&key, nc, ERR_IO, NULL);
            return;
        }

        //stores the file in dataBuf
        char* dataBuf = calloc((size_t)size + 1, sizeof(char));
        if(dataBuf == NULL){
            debug_printf("couldn't allocate memory for dataBuf (handle_getset)");
            fclose(fileReceived);
            end_func_call(&key, nc, ERR_OUT_OF_MEMORY, NULL);
            return;
        }
        fseek(fileReceived, 0, SEEK_SET);
        if(ret) {
            debug_printf("fseek for setting the cursor to the beginning of the file fails (handle_getset)");
            free(dataBuf); dataBuf = NULL; fclose(fileReceived);         
            fclose(fileReceived);
            end_func_call(&key, nc, ERR_IO, NULL);
            return;
        }
        size_t nbElem = fread(dataBuf, sizeof(char), (size_t) size, fileReceived);
        if(nbElem != (size_t) size) { 
            debug_printf("fread fails while trying to read elements from the file (handle_getset)");
            free(dataBuf); dataBuf = NULL; fclose(fileReceived);
            fclose(fileReceived);
            end_func_call(&key, nc, ERR_IO, NULL);
            return;
        }


         //parses the received string into a json_object
        struct json_object* jobjIn = json_tokener_parse(dataBuf);
        free(dataBuf); dataBuf = NULL;
        fclose(fileReceived);
        if(jobjIn == NULL) {
            debug_printf("couldn't parse the jSon object from the buffer (handle_getset)");
            mg_error_msg(nc, ERR_IO);
            return;
        }

        //GETS THE CHILDREN JoBJECT
        //gets jC2
        struct json_object* jc2 = NULL;
        json_object_object_get_ex(jobjIn,"c2",&jc2);
        const char* c2 = json_object_get_string(jc2);
        if(c2 == NULL) {
            debug_printf("couldn't get c2 from the jSon (handler_getset)");
            end_func_call(&key, nc, ERR_IO, &jobjIn);
            return;
        }

        //hexdecodes the c2
        struct ckvs_sha decodedC2 = {{'\0'}};
        ret = SHA256_from_string(c2, &decodedC2);
        if(ret != SHA256_DIGEST_LENGTH) {
            debug_printf("couldn't decode the c2 (handler_getset)");
            end_func_call(&key, nc, ERR_IO, &jobjIn);
            return;
        }

        //stores the c2 in the entry
        //memcpy(&(entry->c2), &decodedC2, sizeof(decodedC2));
        entry->c2 = decodedC2;

        //gets jData  
        struct json_object* jdata = NULL;
        json_object_object_get_ex(jobjIn,"data",&jdata);
        const char* data = json_object_get_string(jdata);
        if(data == NULL) {
            debug_printf("couldn't get the data from the json (handler_getset)");
            end_func_call(&key, nc, ERR_IO, &jobjIn);
            return;
        }

        //hexdecodes data
        size_t len = (strlen(data)+1)/2; //changed the by case behavior (even/odd) to single behavior
        unsigned char* dataDecoded = calloc(len + 1, sizeof(unsigned char));
        if(dataDecoded == NULL) {
            debug_printf("couldn't allocate memory of dataDecoded (handler_getset)");
            end_func_call(&key, nc, ERR_IO, &jobjIn);
            return;
        }

        ret = hex_decode(data,dataDecoded);
        if(ret != len) {
            debug_printf("couldn't hex_decode the data (handler_getset)");
            end_func_call(&key, nc, ERR_IO, &jobjIn);
            free(dataDecoded); dataDecoded = NULL;
            return;
        }


        ret = ckvs_write_encrypted_value(ckvs,entry,dataDecoded,len);
        json_object_put(jobjIn);
        free(dataDecoded); dataDecoded = NULL;
        if(ret){
            debug_printf("couldn't write entry to disk (handle_set_call)");
            end_func_call(&key, nc, ERR_IO, NULL);
            return;
        }

        mg_http_reply(nc,HTTP_OK_CODE,"", "");
    }
    else{
        //creates the new json object
        struct json_object* ckvs_json = json_object_new_object();
        if(ckvs_json == NULL){ 
            debug_printf("created json is null (handle_get_call)");
            return end_func_call(&key, nc, ERR_IO, &ckvs_json);
        }

        //hex-encodes the c2 and then adds it to the json
        char buf[2*SHA256_DIGEST_LENGTH + 1] = {0}; //small value doesn't need to be dynamically allocated
        SHA256_to_string(&(entry->c2), buf);
        ret = json_object_object_add(ckvs_json, "c2", json_object_new_string(buf));
        if(ret < 0) {
            debug_printf("couldn't add c2 to jSon object (handle_get_call)");
            return end_func_call(&key, nc, ERR_IO, &ckvs_json);
        }

        //---------Reads the encrypted data from the file and hex-encodes it

        //places the read pointer at the address to read
        ret = fseek(ckvs->file, (long)entry->value_off, SEEK_SET);
        if (ret) {
            debug_printf("couldn't place the cursor (handle_get_call)\n");
            return end_func_call(&key, nc, ERR_IO, &ckvs_json);
        }

        //initializes the input buffer to store the encrypted value in
        unsigned char* bufferIn = calloc(entry->value_len + 1, sizeof(unsigned char));
        if(bufferIn == NULL) {
            end_func_call(&key, nc, ERR_IO, &ckvs_json);
            debug_printf("couldn't allocate bufferIn (handle_get_call)\n");
            return;
        }
        //reads encrypted value of the entry and stores it in bufferIn
        size_t nbElem = fread(bufferIn, entry->value_len, 1, ckvs->file);
        if(nbElem != 1) {
            free(bufferIn); bufferIn = NULL;
            end_func_call(&key, nc, ERR_IO, &ckvs_json);
            debug_printf("couldn't read file (handle_get_call)\n");
            return;
        }
        //initializes the buffer to store the hex-encoded value in
        char* bufferEncoded = calloc(2*(entry->value_len) + 2, sizeof(char));
        if(bufferEncoded == NULL) {
            free(bufferIn); bufferIn = NULL;
            end_func_call(&key, nc, ERR_IO, &ckvs_json);
            debug_printf("couldn't allocate memory for bufferEncoded (handle_get_call)\n");
            return;
        }
    
        //enocdes the data from bufferIn and stores it in bufferEncoded
        hex_encode(bufferIn,entry->value_len, bufferEncoded);
        ret = json_object_object_add(ckvs_json, "data", json_object_new_string(bufferEncoded));
        if(ret < 0) {
            free(bufferEncoded); bufferEncoded = NULL;
            free(bufferIn); bufferIn = NULL;
            end_func_call(&key, nc, ERR_IO, &ckvs_json);
            debug_printf("couldn't hexencode the data (handle_get_call)\n");
            return;
        }
        
        const char* ckvs_json_string = json_object_to_json_string(ckvs_json);
        if(ckvs_json_string == NULL){
            free(bufferEncoded); bufferEncoded = NULL; 
            free(bufferIn); bufferIn = NULL;
            end_func_call(&key, nc, ERR_IO, &ckvs_json);
            debug_printf("couldn't convert ckvs_json to json_string (handle_get_call)\n");
            return;
        }

        mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", ckvs_json_string);

        free(bufferEncoded); bufferEncoded = NULL;
        free(bufferIn); bufferIn = NULL;
        curl_free(key);
        json_object_put(ckvs_json);
    }
}

/**
 * @brief handles the call to get function from the server
 * 
 * @param nc struct mg_connection* : the connection between the server and the client
 * @param ckvs struct CKVS* : the ckvs which contains the entry we want
 * @param hm the message
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm){
    handle_getset(nc, ckvs, hm, 0);
    return;
}

/**
 * @brief handles a call to the set function
 * 
 * @param nc struct mg_connection : the connection between the server and the client
 * @param ckvs struct CKVS* : the ckvs which we want to modify
 * @param hm the message
 */
static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm){                          
    if(!hm->body.len) { 
        //does the set operation
        debug_printf("%s","received empty message");
        return handle_getset(nc, ckvs, hm, 1);
    }

    debug_printf("%s","received non-empty message");
    int ret = mg_http_upload(nc,hm,"/tmp");
    if(ret < 0) { mg_error_msg(nc, ERR_IO);}
}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data){
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        // TODO: handle commands calls

        //pattern matched on the URI to call the right command to execute
        if(mg_http_match_uri(hm, "/stats")){
            handle_stats_call(nc,ckvs,hm);
        }
        if(mg_http_match_uri(hm, "/get")){
            handle_get_call(nc,ckvs,hm);
        }

        if(mg_http_match_uri(hm, "/set")){
            handle_set_call(nc,ckvs,hm);
        }

        mg_error_msg(nc, NOT_IMPLEMENTED);   
        
        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c==NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}
