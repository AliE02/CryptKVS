/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 * @author E. Bugnion
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>

#include "ckvs_rpc.h"
#include "error.h"
#include "util.h"
#include "ckvs_utils.h"

/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 * It writes the payload inside ckvs_connection.resp_buf.
 * Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*) content received by CURL
 * @param size (size_t) size of an element of of content. Always 1
 * @param nmemb (size_t) number of elements in content
 * @param userp (void*) points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}

/**
 * @brief initiates a connection
 * 
 * @param conn struct ckvs_connection* : entity containing information about the connection
 * @param url the url to which we are connecting
 * @return int : error code
 */
int ckvs_rpc_init(struct ckvs_connection *conn, const char *url)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(url);
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

/**
 * @brief closes a connection
 * 
 * @param conn struct ckvs_connection* : the connection to close
 */
void ckvs_rpc_close(struct ckvs_connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf) {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}

/**
 * @brief creates the url to which we want to connect
 * 
 * @param conn struct ckvs_connection* : entity containing information about the connection
 * @param GET const char* :  the GET field of the url
 * @param url the url that we are creating
 * @return int : error code
 */
static int ckvs_create_url(struct ckvs_connection *conn, const char *GET, char* url){
    //Creating a string (url) that will contain (conn->url | GET)
    url = calloc(strlen(GET) + strlen(conn->url) + 1, sizeof(char));
    if(url == NULL){ M_EXIT(ERR_OUT_OF_MEMORY, "%s", "couldn't allocate memory for url (ckvs_rpc)");}

    strncpy(url, conn->url, strlen(conn->url));
    strcat(url, GET);

    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    free(url); url = NULL;     // no need anymore for url so just free it
    if(ret != CURLE_OK){
        M_EXIT(ERR_OUT_OF_MEMORY, "%s", "curl_easy_setopt failed in (ckvs_rpc)");
    }

    return ERR_NONE;
}

/**
 * @brief sends a request to the server
 * 
 * @param conn struct ckvs_connection* : entity containing information about the connection
 * @param POST const char* : the message we want to send
 * @return CURLcode 
 */
CURLcode send_request(struct ckvs_connection* conn, const char* POST){
    CURLcode ret = 0;
    if(POST != NULL){
        ret = curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, POST);
        if(ret != CURLE_OK) {
            M_EXIT(ret,"%s","easy set opt fails with the POSTFIELDS option");
        }
    }

    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK){
        M_EXIT(ret, "%s", "failure while calling curl_easy_perform");
    }
    return ret;
}

/**
 * @brief creates a url related to conn and sends a request to it
 * 
 * @param conn struct ckvs_connection* : entity containing information about the connection
 * @param GET const char* :  the GET field of the url
 * @return int : error code
 */
int ckvs_rpc(struct ckvs_connection *conn, const char *GET){
    M_REQUIRE_NON_NULL(conn); M_REQUIRE_NON_NULL(GET);
    
    //Creating a string (url) that will contain (conn->url | GET)
    char* url = NULL;
    int ret_value = ckvs_create_url(conn, GET, url);
    if(ret_value){ M_EXIT(ret_value, "%s","cannot create an url, ckvs_rpc");}

    //if worked correctly, content stored in conn->resp_buf
    CURLcode ret = send_request(conn,NULL);
    if(ret != CURLE_OK){
        M_EXIT(ERR_TIMEOUT, "%s", "failure while calling curl_easy_perform (ckvs_rpc)");
    }

    return ERR_NONE;
}

/**
 * @brief Sends an HTTP POST request to the connected server,
 * using its url, and the GET and POST payloads.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param GET (const char*) the GET payload. Should already contain the fields "name" and "offset".
 * @param POST (const char*) the POST payload
 * @return int, error code
 */
int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST){
    M_REQUIRE_NON_NULL(conn); M_REQUIRE_NON_NULL(GET); M_REQUIRE_NON_NULL(POST);

    //Creating a string (url) that will contain (conn->url | GET)
    char* url = NULL;
    int ret_value = ckvs_create_url(conn, GET, url);
    if(ret_value){ M_EXIT(ret_value, "%s","cannot create an url, ckvs_rpc");}

    struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/json");

    //adds the header behavior
    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    if(ret != CURLE_OK) {
        curl_slist_free_all(headers);
        M_EXIT(ret,"%s","easy set opt fails with the HTTP_HEADER option");
    }   
    
    //posts the data
    ret = send_request(conn,POST);
    if(ret != CURLE_OK){
        curl_slist_free_all(headers);
        M_EXIT(ERR_TIMEOUT, "%s", "failure while calling send_request (ckvs_post)");
    }

    //posts an emtpy string to terminate the post operation
    ret = send_request(conn,"");
    if(ret != CURLE_OK){
        curl_slist_free_all(headers);
        M_EXIT(ERR_TIMEOUT, "%s", "failure while calling send_request (ckvs_post)");
    }
    if(conn->resp_buf != NULL && strlen(conn->resp_buf)){
        debug_printf("response buffer : %s", conn->resp_buf);
        pps_printf("%s",conn->resp_buf);
        curl_slist_free_all(headers);
        M_EXIT(ERR_IO,"%s","server answered with error");
    }

    curl_slist_free_all(headers);
    return ERR_NONE;
}




