#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ckvs_io.h"
#include "error.h"
#include "ckvs.h"
#include "ckvs_crypto.h"

/**
 * @brief return wether it is a power of two or not
 * @param size
 * @return double: 0.0 if it s a power of two, any other value otherwise
 */
double powerOfTwo(uint32_t size){
    return (log(size) - floor(size));
}

/**
 * @brief proceeds to closing the file of a ckvs struct 
 * 
 * @param ckvs (struct CKVS*) the ckvs whose file is to close
 */
void ckvs_close(struct CKVS *ckvs){
    if(ckvs != NULL && ckvs->file != NULL){
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
}

/**
 * @brief proceeds to opening a ckvs using from filename and points to it using the parameter "ckvs"
 * 
 * @param filename (const* char) is the filename of the file from which we read the ckvs
 * @param ckvs (struct CKVS*) is the pointer which will point to the newly created ckvs
 * @return int : ERR_NONE           if no error
 *               ERR_IO             if problem with file opening or file reading
 *               ERR_CORRUPT_STORE  if the database is not of the correct format
 */
int ckvs_open(const char* filename, struct CKVS* ckvs){
    M_REQUIRE_NON_NULL(filename); M_REQUIRE_NON_NULL(ckvs);
    ckvs_header_t header = {{'\0'}, 0, 0, 0, 0};
    memset(&ckvs->entries, 0, CKVS_FIXEDSIZE_TABLE * sizeof(struct ckvs_entry));

    //opens the file ckvs file
    ckvs->file = NULL;
    ckvs->file = fopen(filename, "rb+");
    if(ckvs->file == NULL){
        M_EXIT(ERR_IO, "%s", "couldn't open the file (ckvs_open)");
	}

    //reads the ckvs header
    size_t nb_elem = fread(&header, sizeof(ckvs_header_t), 1, ckvs->file);
    if (nb_elem != 1) {
        ckvs_close(ckvs);
        M_EXIT(ERR_IO, "%s", "couldn't read the header of ckvs (ckvs_open)");
    }

    //verifies if the header is in the good expected format
    char expected[14] = CKVS_HEADERSTRING_PREFIX;
    if (strncmp(expected, header.header_string, 14) != 0 || (header.version != 1)
        || (powerOfTwo(header.table_size) > 0.0)) {
            ckvs_close(ckvs);
            M_EXIT(ERR_CORRUPT_STORE, "%s", "didn't get the header (ckvs_open)");
    }

    if (header.table_size != CKVS_FIXEDSIZE_TABLE) {
        ckvs_close(ckvs);
        M_EXIT(ERR_CORRUPT_STORE, "%s", "the table size is not equal to fixedSize");
    }

    //assigns the header tot he ckvs once the checks succeed
    ckvs->header = header;

    //reads the entries of the ckvs and stores them in the ckvs object
    nb_elem = fread(ckvs->entries,sizeof(ckvs_entry_t),ckvs->header.table_size,ckvs->file);
    if (nb_elem != ckvs->header.table_size) {
        ckvs_close(ckvs);
        M_EXIT(ERR_IO, "%s", "couldn't read the entries of ckvs (ckvs_open)");
    }
    return ERR_NONE;
}

/**
 * @brief Finds the entry with the given (key, auth_key) pair in the ckvs database.
 *
 * @param ckvs      (struct CKVS*) the ckvs database to search
 * @param key       (const char*) the key of the entry
 * @param auth_key  (const struct ckvs_sha*) the auth_key of the entry
 * @param e_out     (struct ckvs_entry**) points to a pointer to an entry. Used to store the pointer to the entry if found.
 * @return int, error code
 */
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    M_REQUIRE_NON_NULL(ckvs); M_REQUIRE_NON_NULL(key); M_REQUIRE_NON_NULL(auth_key); M_REQUIRE_NON_NULL(e_out);

    //linearly searches for the key
    size_t i = 0;
    while(i < ckvs->header.table_size && strncmp(key,ckvs->entries[i].key, CKVS_MAXKEYLEN) != 0){ i += 1;}

    //checks if the key was found in the table
    if(i >= ckvs->header.table_size) {
        return ERR_KEY_NOT_FOUND;
    }
    //checks if the auth_key match
    if(ckvs_cmp_sha(auth_key,&ckvs->entries[i].auth_key) != 0) {
        return ERR_DUPLICATE_ID;
    }

    //assigns the found entry to the e_out pointer
    *e_out = &ckvs->entries[i];
    return ERR_NONE;
}

/**
 * @brief Reads the file at filename, then allocates a buffer to dumps the file content into.
 * 
 * @param filename      (const char*) name of the file from which we are reading
 * @param buffer_ptr    (char**) buffer that will point to the read content
 * @param buffer_size   (size_t*) final size of the buffer
 * @return int 
 */
int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){
    M_REQUIRE_NON_NULL(filename);

    //opens the file
    FILE* fileEntry = NULL;
    fileEntry = fopen(filename, "rb");
    if (fileEntry == NULL){
        M_EXIT(ERR_IO,"%s","couldn't open the file in read_value_file_from_content");
    }

    //gets the size of the file using fseek and ftell, and sets the corresponding pointer
    long int posEnd = 0;
    if(!fseek(fileEntry,0,SEEK_END)){
        posEnd = ftell(fileEntry);
        if(posEnd == -1L) {
            fclose(fileEntry);
            M_EXIT(ERR_IO,"%s","call to ftell fails (couldn't assign size correctly");
        }
        *buffer_size = (size_t) posEnd;
    } else {
        fclose(fileEntry);
        M_EXIT(ERR_IO,"%s","couldn't set fseek to end correctly");
    }

    //sets the file pointer back to the beginning of the file
    if(!fseek(fileEntry,0,SEEK_SET)) {
        //allocates enough space for the content to read, returns ERR_OUT_OF_MEMORY in case of error
        *buffer_ptr = calloc(*buffer_size + 1,sizeof(char));
        if(*buffer_ptr == NULL){
            fclose(fileEntry);
            M_EXIT(ERR_OUT_OF_MEMORY, "%s", "could'nt allocate space for buffer_ptr (read_value_file_content)");
        }

        //reads the value to set from the file and stores it in the buffer
        size_t nbElem = fread(*buffer_ptr, sizeof(char), *buffer_size, fileEntry);
        if(nbElem != *buffer_size) {
            fclose(fileEntry);
            M_EXIT(ERR_IO,"%s","couldn't read the correct number");
        }
        //null-terminates the buffer
        (*buffer_ptr)[*buffer_size] = '\0';

        fclose(fileEntry);
        return ERR_NONE;
    } else {
        fclose(fileEntry);
        M_EXIT(ERR_IO,"%s","couldn't set fseek to beginning correctly");
    }
}

/**
 * @brief rewrites in the file of ckvs, the value at index idx in ckvs entries
 * 
 * @param ckvs (struct CKVS*) pointer to the given ckvs
 * @param idx  (uint32_t) index of the value in ckvs entries
 * @return int 
 */
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx){
    //sets the file cursor to the entry's index we need to write in
    if(fseek(ckvs->file, (long)(idx*sizeof(ckvs_entry_t) + sizeof(ckvs_header_t)) ,SEEK_SET)){
        M_EXIT(ERR_IO, "%s", "fseek couldn't find the cursor (ckvs_write_entry_to_disk)");
    }
    //once the cursor is set, writes to the file the value of the idx's entry of the ckvs
    if(!fwrite(&ckvs->entries[idx], sizeof(ckvs_entry_t), 1, ckvs->file)){
        M_EXIT(ERR_IO, "%s", "couldn't write to file (ckvs_write_entry_to_disk)");
    }
    fflush(ckvs->file);
    return ERR_NONE;
}

/**
 * @brief writes encrypted value in the file of the ckvs struct while updating values of the ckvs_entry
 * 
 * @param ckvs (struct CKVS*) whose file is to change
 * @param e (struct cvks_entry*) the entry whose value is the encrypted one
 * @param buf (const unsigned char*) the encrypted value
 * @param buflen (uint64_t) length of the encrypted value
 * @return int 
 */
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen){
    M_REQUIRE_NON_NULL(ckvs); M_REQUIRE_NON_NULL(e); M_REQUIRE_NON_NULL(buf);

    //sets the cursor to the end of the file to get the new offset of the entry
    fseek(ckvs->file, 0, SEEK_END);
    long cursor = ftell(ckvs->file);
    if(cursor == -1L) {
        M_EXIT(ERR_IO,"%s","ftell returns an error in write_encrypted");
    }
    //sets the entry with its new offset and length
    e->value_off = (uint64_t) cursor;
    e->value_len = buflen;

    //writes the new set entry to the end of the file (where we placed the cursor)
    fwrite(buf, buflen, 1, ckvs->file);
    ckvs_write_entry_to_disk(ckvs, e - ckvs->entries);

    return ERR_NONE;
}