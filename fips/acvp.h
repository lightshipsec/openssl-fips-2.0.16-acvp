#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"

#include <cjson/cJSON.h>

/* Assumes caller has `error_die' guards set up.
 * If error is NULL, then we ignore the error.
 */
#define SAFEGET(call, error, ...)   \
    if(call != 0) { \
        if(error)  { \
            printf(error, ## __VA_ARGS__); \
            goto error_die; \
        } \
    }

#define SAFEPUT(call, error, ...)   \
    if(call != 0) { \
        if(error)  { \
            printf(error, ## __VA_ARGS__); \
            goto error_die; \
        } \
    }


static int cavs = 0;
static int acvp = 0;

/* Initializer */
int select_mode(void)  {
    if (getenv("ACVP"))
        acvp = 1;
    if (getenv("CAVS"))
        cavs = 1;
    /* Set default if neither is set */
    if(!acvp && !cavs)
        cavs = 1;
    return 0;
}

/* Utility functions */

int get_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_array_item(cJSON **to, const cJSON *from, int index) {
    if(!from || !to || index<0) return -1;
    cJSON *t = cJSON_GetArrayItem((cJSON *)from, index);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_string_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_integer_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_boolean_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}

/* Appends; else use cJSON_InsertItemInArray to insert */
int put_array_item(cJSON *obj, cJSON *to_arr)  {
    if(!to_arr || !obj) return -1;
    /* Get array size before adding */
    //int before = cJSON_GetArraySize(to_arr);
    cJSON_AddItemToArray(to_arr, obj);
    //int after = cJSON_GetArraySize(to_arr);
    //if (after != (before + 1)) return -1;
    return 0;
}
/* Any object */
int put_object(char *name, cJSON *obj, cJSON *to)  {
    if(!to || !obj || !name) return -1;
    cJSON_AddItemToObject(to, name, obj);
    return 0;
}

/* Specific objects */
int put_string(const char *name, const unsigned char *value, cJSON *to) { 
    if(!to || !name) return -1;
    cJSON *s = cJSON_CreateString((const char *)value);
    if(!s) return -1;
    int before = 0, after = 0;
    if (cJSON_IsArray(to))
        before = cJSON_GetArraySize(to);

    cJSON_AddItemToObject(to, name, s);
    /* Unfortunately, the current cJSON API does not check if the addition was successful.
     * Therefore, we check if the object is in there after adding.
     */
    cJSON *verify = NULL;
    if (cJSON_IsObject(to))  {
        int err = get_string_object(&verify, (const cJSON *)to, (char *)name); 
        if (err < 0 || !verify) return -1;
    } else if (cJSON_IsArray(to))  {
        after = cJSON_GetArraySize(to);
        if (after != (before + 1)) return -1;
        verify = cJSON_GetArrayItem(to, after-1);
    }
    if (strncmp((const char *)value, verify->valuestring, strlen((const char *)value)) != 0) return -1;
    return 0;
}
int put_integer(const char *name, int value, cJSON *to) {
    if(!to || !name) return -1;
    cJSON *s = cJSON_CreateNumber(value);
    if(!s) return -1;
    int before = 0, after = 0;
    if (cJSON_IsArray(to))
        before = cJSON_GetArraySize(to);

    cJSON_AddItemToObject(to, name, s);
    /* Unfortunately, the current cJSON API does not check if the addition was successful.
     * Therefore, we check if the object is in there after adding.
     */
    cJSON *verify = NULL;
    if (cJSON_IsObject(to))  {
        int err = get_integer_object(&verify, (const cJSON *)to, (char *)name); 
        if (err < 0 || !verify) return -1;
    } else if (cJSON_IsArray(to))  {
        after = cJSON_GetArraySize(to);
        if (after != (before + 1)) return -1;
        verify = cJSON_GetArrayItem(to, after-1);
    }
    if (value != verify->valueint) return -1;
    return 0;
}


int verify_acvp_version(cJSON *json, const char *check)  {
    /* Data is parsed already; now we need to extract everything to give to the caller. */
    /* Validate that the structure is sound and conforms with the expected structure format. */
    if (cJSON_GetArraySize(json) != 2)  {
        printf("Expecting array of size 2 in top-level JSON. Check input format.\n");
        goto error_die;
    }

    /* Check version is correct */
    cJSON *a0 = NULL;
    SAFEGET(get_array_item(&a0, json, 0), "JSON not structured properly\n");

    cJSON *versionStr = NULL;
    SAFEGET(get_string_object(&versionStr, a0, "acvVersion"), "Version identifier is missing\n");
    return strncmp(check, versionStr->valuestring, 3) == 0;

error_die:
    return -1;
}

cJSON *init_output(cJSON *json)  {
    /* Take in the initial structure and copy the necessary pieces out */
    cJSON *output = cJSON_CreateArray();

    /* Data is parsed already; now we need to extract everything to give to the caller. */
    /* Validate that the structure is sound and conforms with the expected structure format. */
    if (cJSON_GetArraySize(json) != 2)  {
        printf("Expecting array of size 2 in top-level JSON. Check input format.\n");
        goto error_die;
    }

    /* Check version is correct */
    cJSON *a0 = NULL;
    SAFEGET(get_array_item(&a0, json, 0), "JSON not structured properly\n");

    cJSON *versionStr = NULL;
    SAFEGET(get_string_object(&versionStr, a0, "acvVersion"), "Version identifier is missing\n");

    cJSON *out_versionObj = cJSON_CreateObject();
    SAFEPUT(put_string("acvVersion", (const unsigned char *)versionStr->valuestring, out_versionObj), "Unable to add version string");

    if (!output) return NULL;
    SAFEPUT(put_array_item(out_versionObj, output), "Unable to add version string to output structure");

    goto success;

error_die:
    if (output) cJSON_Delete(output); output = NULL;

success:
    return output;
}


/**
 * Read a file into a memory buffer
 */
char *read_fd_as_string(FILE *fd, char **buf)  {
    if (!fd || !buf) return NULL;

    int length = 0;

    /* Read entire file into memory, dynamically resizing the memory buffer */
    if (fd)  {
        fseek (fd, 0, SEEK_END);
        length = ftell (fd);
        fseek (fd, 0, SEEK_SET);
        *buf = malloc (length);
        if (*buf)
            fread (*buf, 1, length, fd);
        else
            return NULL;
    }
    else
        return NULL;

    return *buf;
}

char *read_file_as_string(char *fn, char **buf)  {
    if (!fn || !buf) return NULL;
    FILE *fd = fopen (fn, "rt");
    read_fd_as_string(fd, buf);
    fclose (fd);
    fd = NULL;
    return *buf;
}

/**
 * Read a file as a JSON object.
 */
cJSON *read_fd_as_json(FILE *fd)  {
    if (!fd) return NULL;

    char *buf = NULL;
    cJSON *c = NULL;

    if (!read_fd_as_string(fd, &buf))  {
        perror("Unable to load JSON file to memory structure.");
        goto error_die;
    }

    c = cJSON_Parse(buf);
    if(!c)  {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)  {
            fprintf(stderr, "JSON parsing error before: %s\n", error_ptr);
        }
        goto error_die;
    }
    goto success;

error_die:
    if (c) cJSON_Delete(c);
    c = NULL;

success:
    if (buf) free(buf);
    buf = NULL;

    return c;
}


cJSON *read_file_as_json(char *fn)  {
    if (!fn) return NULL;
    FILE *fd = fopen (fn, "rt");
    cJSON *json = read_fd_as_json(fd);
    fclose (fd);
    fd = NULL;
    return json;
}

unsigned char *bin2hex(unsigned char *bin, int bin_len, unsigned char *hex, int hex_len)  {
    if (!hex || (bin_len*2+1 > hex_len)) return NULL;
    for(int i=0, j=0; i < bin_len; i++, j+=2)
       sprintf((char *)&hex[j], "%02X", bin[i]);
    hex[bin_len*2] = '\x0';
    return hex;
}

unsigned char *bin2hex_m(unsigned char *bin, int bin_len, unsigned char **hex)  {
    if (!hex) return NULL;
    unsigned char *hex_r = *hex;
    hex_r = malloc(bin_len*2+1);
    *hex = bin2hex(bin, bin_len, hex_r, bin_len*2+1);
    return hex_r;
}


#pragma GCC diagnostic pop
