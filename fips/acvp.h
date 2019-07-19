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

/* Utility functions */

int get_object(cJSON **to, const cJSON *from, char *name) {
    cJSON *t = cJSON_GetObjectItemCaseSensitive(from, name);
    if(!t || !to) return -1;
    *to = t;
    return 0;
}
int get_array_item(cJSON **to, const cJSON *from, int index) {
    cJSON *t = cJSON_GetArrayItem(from, index);
    if(!t || !to) return -1;
    *to = t;
    return 0;
}
int get_string_object(cJSON **to, const cJSON *from, char *name) {
    cJSON *t = cJSON_GetObjectItemCaseSensitive(from, name);
    if(!t || !to) return -1;
    *to = t;
    return 0;
}
int get_integer_object(cJSON **to, const cJSON *from, char *name) {
    cJSON *t = cJSON_GetObjectItemCaseSensitive(from, name);
    if(!t || !to) return -1;
    *to = t;
    return 0;
}

/**
 * Read a file into a memory buffer
 */
char *read_file_as_string(char *fn, char **buf)  {
    if (!fn || !buf) return NULL;

    int length = 0;
    FILE *f = fopen (fn, "rt");

    /* Read entire file into memory, dynamically resizing the memory buffer */
    if (f)  {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        *buf = malloc (length);
        if (*buf)
            fread (*buf, 1, length, f);
        else
            return NULL;
        fclose (f);
        f = NULL;
    }
    else
        return NULL;

    return *buf;
}


/**
 * Read a file as a JSON object.
 */
cJSON *read_file_as_json(char *fn)  {
    if (!fn) return NULL;

    char *buf = NULL;
    cJSON *c = NULL;

    if (!read_file_as_string(fn, &buf))  {
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
