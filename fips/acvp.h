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

/* Initializer */
int select_mode(int *cavs, int *acvp)  {
    if(!cavs && !acvp) return -1;
    if (getenv("ACVP"))
        *acvp = 1;
    if (getenv("CAVS"))
        *cavs = 1;
    /* Set default if neither is set */
    if(!*acvp && !*cavs)
        *cavs = 1;
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
    const cJSON *a0 = NULL;
    SAFEGET(get_array_item(&a0, json, 0), "JSON not structured properly\n");

    const cJSON *versionStr = NULL;
    SAFEGET(get_string_object(&versionStr, a0, "acvVersion"), "Version identifier is missing\n");
    return strncmp(check, versionStr->valuestring, 3) == 0;

error_die:
    return -1;
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
