#include <stddef.h>

/* Placeholder for embedded malloc/free interception. */

void *hook_malloc(size_t size) {
    // TODO: implement platform specific allocation hook
    return NULL;
}

void hook_free(void *ptr) {
    // TODO: implement platform specific free hook
}
