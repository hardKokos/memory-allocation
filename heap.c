#include "heap.h"
#include "tested_declarations.h"
#include "rdebug.h"
#include <string.h>
#include <stdio.h>
#include "tested_declarations.h"
#include "rdebug.h"

#define FENCE 4
#define CONTROL_STRUCT_SIZE sizeof(struct memory_chunk_t)
#define CHECKSUM_SIZE 11
#define MAX_ALLOWED_SIZE 65057756
#define CONTROL_AND_FENCE_SIZE (CONTROL_STRUCT_SIZE + FENCE)
#define HEAP_NOT_INITIALIZED 2
#define HEAP_CONTROL_SUM_MISMATCH 3
#define HEAP_FENCE_CORRUPTED 1
#define HEAP_VALID 0
#define TOTAL_SIZE(size) (CONTROL_STRUCT_SIZE + FENCE * 2 + size)
#define FILL_FENCES(size, chunk) \
    do { \
        char *ptr = (char *)chunk + CONTROL_STRUCT_SIZE; \
        for (size_t i = 0; i < FENCE; ++i) \
            ptr[i] = ptr[i + FENCE + size] = 0; \
    } while (0)

int check_sum(struct memory_chunk_t *chunk);
void update_control_sum();
struct memory_chunk_t *initialize_memory_chunk(size_t size);

struct memory_manager_t memMgr;

int check_sum(struct memory_chunk_t *chunk) {
    int res = 0;
    for (int i = 0; i < CHECKSUM_SIZE; ++i)
        res += *((int *) ((char *) chunk + i * sizeof(int)));
    return res;
}

void update_control_sum() {
    struct memory_chunk_t *chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    while (chunk) {
        chunk->control_sum = check_sum(chunk);
        chunk = chunk->next;
    }
}

struct memory_chunk_t *initialize_memory_chunk(size_t size) {
    struct memory_chunk_t *chunk = (struct memory_chunk_t *) custom_sbrk(
            (intptr_t) (CONTROL_STRUCT_SIZE + FENCE * 2 + size));
    if (chunk == (void *) -1)
        return NULL;

    *chunk = (struct memory_chunk_t) {
            .prev = NULL,
            .next = NULL,
            .size = size,
            .free = 1,
            .prev_size = size,
            .times_allocated = 1
    };

    FILL_FENCES(size, chunk);

    return chunk;
}

int heap_setup(void) {
    void *heap_end = custom_sbrk(0);
    if (heap_end == (void *) -1) return -1;

    memMgr = (struct memory_manager_t) {
        .memory_start = heap_end,
        .memory_size = 0,
        .first_memory_chunk = NULL
    };

    return 0;
}

void heap_clean(void) {
    custom_sbrk(-1 * (intptr_t) memMgr.memory_size);
    memMgr.memory_start = NULL;
    memMgr.memory_size = 0;
    memMgr.first_memory_chunk = NULL;
}

int heap_validate(void) {
    // Check if the heap is not initialized
    if (memMgr.memory_start == NULL)
        return HEAP_NOT_INITIALIZED;
    struct memory_chunk_t *current_chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    while (current_chunk) {
        int sum = check_sum(current_chunk);
        if (current_chunk->control_sum != sum)
            return HEAP_CONTROL_SUM_MISMATCH;
        char *ptr1 = (char *) current_chunk + CONTROL_STRUCT_SIZE;
        for (size_t i = 0; i < FENCE; ++i)
            if (*(ptr1 + i) != 0 && current_chunk->free == 1)
                return HEAP_FENCE_CORRUPTED;
        char *ptr2 = (char *) current_chunk + CONTROL_AND_FENCE_SIZE + current_chunk->size;
        for (size_t i = 0; i < FENCE; ++i)
            if (*(ptr2 + i) != 0 && current_chunk->free == 1)
                return HEAP_FENCE_CORRUPTED;
        current_chunk = current_chunk->next;
    }

    return HEAP_VALID;
}


void *heap_malloc(size_t size) {
    if (size <= 0 || !memMgr.memory_start || size > MAX_ALLOWED_SIZE) {
        return NULL;
    }

    if (!memMgr.first_memory_chunk) {

        struct memory_chunk_t *new_chunk = initialize_memory_chunk(size);
        if (!new_chunk) {
            return NULL;
        }

        // Update memory manager information
        memMgr.first_memory_chunk = new_chunk;
        memMgr.memory_size += TOTAL_SIZE(size);
        new_chunk->control_sum = check_sum(memMgr.first_memory_chunk);

        // Return the user-accessible address
        return (void *) ((char *) new_chunk + CONTROL_AND_FENCE_SIZE);
    }

    // Check if heap is corrupted
    if (heap_validate())
        return NULL;

    // Go through whole heap and find free memory chunk
    struct memory_chunk_t *current_chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    while (current_chunk) {
        // Find free memory chunk that can fit the requested size
        if (current_chunk->free == 0 && (intptr_t) current_chunk->size >= (intptr_t) size) {
            current_chunk->times_allocated += 1;
            current_chunk->prev_size = current_chunk->size;
            current_chunk->size = size;
            current_chunk->free = 1;
            FILL_FENCES(size, current_chunk);
            current_chunk->control_sum = check_sum(current_chunk);
            return (void *) ((char *) current_chunk + CONTROL_AND_FENCE_SIZE);
        }

        if (!current_chunk->next)
            break;

        current_chunk = current_chunk->next;
    }

    struct memory_chunk_t *new_chunk = (struct memory_chunk_t *) custom_sbrk((intptr_t) TOTAL_SIZE(size));
    if (new_chunk == (void *) -1)
        return NULL;

    new_chunk->size = size;
    new_chunk->next = NULL;
    new_chunk->prev = current_chunk;
    new_chunk->free = 1;
    new_chunk->times_allocated = 1;
    new_chunk->prev_size = size;
    current_chunk->next = new_chunk;
    memMgr.memory_size += TOTAL_SIZE(size);
    FILL_FENCES(size, new_chunk);
    current_chunk->next->control_sum = check_sum(current_chunk->next);
    current_chunk->control_sum = check_sum(current_chunk);
    return (void *) ((char *) new_chunk + CONTROL_AND_FENCE_SIZE);
}

void *heap_calloc(size_t number, size_t size) {
    if (number <= 0 || size <= 0)
        return NULL;

    // Calculate the total size required
    size_t total_size = number * size;

    // Use heap_malloc to allocate memory
    void *allocated_memory = heap_malloc(total_size);
    if (allocated_memory == NULL)
        return NULL;
    else {
        char *ptr = (char *) allocated_memory;
        for (size_t i = 0; i < total_size; ++i)
            *(ptr + i) = 0;

    }
    return allocated_memory;
}


void *heap_realloc(void *memblock, size_t count) {
    if (count <= 0) {
        heap_free(memblock);
        return NULL;
    }
    if (!memblock) {
        char *ptr = heap_malloc(count);
        if (!ptr)
            return NULL;
        return ptr;
    }
    struct memory_chunk_t *current_chunk = (void *) ((char *) memblock - CONTROL_STRUCT_SIZE - FENCE);
    struct memory_chunk_t *first_chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    while (first_chunk) {
        if (first_chunk == current_chunk)
            break;
        first_chunk = first_chunk->next;
    }
    if (!first_chunk)
        return NULL;
    current_chunk = (void *) ((char *) memblock - CONTROL_STRUCT_SIZE - FENCE);
    if (current_chunk->size == count)
        return memblock;
    if (current_chunk->size > count) {
        current_chunk->size = count;
        FILL_FENCES(count, current_chunk);
        update_control_sum();
        return memblock;
    }
    struct memory_chunk_t *next_chunk = current_chunk->next;
    if (!next_chunk) {
        struct memory_chunk_t *new_chunk = (struct memory_chunk_t *) custom_sbrk(
                (intptr_t) (count - current_chunk->size));
        if (new_chunk == (void *) -1)
            return NULL;
        memcpy((char *) current_chunk + CONTROL_AND_FENCE_SIZE + current_chunk->size, (char *) new_chunk,
               count - current_chunk->size);
        memMgr.memory_size += count - current_chunk->size;
        current_chunk->size = count;
        FILL_FENCES(count, current_chunk);
    } else {
        if (((char *) next_chunk + CONTROL_STRUCT_SIZE + next_chunk->size + FENCE * 2 - (char *) current_chunk) -
            CONTROL_STRUCT_SIZE - FENCE * 2 >= count) {
            current_chunk->prev_size = current_chunk->size;
            current_chunk->size = count;
            current_chunk->next = next_chunk->next;
            next_chunk->prev = current_chunk;
            FILL_FENCES(count, current_chunk);
        } else {
            void *ptr = heap_malloc(count);
            if (!ptr)
                return NULL;
            memcpy((char *) ptr, (char *) current_chunk + CONTROL_AND_FENCE_SIZE, current_chunk->size);
            heap_free((char *) current_chunk + CONTROL_AND_FENCE_SIZE);
            return ptr;
        }
    }
    update_control_sum();
    return memblock;
}

void heap_free(void *memblock) {
    if (!memblock || get_pointer_type(memblock) != pointer_valid)
        return;
    struct memory_chunk_t *chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    struct memory_chunk_t *chunk_to_free = (void *) ((char *) memblock - CONTROL_STRUCT_SIZE - FENCE);
    while (chunk != chunk_to_free)
        chunk = chunk->next;

    struct memory_chunk_t *prev = chunk->prev;
    struct memory_chunk_t *next = chunk->next;
    struct memory_chunk_t *last_chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    while (last_chunk->next)
        last_chunk = last_chunk->next;

    chunk->free = 0;
    chunk->size = chunk->prev_size;

    //Przypadki na krańcach pamięci
    if ((next == NULL && prev == NULL) || (chunk == memMgr.first_memory_chunk && next->free == 1)) {
        if (chunk->times_allocated > 1)
            chunk->size = chunk->prev_size;
        update_control_sum();
        return;
    }
    // NULL |x| wolny
    if (prev == NULL && next->free == 0) {
        chunk->size += next->size + CONTROL_STRUCT_SIZE + FENCE * 2;
        chunk->next = next->next;
        struct memory_chunk_t *next_next = next->next;
        if (next_next)
            next_next->prev = chunk;
        else
            chunk->next = NULL;
        update_control_sum();
        return;
    }
    // wolny |x| NULL
    if (prev->free == 0 && next == NULL) {
        prev->size += chunk->size + CONTROL_STRUCT_SIZE + FENCE * 2;
        prev->next = NULL;
        update_control_sum();
        return;
    }

    // Przypadki w środku pamięci
    // wolny |x| blok
    if (prev->free == 0 && next->free == 1) {
        prev->size += chunk->size + CONTROL_STRUCT_SIZE + FENCE * 2;
        prev->next = next;
        next->prev = prev;
    }
        // blok |x| wolny
    else if (prev->free == 1 && next != NULL && next->free == 0) {
        chunk->size += next->size + CONTROL_STRUCT_SIZE + FENCE * 2;
        if (next->next) {
            chunk->next = next->next;
            struct memory_chunk_t *next_next = next->next;
            next_next->prev = chunk;
        } else
            chunk->next = NULL;
    }
        // wolny |x| wolny
    else if (prev->free == 0 && next->free == 0) {
        prev->size += chunk->size + next->size + CONTROL_STRUCT_SIZE + FENCE * 2;
        if (next->next) {
            prev->next = next->next;
            struct memory_chunk_t *next_next = next->next;
            next_next->prev = prev;
        } else
            prev->next = NULL;
    }

    update_control_sum();
}

size_t heap_get_largest_used_block_size(void) {
    if (!memMgr.memory_start || !memMgr.first_memory_chunk || heap_validate()) {
        return 0;
    }
    struct memory_chunk_t *current_chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    size_t largest_size = 0;
    while (current_chunk) {
        if ((intptr_t) current_chunk->size > (intptr_t) largest_size && current_chunk->free == 1) {
            largest_size = current_chunk->size;
        }
        current_chunk = current_chunk->next;
    }
    return largest_size;
}

enum pointer_type_t get_pointer_type(const void *const pointer) {
    if (!pointer || !memMgr.memory_start || !memMgr.first_memory_chunk)
        return pointer_null;
    if (heap_validate())
        return pointer_heap_corrupted;
    struct memory_chunk_t *current_chunk = (struct memory_chunk_t *) memMgr.first_memory_chunk;
    while (current_chunk) {
        if (current_chunk->free == 1) {
            if (pointer >= (void *) (char *) current_chunk &&
                pointer < (void *) ((char *) current_chunk + CONTROL_STRUCT_SIZE))
                return pointer_control_block;
            if ((pointer >= (void *) ((char *) current_chunk + CONTROL_STRUCT_SIZE) &&
                 pointer < (void *) ((char *) current_chunk + CONTROL_AND_FENCE_SIZE)))
                return pointer_inside_fences;
            if ((pointer >= (void *) ((char *) current_chunk + CONTROL_AND_FENCE_SIZE + current_chunk->size) &&
                 pointer < (void *) ((char *) current_chunk + CONTROL_STRUCT_SIZE + FENCE * 2 + current_chunk->size)))
                return pointer_inside_fences;
            if (pointer > (void *) ((char *) current_chunk + CONTROL_AND_FENCE_SIZE) &&
                pointer < (void *) ((char *) current_chunk + CONTROL_AND_FENCE_SIZE + current_chunk->size))
                return pointer_inside_data_block;
            if (pointer == (void *) ((char *) current_chunk + CONTROL_AND_FENCE_SIZE))
                return pointer_valid;
        }
        if (!current_chunk->next)
            break;
        current_chunk = current_chunk->next;
    }
    return pointer_unallocated;
}
