#include "asbestos/asbestos.h"
#include "util/list.h"
#include "util/sync.h"

/* Minimal asbestos stubs for AArch64 guest: memory invalidation hooks only. */

struct asbestos *asbestos_new(struct mmu *mmu) {
    struct asbestos *asbestos = calloc(1, sizeof(struct asbestos));
    asbestos->mmu = mmu;
    lock_init(&asbestos->lock);
    wrlock_init(&asbestos->jetsam_lock);
    list_init(&asbestos->jetsam);
    return asbestos;
}

void asbestos_free(struct asbestos *asbestos) {
    free(asbestos);
}

void asbestos_invalidate_range(struct asbestos *asbestos, page_t start, page_t end) {
    (void) asbestos; (void) start; (void) end;
}

void asbestos_invalidate_page(struct asbestos *asbestos, page_t page) {
    (void) asbestos; (void) page;
}

void asbestos_invalidate_all(struct asbestos *asbestos) {
    (void) asbestos;
}
