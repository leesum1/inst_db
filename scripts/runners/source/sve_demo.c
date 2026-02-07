#include <arm_sve.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    size_t vl = svcntw();
    int *buf = (int *)malloc(vl * sizeof(int));
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    svbool_t pg = svptrue_b32();
    svint32_t base = svindex_s32(1, 1);
    svint32_t vec = svadd_s32_x(pg, base, svdup_s32(10));

    svst1_s32(pg, buf, vec);

    printf("SVE demo: vl=%zu lanes\n", vl);
    for (size_t i = 0; i < vl; i++) {
        printf("lane[%zu]=%d\n", i, buf[i]);
    }

    free(buf);
    return 0;
}
