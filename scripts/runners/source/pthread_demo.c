#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int rounds;
    int step;
    long *shared_sum;
    pthread_mutex_t *mutex;
} worker_ctx_t;

static void *worker_fn(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;

    for (int i = 0; i < ctx->rounds; i++) {
        pthread_mutex_lock(ctx->mutex);
        *ctx->shared_sum += (long)(i + 1) * ctx->step;
        pthread_mutex_unlock(ctx->mutex);
    }

    return NULL;
}

int main(void) {
    enum {
        THREADS = 2,
        ROUNDS = 100,
    };

    pthread_t tids[THREADS];
    worker_ctx_t contexts[THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    long shared_sum = 0;

    for (int index = 0; index < THREADS; index++) {
        contexts[index].rounds = ROUNDS;
        contexts[index].step = index + 1;
        contexts[index].shared_sum = &shared_sum;
        contexts[index].mutex = &mutex;

        int err = pthread_create(&tids[index], NULL, worker_fn, &contexts[index]);
        if (err != 0) {
            fprintf(stderr, "pthread_create failed: %d\n", err);
            return 1;
        }
    }

    for (int index = 0; index < THREADS; index++) {
        int err = pthread_join(tids[index], NULL);
        if (err != 0) {
            fprintf(stderr, "pthread_join failed: %d\n", err);
            return 1;
        }
    }

    long expected = 0;
    for (int i = 0; i < ROUNDS; i++) {
        expected += (long)(i + 1) * 1;
        expected += (long)(i + 1) * 2;
    }

    if (shared_sum != expected) {
        fprintf(stderr, "unexpected sum: got=%ld expected=%ld\n", shared_sum, expected);
        return 1;
    }

    printf("pthread demo sum: %ld\n", shared_sum);
    return 0;
}
