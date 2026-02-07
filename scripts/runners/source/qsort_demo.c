#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void swap_int(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

static int partition(int *arr, int low, int high) {
    int pivot = arr[high];
    int i = low - 1;

    for (int j = low; j < high; j++) {
        if (arr[j] <= pivot) {
            i++;
            swap_int(&arr[i], &arr[j]);
        }
    }

    swap_int(&arr[i + 1], &arr[high]);
    return i + 1;
}

static void quicksort(int *arr, int low, int high) {
    if (low < high) {
        int pi = partition(arr, low, high);
        quicksort(arr, low, pi - 1);
        quicksort(arr, pi + 1, high);
    }
}

static int checksum(const int *arr, int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i] * (i + 1);
    }
    return sum;
}

int main(void) {
    enum { DATA_SIZE = 100 };
    int data[DATA_SIZE];
    int size = DATA_SIZE;

    srand((unsigned int)time(NULL));
    for (int i = 0; i < size; i++) {
        data[i] = rand() % 1000;
    }

    quicksort(data, 0, size - 1);

    int sum = checksum(data, size);
    printf("sorted checksum: %d\n", sum);

    return 0;
}
