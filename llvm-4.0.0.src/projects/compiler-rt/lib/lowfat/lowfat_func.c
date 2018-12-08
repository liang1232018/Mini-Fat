#include <lowfat.h>

#define INLINEATTR __attribute__((always_inline))

#define MINIFAT_MASK (0xFC00000000000000)
#define MINIFAT_MATCH (0x03FFFFFFFFFFFFFF)
#define MINIFAT_BASE_SIZE 6

#define PTRTYPE uint64_t

INLINEATTR void* __minifat_uninstrument(const void* ptr){
    return  (void *)((unsigned long long )ptr & MINIFAT_MATCH);
}
INLINEATTR void* __minifat_uninstrument_check(const void* ptr, size_t* size) {

    unsigned long long tmp_size = (unsigned long long )ptr & MINIFAT_MASK;
    unsigned long long alloca_size = tmp_size >> (64 - MINIFAT_BASE_SIZE);
    alloca_size = 1 << alloca_size;
    // if(alloca_size == 0)
    //     return ptr;

    unsigned long long match = (unsigned long long )ptr & MINIFAT_MATCH;
    unsigned long long offset = (unsigned long long)ptr & (alloca_size - 1);

    if(offset + *size <= alloca_size) {
        return match;
    } 
    // todo SRW ptr
    lowfat_oob_error("libc overflow",ptr+*size, (unsigned long long)ptr & (~(alloca_size - 1)));
    return NULL;

}
INLINEATTR PTRTYPE __minifat_extract_ubnd(const void* ptr) {
    unsigned long long size = (unsigned long long )ptr & MINIFAT_MASK;
    size = size >> (64 - MINIFAT_BASE_SIZE);
    unsigned long long alloca_size = 1 << size;
    return ((unsigned long long )ptr & MINIFAT_MATCH & alloca_size) + (alloca_size - 1);
}
INLINEATTR void* __minifat_combine_ptr(const void* ptrval, PTRTYPE ubnd) {
    unsigned long long size = ubnd - (uint64_t)ptrval;
    int num = 0;
    while(size != 0) {
        size = size >> 1;
        num++;
    }

    num = num  << (64 - MINIFAT_BASE_SIZE);

    return ptrval + num;

}
// todo if doesnot know the size
INLINEATTR PTRTYPE __minifat_highest_bound(){
    return 0x8000000000000ull;
}