#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <utime.h>
#include <dirent.h>
#include <setjmp.h>
#include <mntent.h>
#include <libgen.h>
#include <getopt.h>
#include <ftw.h>
#include <poll.h>
#include <pthread.h>
#include <libintl.h>
#include <nl_types.h>
#include <iconv.h>
#include <locale.h>
#include <langinfo.h>
#include <monetary.h>
#include <wchar.h>
#include <semaphore.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sem.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#define weak_alias(old, new) extern __typeof(old) new __attribute__((weak, alias(#old)))

#define PAGE_SIZE 4096
#define PTRSIZE 4
#define PTRTYPE uint64_t
#define PTRSIZEBITS PTRSIZE*8
#define PTRVALMASK ((1ULL << PTRSIZEBITS) - 1ULL)
#define UPBNDMASK  (~((1ULL << PTRSIZEBITS) - 1ULL))
#define MAXPTRVAL PTRVALMASK

#define INLINEATTR __attribute__((always_inline))

/* ------------------------------------------------------------------------- */
/* ------------------ Run-time macros to change behaviour ------------------ */
/* ------------------------------------------------------------------------- */
//#define minifat_ZERO_ON_ERROR 1  // comment out if want at least partial results

/* ------------------------------------------------------------------------- */
/* --------------------------- minifat helpers --------------------------- */
/* ------------------------------------------------------------------------- */
INLINEATTR void* __minifat_uninstrument(const void* ptr);
INLINEATTR void* __minifat_uninstrument_check(const void* ptr, size_t* size);
INLINEATTR PTRTYPE __minifat_extract_ubnd(const void* ptr);
INLINEATTR void* __minifat_combine_ptr(const void* ptrval, PTRTYPE ubnd);
INLINEATTR PTRTYPE __minifat_highest_bound();

int printf(const char *__restrict format, ...);
__attribute__((noinline)) void __minifat_printptr(const char* str, const void* ptr) {
    str = __minifat_uninstrument(str);
    long long unsigned ptrint = (long long unsigned) ptr;
    printf("[minifat info] %s = %llx\n", str, ptrint);
}


// TODOs:
//   - currently we only uninstrument, must also minifat-check
//       - done for most important (mem*) funcs via __minifat_uninstrument_check
//   - environ variable is uninstrumented: must deal with accesses to it
//       - done in a hacky way (environ is always uninstrumented)
//   - currently ignore widechar versions of functions (e.g., wcstod, wprintf)
//
//   - high priority: linux,
//                    search, regex,
//   - low  priority: complex (?), conf, crypt, ctype (?), math,
//                    sched,
//   - zero priority: fenv (?), ldso, legacy, mq, multibyte, process,
//                    termios, tsxqueue
//
// DONE: fcntl, malloc, mman, stdlib, string, unistd, stdio, time, env, errno,
//       stat, exit, prng, dirent, setjmp, misc, select, thread, locale, network,
//       temp, passwd, signal, ipc

// NOTE: we use `0` in high bits to indicate NULL (always-failing) bounds;
//       this should work fine -- we do not have legacy uninstrumented funcs

/* ------------------------------------------------------------------------- */
/* --------------------------- memory allocation --------------------------- */
/* ------------------------------------------------------------------------- */
// void *minifat_malloc(size_t size);
// void* minifat_calloc(size_t n_elements, size_t element_size);
// void* minifat_realloc(void* p, size_t n);
// void* minifat_memalign(size_t alignment, size_t n);
// int minifat_posix_memalign(void** pp, size_t alignment, size_t n);
// void* minifat_valloc(size_t size);
// void* minifat_pvalloc(size_t size);
// void minifat_free(void* ptr);

void *minifat_mmap(void *start, size_t len, int prot, int flags, int fd, off_t off);
int minifat_mprotect(void *addr, size_t len, int prot);
int minifat_madvise(void *addr, size_t len, int advice);
int minifat_mincore(void *addr, size_t len, unsigned char *vec);
int minifat_munmap(void *start, size_t len);

// static inline uintptr_t minifat_specifyupbound(uintptr_t ptrint, size_t size) {
//     // calculate upper bound
//     uintptr_t upbnd = ptrint + size;
//     assert(upbnd <= MAXPTRVAL);
//     // save lower bound right after allocated object
//     PTRTYPE* lobndaddr = (PTRTYPE*) upbnd;
//     *lobndaddr = ptrint;
//     return upbnd;
// }

// static inline void* minifat_makefatptr(uintptr_t ptrint, uintptr_t upbnd) {
//     // add upper bound in upper bits of ptr
//     ptrint |= upbnd << PTRSIZEBITS;
//     return (void*) ptrint;
// }

static inline void* minifat_specifybounds(void* ptr, size_t size) {
    unsigned long long num = 0;
    while(size != 0) {
        size = size >> 1;
        num++;
    }
    num = ~num & 0x3F;
    num = num  << 58;
    return ptr + num;
}

// void* minifat_malloc(size_t size) {
//     if (size == 0) {
//         // comply with musl which returns some (unaccessible) address
//         return malloc(size);
//     }
//     void* ptr = malloc(size + PTRSIZE);
//     if (ptr)
//         ptr = minifat_specifybounds(ptr, size);
//     return ptr;
// }

// void* minifat_calloc(size_t n_elements, size_t element_size) {
//     if (n_elements == 0 || element_size == 0) {
//         // comply with musl which returns some (unaccessible) address
//         return calloc(n_elements, element_size);
//     }
//     size_t add = (element_size >= PTRSIZE) ? 1 : (PTRSIZE/element_size + 1);
//     void* ptr = calloc(n_elements + add, element_size);
//     if (ptr)
//         ptr = minifat_specifybounds(ptr, n_elements * element_size);
//     return ptr;
// }

// void* minifat_realloc(void* p, size_t n) {
//     if (n == 0) {
//         // comply with musl which returns some (unaccessible) address
//         return realloc(p, n);
//     }
//     if (p)  p = __minifat_uninstrument(p);
//     void* ptr = realloc(p, n + PTRSIZE);
//     if (ptr)
//         ptr = minifat_specifybounds(ptr, n);
//     return ptr;
// }

// void* minifat_memalign(size_t alignment, size_t n) {
//     if (n == 0) {
//         // comply with musl which returns some (unaccessible) address
//         return memalign(alignment, n);
//     }
//     void* ptr = memalign(alignment, n + PTRSIZE);
//     if (ptr)
//         ptr = minifat_specifybounds(ptr, n);
//     return ptr;
// }

// int minifat_posix_memalign(void** pp, size_t alignment, size_t n) {
//     if (n == 0) {
//         // comply with musl which returns some (unaccessible) address
//         return posix_memalign(pp, alignment, n);
//     }
//     if (pp)  pp = __minifat_uninstrument(pp);
//     int ret = posix_memalign(pp, alignment, n + PTRSIZE);
//     *pp = minifat_specifybounds(*pp, n);
//     return ret;
// }

// void* minifat_valloc(size_t size) {
//     if (size == 0) {
//         // comply with musl which returns some (unaccessible) address
//         return valloc(size);
//     }
//     void* ptr = valloc(size + PTRSIZE);
//     if (ptr)
//         ptr = minifat_specifybounds(ptr, size);
//     return ptr;
// }

// void* minifat_pvalloc(size_t size) {
//     if (size == 0) {
//         // comply with musl which returns some (unaccessible) address
//         return pvalloc(size);
//     }
//     void* ptr = pvalloc(size + PTRSIZE);
//     if (ptr)
//         ptr = minifat_specifybounds(ptr, size);
//     return ptr;
// }

// void minifat_free(void* ptr) {
//     if (ptr)  ptr = __minifat_uninstrument(ptr);
//     free(ptr);
// }

void *minifat_mmap(void *start, size_t len, int prot, int flags, int fd, off_t off) {
    void* startval = NULL;
    if (start)  startval = __minifat_uninstrument(start);
    void* ptr = mmap(startval, len + PTRSIZE, prot, flags, fd, off);
    if (ptr)
        ptr = minifat_specifybounds(ptr, len);
    return ptr;
}

void *minifat_mmap64(void *start, size_t len, int prot, int flags, int fd, off_t off) {
    return minifat_mmap(start, len, prot, flags, fd, off);
}

void *minifat_mremap(void *old_addr, size_t old_len, size_t new_len, int flags, ...) {
    assert(0 && "mremap is not implemented in minifat!");
    exit(42);
    return NULL;
}

int minifat_mprotect(void *addr, size_t len, int prot) {
    if (addr)  addr = __minifat_uninstrument(addr);
    return mprotect(addr, len + PTRSIZE, prot);
}

int minifat_madvise(void *addr, size_t len, int advice) {
    if (addr)  addr = __minifat_uninstrument(addr);
    return madvise(addr, len + PTRSIZE, advice);
}

int minifat_mincore(void *addr, size_t len, unsigned char *vec) {
    if (addr)  addr = __minifat_uninstrument(addr);
    if (vec)   vec  = __minifat_uninstrument(vec);
    return mincore(addr, len + PTRSIZE, vec);
}

int minifat_munmap(void *start, size_t len) {
    if (start)  start = __minifat_uninstrument(start);
    return munmap(start, len + PTRSIZE);
}

int minifat_munmap64(void *start, size_t len) {
    return minifat_munmap(start, len);
}

/* ------------------------------------------------------------------------- */
/* ---------------------------- memory movements --------------------------- */
/* ------------------------------------------------------------------------- */
extern void *minifat_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n);
void *minifat_memmove(void *dest, const void *src, size_t n);
extern void *minifat_memset(void *dest, int c, size_t n);
void minifat_bzero(void *s, size_t n);
int minifat_bcmp(const void *s1, const void *s2, size_t n);
void minifat_bcopy(const void *s1, void *s2, size_t n);
void *minifat_memccpy(void *__restrict__ dest, const void *__restrict__ src, int c, size_t n);
void *minifat_memchr(const void *src, int c, size_t n);
int minifat_memcmp(const void *vl, const void *vr, size_t n);
void *minifat_memmem(const void *h0, size_t k, const void *n0, size_t l);
void *minifat_mempcpy(void *dest, const void *src, size_t n);
void *minifat_memrchr(const void *m, int c, size_t n);

INLINEATTR void *minifat_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n) {
    void* ret = dest;
    size_t oldn = n;
    if (dest) dest = __minifat_uninstrument_check(dest, &n);
    if (src)  src  = __minifat_uninstrument_check(src, &n);
    memcpy(dest, src, n);
#ifdef minifat_ZERO_ON_ERROR
    if (oldn > n) {
        PTRTYPE ubnd = __minifat_extract_ubnd(ret);
        PTRTYPE rest = (ubnd - (uintptr_t)dest) - n;
        minifat_bzero(dest+n, rest);
    }
#endif
    return ret;
}

void *minifat_memmove(void *dest, const void *src, size_t n) {
    void* ret = dest;
    size_t oldn = n;
    if (dest) dest = __minifat_uninstrument_check(dest, &n);
    if (src)  src  = __minifat_uninstrument_check(src, &n);
    memmove(dest, src, n);
#ifdef minifat_ZERO_ON_ERROR
    if (oldn > n) {
        PTRTYPE ubnd = __minifat_extract_ubnd(ret);
        PTRTYPE rest = (ubnd - (uintptr_t)dest) - n;
        minifat_bzero(dest+n, rest);
    }
#endif
    return ret;
}

void *minifat_memset(void *dest, int c, size_t n) {
    void* ret = dest;
    size_t oldn = n;
    if (dest) dest = __minifat_uninstrument_check(dest, &n);
    memset(dest, c, n);
    return ret;
}

void minifat_bzero(void *s, size_t n) {
    size_t oldn = n;
    if (s)  s = __minifat_uninstrument_check(s, &n);
    bzero(s, n);
}

int minifat_bcmp(const void *s1, const void *s2, size_t n) {
    if (s1)  s1 = __minifat_uninstrument_check(s1, &n);
    if (s2)  s2 = __minifat_uninstrument_check(s2, &n);
    return bcmp(s1, s2, n);
}

void minifat_bcopy(const void *s1, void *s2, size_t n) {
    void* olds2 = s2;
    size_t oldn = n;
    if (s1)  s1 = __minifat_uninstrument_check(s1, &n);
    if (s2)  s2 = __minifat_uninstrument_check(s2, &n);
    bcopy(s1, s2, n);
#ifdef minifat_ZERO_ON_ERROR
    if (oldn > n)  minifat_bzero(s2, __minifat_extract_ubnd(olds2));
#endif
}

void *minifat_memccpy(void *__restrict__ dest, const void *__restrict__ src, int c, size_t n) {
    PTRTYPE ubnd = __minifat_extract_ubnd(dest);
    size_t oldn = n;
    if (dest)  dest = __minifat_uninstrument_check(dest, &n);
    if (src)   src  = __minifat_uninstrument_check(src, &n);
    void* ptr = memccpy(dest, src, c, n);
    if (ptr) {
        // ptr points into dest, so it has the same bounds as dest
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
#ifdef minifat_ZERO_ON_ERROR
    if (oldn > n)  minifat_bzero(dest, ubnd);
#endif
    return ptr;
}

void *minifat_memchr(const void *src, int c, size_t n) {
    PTRTYPE ubnd = __minifat_extract_ubnd(src);
    size_t oldn = n;
    if (src)  src  = __minifat_uninstrument_check(src, &n);
    char* ptr = memchr(src, c, n);
    if (ptr) {
        // ptr points into src, so it has the same bounds as src
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

int minifat_memcmp(const void *vl, const void *vr, size_t n) {
    if (vl)  vl  = __minifat_uninstrument_check(vl, &n);
    if (vr)  vr  = __minifat_uninstrument_check(vr, &n);
    return memcmp(vl, vr, n);
}

void *minifat_memmem(const void *h0, size_t k, const void *n0, size_t l) {
    PTRTYPE ubnd = __minifat_extract_ubnd(h0);
    if (h0)  h0  = __minifat_uninstrument_check(h0, &k);
    if (n0)  n0  = __minifat_uninstrument_check(n0, &l);
    void* ptr = memmem(h0, k, n0, l);
    if (ptr) {
        // ptr points into h0, so it has the same bounds as h0
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

void *minifat_mempcpy(void *dest, const void *src, size_t n) {
    PTRTYPE ubnd = __minifat_extract_ubnd(dest);
    size_t oldn = n;
    if (dest)  dest = __minifat_uninstrument_check(dest, &n);
    if (src)   src  = __minifat_uninstrument_check(src, &n);
    void* ptr = mempcpy(dest, src, n);
#ifdef minifat_ZERO_ON_ERROR
    if (oldn > n)  minifat_bzero(dest, ubnd);
#endif
    // ptr points into dest, so it has the same bounds as dest
    return __minifat_combine_ptr(ptr, ubnd);
}

void *minifat_memrchr(const void *m, int c, size_t n) {
    PTRTYPE ubnd = __minifat_extract_ubnd(m);
    if (m)  m  = __minifat_uninstrument_check(m, &n);
    char* ptr = memrchr(m, c, n);
    if (ptr) {
        // ptr points into m, so it has the same bounds as m
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

// weak_alias(memcpy, __sgxbound_memcpy);
// weak_alias(memmove, __sgxbound_memmove);
// weak_alias(memset, __sgxbound_memset);

/* ------------------------------------------------------------------------- */
/* ---------------------------- string functions --------------------------- */
/* ------------------------------------------------------------------------- */
struct charbuf {
    char buf[1020]; // hopefully enough for all kinds of strings
    PTRTYPE lbnd;
};

char *minifat_index(const char *s, int c);
char *minifat_rindex(const char *s, int c);
char *minifat_stpcpy(char *__restrict__ d, const char *__restrict__ s);
char *minifat_stpncpy(char *__restrict__ d, const char *__restrict__ s, size_t n);
int minifat_strcasecmp(const char *_l, const char *_r);
char *minifat_strcasestr(const char *h, const char *n);
char *minifat_strcat(char *__restrict__ dest, const char *__restrict__ src);
char *minifat_strchr(const char *s, int c);
char *minifat_strchrnul(const char *s, int c);
int minifat_strcmp(const char *l, const char *r);
char *minifat_strcpy(char *__restrict__ dest, const char *__restrict__ src);
size_t minifat_strcspn(const char *s, const char *c);
char *minifat_strdup(const char *s);
char *minifat_strerror(int errnum);
int minifat_strerror_r(int err, char *buf, size_t buflen);
int __xpg_strerror_r(int err, char *buf, size_t buflen);
// size_t minifat_strlcat(char *d, const char *s, size_t n);
// size_t minifat_strlcpy(char *d, const char *s, size_t n);
size_t minifat_strlen(const char *s);
int minifat_strncasecmp(const char *l, const char *r, size_t n);
char *minifat_strncat(char *__restrict__ d, const char *__restrict__ s, size_t n);
int minifat_strncmp(const char *l, const char *r, size_t n);
char *minifat_strncpy(char *__restrict__ d, const char *__restrict__ s, size_t n);
char *minifat_strndup(const char *s, size_t n);
size_t minifat_strnlen(const char *s, size_t n);
char *minifat_strpbrk(const char *s, const char *b);
char *minifat_strrchr(const char *s, int c);
char *minifat_strsep(char **str, const char *sep);
char *minifat_strsignal(int signum);
size_t minifat_strspn(const char *s, const char *c);
char *minifat_strstr(const char *h, const char *n);
char *minifat_strtok(char *__restrict__ s, const char *__restrict__ sep);
char *minifat_strtok_r(char *__restrict__ s, const char *__restrict__ sep, char **__restrict__ p);
int minifat_strverscmp(const char *l, const char *r);
void minifat_swab(const void *__restrict__ src, void *__restrict__ dest, ssize_t n);

char *minifat_index(const char *s, int c) {
    char* sval = __minifat_uninstrument(s);
    char* ptr = index(sval, c);
    if (ptr) {
        // ptr points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

char *minifat_rindex(const char *s, int c) {
    char* sval = __minifat_uninstrument(s);
    char* ptr = rindex(sval, c);
    if (ptr) {
        // ptr points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

char *minifat_stpcpy(char *__restrict__ d, const char *__restrict__ s) {
    char* dval = __minifat_uninstrument(d);
    char* sval  = __minifat_uninstrument(s);
    char* ptr = stpcpy(dval, sval);
    // ptr points into d, so it has the same bounds as d
    PTRTYPE ubnd = __minifat_extract_ubnd(d);
    return __minifat_combine_ptr(ptr, ubnd);
}

char *minifat_stpncpy(char *__restrict__ d, const char *__restrict__ s, size_t n) {
    char* dval = __minifat_uninstrument(d);
    char* sval  = __minifat_uninstrument(s);
    char* ptr = stpncpy(dval, sval, n);
    // ptr points into d, so it has the same bounds as d
    PTRTYPE ubnd = __minifat_extract_ubnd(d);
    return __minifat_combine_ptr(ptr, ubnd);
}

int minifat_strcasecmp(const char *l, const char *r) {
    l = __minifat_uninstrument(l);
    r = __minifat_uninstrument(r);
    return strcasecmp(l, r);
}

char *minifat_strcasestr(const char *h, const char *n) {
    char* hval = __minifat_uninstrument(h);
    char* nval = __minifat_uninstrument(n);
    char* ptr = strcasestr(hval, nval);
    if (ptr) {
        // ptr points into h, so it has the same bounds as h
        PTRTYPE ubnd = __minifat_extract_ubnd(h);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

char *minifat_strcat(char *__restrict__ dest, const char *__restrict__ src) {
    char* destval = __minifat_uninstrument(dest);
    char* srcval  = __minifat_uninstrument(src);
    strcat(destval, srcval);
    return dest;
}

char *minifat_strchr(const char *s, int c) {
    char* sval = __minifat_uninstrument(s);
    char* ptr = strchr(sval, c);
    if (ptr) {
        // ptr points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

char *minifat_strchrnul(const char *s, int c) {
    char* sval = __minifat_uninstrument(s);
    char* ptr = strchrnul(sval, c);
    // ptr points into s, so it has the same bounds as s
    PTRTYPE ubnd = __minifat_extract_ubnd(s);
    return __minifat_combine_ptr(ptr, ubnd);
}

int minifat_strcmp(const char *l, const char *r) {
    l = __minifat_uninstrument(l);
    r = __minifat_uninstrument(r);
    return strcmp(l, r);
}

INLINEATTR char *minifat_strcpy(char *__restrict__ dest, const char *__restrict__ src) {
    char* destval = __minifat_uninstrument(dest);
    char* srcval  = __minifat_uninstrument(src);
    strcpy(destval, srcval);
    return dest;
}

size_t minifat_strcspn(const char *s, const char *c) {
    s = __minifat_uninstrument(s);
    c = __minifat_uninstrument(c);
    return strcspn(s, c);
}

void* __minifat_memdup(const void *s, size_t size) {
    void* ptr = malloc(size + PTRSIZE);
    if (!ptr) return NULL;
    memcpy(ptr, s, size);
    ptr = minifat_specifybounds(ptr, size);
    return ptr;
}

char* __minifat_strdup(const char *s) {
    size_t size = strlen(s) + 1;           // +1 for null terminator
    return __minifat_memdup(s, size);
}

char *minifat_strdup(const char *s) {
    s = __minifat_uninstrument(s);
    return __minifat_strdup(s);
}

char *minifat_strerror(int errnum) {
    static struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    char* ret = strerror(errnum);
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

int minifat_strerror_r(int err, char *buf, size_t buflen) {
    buf = __minifat_uninstrument(buf);
    return strerror_r(err, buf, buflen);
}

int __xpg_strerror_r(int err, char *buf, size_t buflen) {
    buf = __minifat_uninstrument(buf);
    return __xpg_strerror_r(err, buf, buflen);
}

// size_t minifat_strlcat(char *d, const char *s, size_t n) {
//     d = __minifat_uninstrument(d);
//     s = __minifat_uninstrument(s);
//     return strlcat(d, s, n);
// }

// size_t minifat_strlcpy(char *d, const char *s, size_t n) {
//     d = __minifat_uninstrument(d);
//     s = __minifat_uninstrument(s);
//     return strlcpy(d, s, n);
// }

size_t minifat_strlen(const char *s) {
    s = __minifat_uninstrument(s);
    return strlen(s);
}

// weak_alias(strlen, __sgxbound_strlen);

int minifat_strncasecmp(const char *l, const char *r, size_t n) {
    l = __minifat_uninstrument(l);
    r = __minifat_uninstrument(r);
    return strncasecmp(l, r, n);
}

char *minifat_strncat(char *__restrict__ d, const char *__restrict__ s, size_t n) {
    char* dval = __minifat_uninstrument(d);
    char* sval  = __minifat_uninstrument(s);
    strncat(dval, sval, n);
    return d;
}

int minifat_strncmp(const char *l, const char *r, size_t n) {
    l = __minifat_uninstrument(l);
    r = __minifat_uninstrument(r);
    return strncmp(l, r, n);
}

char *minifat_strncpy(char *__restrict__ d, const char *__restrict__ s, size_t n) {
    char* dval = __minifat_uninstrument(d);
    char* sval  = __minifat_uninstrument(s);
    strncpy(dval, sval, n);
    return d;
}

char *minifat_strndup(const char *s, size_t n) {
    s = __minifat_uninstrument(s);
    size_t l = strnlen(s, n);
    char *d = malloc(l + 1 + PTRSIZE); // +1 for null terminator
    if (!d) return NULL;
    memcpy(d, s, l);
    d[l] = 0;
    d = minifat_specifybounds(d, l + 1);
    return d;
}

size_t minifat_strnlen(const char *s, size_t n) {
    s = __minifat_uninstrument(s);
    return strnlen(s, n);
}

char *minifat_strpbrk(const char *s, const char *b) {
    char* sval = __minifat_uninstrument(s);
    char* bval = __minifat_uninstrument(b);
    char* ptr = strpbrk(sval, bval);
    if (ptr) {
        // ptr points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

char *minifat_strrchr(const char *s, int c) {
    char* sval = __minifat_uninstrument(s);
    char* ptr = strrchr(sval, c);
    if (ptr) {
        // ptr points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

char *minifat_strsep(char **str, const char *sep) {
    str = (char **) __minifat_uninstrument((void*) str);
    sep = (const char *) __minifat_uninstrument((void*) sep);
    char *s = *str;
    if (!s) return NULL;
    *str = __minifat_uninstrument(s);
    strsep(str, sep);
    if (*str) {
        // *str points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *str = __minifat_combine_ptr(*str, ubnd);
    }
    return s;
}

char *minifat_strsignal(int signum) {
    static struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    char* ret = strsignal(signum);
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

size_t minifat_strspn(const char *s, const char *c) {
    s = __minifat_uninstrument(s);
    c = __minifat_uninstrument(c);
    return strspn(s, c);
}

char *minifat_strstr(const char *h, const char *n) {
    char* hval = __minifat_uninstrument(h);
    char* nval = __minifat_uninstrument(n);
    char* ptr = strstr(hval, nval);
    if (ptr) {
        // ptr points into h, so it has the same bounds as h
        PTRTYPE ubnd = __minifat_extract_ubnd(h);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

char *minifat_strtok(char *__restrict__ s, const char *__restrict__ sep) {
    static PTRTYPE curr_ubnd = 0;
    char* sval = NULL;
    if (s) {
        // first invocation, memorize ubnd of s
        sval      = __minifat_uninstrument(s);
        curr_ubnd = __minifat_extract_ubnd(s);
    }
    sep = __minifat_uninstrument(sep);
    char* ptr = strtok(sval, sep);
    if (ptr) {
        // ptr points into s from first invocation
        assert(curr_ubnd != 0);
        ptr = __minifat_combine_ptr(ptr, curr_ubnd);
    }
    return ptr;
}

char *minifat_strtok_r(char *__restrict__ s, const char *__restrict__ sep, char **__restrict__ p) {
    PTRTYPE curr_ubnd = 0;
    char* sval = NULL;
    sep = __minifat_uninstrument(sep);
    p   = __minifat_uninstrument(p);
    if (s) {
        // first invocation
        curr_ubnd = __minifat_extract_ubnd(s);
        sval = __minifat_uninstrument(s);
    } else {
        // following invocations
        curr_ubnd = __minifat_extract_ubnd(*p);
        *p = __minifat_uninstrument(*p);
    }
    char* ptr = strtok_r(sval, sep, p);
    *p = __minifat_combine_ptr(*p, curr_ubnd);
    if (ptr) {
        // ptr points into s, so it has the same bounds as s
        // (which value is memorized in curr_ubnd)
        assert(curr_ubnd != 0);
        ptr = __minifat_combine_ptr(ptr, curr_ubnd);
    }
    return ptr;
}

int minifat_strverscmp(const char *l, const char *r) {
    l = __minifat_uninstrument(l);
    r = __minifat_uninstrument(r);
    return strverscmp(l, r);
}

void minifat_swab(const void *__restrict__ src, void *__restrict__ dest, ssize_t n) {
    if (n <= 0) return;
    src  = __minifat_uninstrument(src);
    dest = __minifat_uninstrument(dest);
    swab(src, dest, n);
}

/* ------------------------------------------------------------------------- */
/* ------------------------- file descriptor funcs ------------------------- */
/* ------------------------------------------------------------------------- */
int minifat_open(const char *filename, int flags, ...);
int minifat_open64(const char *filename, int flags, ...);
int minifat_openat(int fd, const char *filename, int flags, ...);
int minifat_openat64(int fd, const char *filename, int flags, ...);
int minifat_creat(const char *filename, mode_t mode);
int minifat_creat64(const char *filename, mode_t mode);
int minifat_access(const char *filename, int amode);
int minifat_acct(const char *filename);
int minifat_chdir(const char *path);
int minifat_chown(const char *path, uid_t uid, gid_t gid);
int minifat_lchown(const char *path, uid_t uid, gid_t gid);
char *minifat_ctermid(char *s);
int minifat_faccessat(int fd, const char *filename, int amode, int flag);
int minifat_fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag);
char *minifat_getcwd(char *buf, size_t size);
int minifat_getgroups(int count, gid_t list[]);
int minifat_gethostname(char *name, size_t len);
char *minifat_getlogin(void);
int minifat_getlogin_r(char *name, size_t size);
int minifat_link(const char *existing, const char *new);
int minifat_linkat(int fd1, const char *existing, int fd2, const char *new, int flag);
int minifat_pipe(int fd[2]);
int minifat_pipe2(int fd[2], int flag);
ssize_t minifat_pread(int fd, void *buf, size_t size, off_t ofs);
ssize_t minifat_pread64(int fd, void *buf, size_t size, off_t ofs);
ssize_t minifat_preadv(int fd, const struct iovec *iov, int count, off_t ofs);
ssize_t minifat_preadv64(int fd, const struct iovec *iov, int count, off_t ofs);
ssize_t minifat_pwrite(int fd, const void *buf, size_t size, off_t ofs);
ssize_t minifat_pwrite64(int fd, const void *buf, size_t size, off_t ofs);
ssize_t minifat_pwritev(int fd, const struct iovec *iov, int count, off_t ofs);
ssize_t minifat_minifat_pwritev64(int fd, const struct iovec *iov, int count, off_t ofs);
ssize_t minifat_read(int fd, void *buf, size_t count);
ssize_t minifat_readlink(const char *__restrict__ path, char *__restrict__ buf, size_t bufsize);
ssize_t minifat_readlinkat(int fd, const char *__restrict__ path, char *__restrict__ buf, size_t bufsize);
ssize_t minifat_readv(int fd, const struct iovec *iov, int count);
int minifat_renameat(int oldfd, const char *old, int newfd, const char *new);
int minifat_rmdir(const char *path);
int minifat_symlink(const char *existing, const char *new);
int minifat_symlinkat(const char *existing, int fd, const char *new);
int minifat_truncate(const char *path, off_t length);
int minifat_truncate64(const char *path, off_t length);
char *minifat_ttyname(int fd);
int minifat_ttyname_r(int fd, char *name, size_t size);
int minifat_unlink(const char *path);
int minifat_unlinkat(int fd, const char *path, int flag);
ssize_t minifat_write(int fd, const void *buf, size_t count);
ssize_t minifat_writev(int fd, const struct iovec *iov, int count);

// TODO: fcntl() from fcntl.c uses varargs; instrument similar to printf?

int minifat_open(const char *filename, int flags, ...) {
    filename = __minifat_uninstrument(filename);
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return open(filename, flags, mode);
    }
    return open(filename, flags);
}

int minifat_open64(const char *filename, int flags, ...) {
    filename = __minifat_uninstrument(filename);
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return open64(filename, flags, mode);
    }
    return open64(filename, flags);
}

int minifat_openat(int fd, const char *filename, int flags, ...) {
    filename = __minifat_uninstrument(filename);
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return openat(fd, filename, flags, mode);
    }
    return openat(fd, filename, flags);
}

int minifat_openat64(int fd, const char *filename, int flags, ...) {
    filename = __minifat_uninstrument(filename);
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return openat64(fd, filename, flags, mode);
    }
    return openat64(fd, filename, flags);
}

int minifat_creat(const char *filename, mode_t mode) {
    filename = __minifat_uninstrument(filename);
    return creat(filename, mode);
}

int minifat_creat64(const char *filename, mode_t mode) {
    return creat(filename, mode);
}

int minifat_access(const char *filename, int amode) {
    filename = __minifat_uninstrument(filename);
    return access(filename, amode);
}

int minifat_acct(const char *filename) {
    filename = __minifat_uninstrument(filename);
    return acct(filename);
}

int minifat_chdir(const char *path) {
    path = __minifat_uninstrument(path);
    return chdir(path);
}

int minifat_chown(const char *path, uid_t uid, gid_t gid) {
    path = __minifat_uninstrument(path);
    return chown(path, uid, gid);
}

int minifat_lchown(const char *path, uid_t uid, gid_t gid) {
    path = __minifat_uninstrument(path);
    return lchown(path, uid, gid);
}

char *minifat_ctermid(char *s) {
    // TODO: now it's suboptimal due to mem allocation on each call via strdup
    s = __minifat_uninstrument(s);
    char* tmp = ctermid(s);
    if (!tmp) return NULL;
    return __minifat_strdup(tmp);
}

int minifat_faccessat(int fd, const char *filename, int amode, int flag) {
    filename = __minifat_uninstrument(filename);
    return faccessat(fd, filename, amode, flag);
}

int minifat_fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag) {
    path = __minifat_uninstrument(path);
    return fchownat(fd, path, uid, gid, flag);
}

char *minifat_getcwd(char *buf, size_t size)
{
    if (buf) {
        // user supplied `buf` which is already instrumented:
        // uninstrument for real getcwd, but return `buf`
        char* bufval = __minifat_uninstrument(buf);
        char* ret = getcwd(bufval, size);
        if (!ret) return 0;
        return buf;
    }
    // else no `buf` is supplied, use tmp for real getcwd
    // and copy it using our instrumented version of strdup
    char tmp[PATH_MAX];
    char* ret = getcwd(tmp, sizeof(tmp));
    if (!ret) return 0;
    return __minifat_strdup(tmp);
}

int minifat_getgroups(int count, gid_t list[]) {
    // TODO: implement it?
    return -1;
}

int minifat_gethostname(char *name, size_t len) {
    name = __minifat_uninstrument(name);
    return gethostname(name, len);
}

char *minifat_getlogin(void) {
    static struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    char* ret = getlogin();
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

int minifat_getlogin_r(char *name, size_t size) {
    name = __minifat_uninstrument(name);
    return getlogin_r(name, size);
}

int minifat_link(const char *existing, const char *new) {
    existing = __minifat_uninstrument(existing);
    new = __minifat_uninstrument(new);
    return link(existing, new);
}

int minifat_linkat(int fd1, const char *existing, int fd2, const char *new, int flag) {
    existing = __minifat_uninstrument(existing);
    new = __minifat_uninstrument(new);
    return linkat(fd1, existing, fd2, new, flag);
}

int minifat_pipe(int fd[2]) {
    int* fdval = (int*)__minifat_uninstrument((void*) fd);
    return pipe(fdval);
}

int minifat_pipe2(int fd[2], int flag) {
    int* fdval = (int*)__minifat_uninstrument((void*) fd);
    return pipe2(fdval, flag);
}

ssize_t minifat_pread(int fd, void *buf, size_t size, off_t ofs) {
    buf = __minifat_uninstrument(buf);
    return pread(fd, buf, size, ofs);
}

ssize_t minifat_pread64(int fd, void *buf, size_t size, off_t ofs) {
    return pread(fd, buf, size, ofs);
}

ssize_t minifat_preadv(int fd, const struct iovec *iov, int count, off_t ofs) {
    int i;
    // uninstrument iov into iovval including its iov_base members
    struct iovec* iovval = malloc(count * sizeof(struct iovec));
    iov = __minifat_uninstrument(iov);
    for (i = 0; i < count; i++) {
        iovval[i].iov_base = __minifat_uninstrument(iov[i].iov_base);
        iovval[i].iov_len = iov[i].iov_len;
    }
    ssize_t ret = preadv(fd, iovval, count, ofs);
    free(iovval);
    return ret;
}

ssize_t minifat_preadv64(int fd, const struct iovec *iov, int count, off_t ofs) {
    return preadv(fd, iov, count, ofs);
}

ssize_t minifat_pwrite(int fd, const void *buf, size_t size, off_t ofs) {
    buf = __minifat_uninstrument(buf);
    return pwrite(fd, buf, size, ofs);
}

ssize_t minifat_pwrite64(int fd, const void *buf, size_t size, off_t ofs) {
    return pwrite(fd, buf, size, ofs);
}

ssize_t minifat_write(int fd, const void *buf, size_t count) {
    buf = __minifat_uninstrument(buf);
    return write(fd, buf, count);
}

ssize_t minifat_pwritev(int fd, const struct iovec *iov, int count, off_t ofs) {
    int i;
    // uninstrument iov into iovval including its iov_base members
    struct iovec* iovval = malloc(count * sizeof(struct iovec));
    iov = __minifat_uninstrument(iov);
    for (i = 0; i < count; i++) {
        iovval[i].iov_base = __minifat_uninstrument(iov[i].iov_base);
        iovval[i].iov_len = iov[i].iov_len;
    }
    ssize_t ret = pwritev(fd, iovval, count, ofs);
    free(iovval);
    return ret;
}

ssize_t minifat_pwritev64(int fd, const struct iovec *iov, int count, off_t ofs) {
    return pwritev(fd, iov, count, ofs);
}

ssize_t minifat_writev(int fd, const struct iovec *iov, int count) {
    int i;
    // uninstrument iov into iovval including its iov_base members
    struct iovec* iovval = malloc(count * sizeof(struct iovec));
    iov = __minifat_uninstrument(iov);
    for (i = 0; i < count; i++) {
        iovval[i].iov_base = __minifat_uninstrument(iov[i].iov_base);
        iovval[i].iov_len = iov[i].iov_len;
    }
    ssize_t ret = writev(fd, iovval, count);
    free(iovval);
    return ret;
}

ssize_t minifat_read(int fd, void *buf, size_t count) {
    buf = __minifat_uninstrument(buf);
    return read(fd, buf, count);
}

ssize_t minifat_readlink(const char *__restrict__ path, char *__restrict__ buf, size_t bufsize) {
    path = __minifat_uninstrument(path);
    buf = __minifat_uninstrument(buf);
    return readlink(path, buf, bufsize);
}

ssize_t minifat_readlinkat(int fd, const char *__restrict__ path, char *__restrict__ buf, size_t bufsize) {
    path = __minifat_uninstrument(path);
    buf = __minifat_uninstrument(buf);
    return readlinkat(fd, path, buf, bufsize);
}

ssize_t minifat_readv(int fd, const struct iovec *iov, int count) {
    int i;
    // uninstrument iov into iovval including its iov_base members
    struct iovec* iovval = malloc(count * sizeof(struct iovec));
    iov = __minifat_uninstrument(iov);
    for (i = 0; i < count; i++) {
        iovval[i].iov_base = __minifat_uninstrument(iov[i].iov_base);
        iovval[i].iov_len = iov[i].iov_len;
    }
    ssize_t ret = readv(fd, iovval, count);
    free(iovval);
    return ret;
}

int minifat_renameat(int oldfd, const char *old, int newfd, const char *new) {
    old = __minifat_uninstrument(old);
    new = __minifat_uninstrument(new);
    return renameat(oldfd, old, newfd, new);
}

int minifat_rmdir(const char *path) {
    path = __minifat_uninstrument(path);
    return rmdir(path);
}

int minifat_symlink(const char *existing, const char *new) {
    existing = __minifat_uninstrument(existing);
    new = __minifat_uninstrument(new);
    return symlink(existing, new);
}

int minifat_symlinkat(const char *existing, int fd, const char *new) {
    existing = __minifat_uninstrument(existing);
    new = __minifat_uninstrument(new);
    return symlinkat(existing, fd, new);
}

int minifat_truncate(const char *path, off_t length) {
    path = __minifat_uninstrument(path);
    return truncate(path, length);
}

int minifat_truncate64(const char *path, off_t length) {
    return truncate(path, length);
}

char *minifat_ttyname(int fd) {
    static struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    char* ret = ttyname(fd);
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

int minifat_ttyname_r(int fd, char *name, size_t size) {
    name = __minifat_uninstrument(name);
    return ttyname_r(fd, name, size);
}

int minifat_unlink(const char *path) {
    path = __minifat_uninstrument(path);
    return unlink(path);
}

int minifat_unlinkat(int fd, const char *path, int flag) {
    path = __minifat_uninstrument(path);
    return unlinkat(fd, path, flag);
}

/* ------------------------------------------------------------------------- */
/* ------------------------------ FILE* family ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: struct FILE* is opaque and must never be dereferenced; we use this
//       feature and do not instrument FILE* pointers -- leaving them with
//       NULL (always-failing) bounds, such that any attempt to deref them
//       leads to segfault on address `0`.
//       E.g., fopen() returns FILE* ptr -- we must not instrument this ptr.
//
// NOTE: same reasoning applies to auxiliary structs: fpos_t

FILE *minifat_fdopen(int fd, const char *mode);
// char *minifat_fgetln(FILE *f, size_t *plen);
FILE *minifat_fmemopen(void *__restrict__ buf, size_t size, const char *__restrict__ mode);
FILE *minifat_fopen(const char *__restrict__ filename, const char *__restrict__ mode);
FILE *minifat_fopen64(const char *__restrict__ filename, const char *__restrict__ mode);
size_t minifat_fread(void *__restrict__ destv, size_t size, size_t nmemb, FILE *__restrict__ f);
size_t minifat_fread_unlocked(void *__restrict__ destv, size_t size, size_t nmemb, FILE *__restrict__ f);
FILE *minifat_freopen(const char *__restrict__ filename, const char *__restrict__ mode, FILE *__restrict__ f);
FILE *minifat_freopen64(const char *__restrict__ filename, const char *__restrict__ mode, FILE *__restrict__ f);
size_t minifat_fwrite(const void *__restrict__ src, size_t size, size_t nmemb, FILE *__restrict__ f);
size_t minifat_fwrite_unlocked(const void *__restrict__ src, size_t size, size_t nmemb, FILE *__restrict__ f);
ssize_t minifat_getdelim(char **__restrict__ s, size_t *__restrict__ n, int delim, FILE *__restrict__ f);
FILE *minifat_open_memstream(char **bufp, size_t *sizep);
void minifat_perror(const char *msg);
FILE *minifat_popen(const char *cmd, const char *mode);
int minifat_remove(const char *path);
int minifat_rename(const char *old, const char *new);
void minifat_setbuf(FILE *__restrict__ f, char *__restrict__ buf);
void minifat_setbuffer(FILE *f, char *buf, size_t size);
int minifat_setvbuf(FILE *__restrict__ f, char *__restrict__ buf, int type, size_t size);
// char *minifat_tempnam(const char *dir, const char *pfx);
// char *minifat_tmpnam(char *buf);


FILE *minifat_fdopen(int fd, const char *mode) {
    mode = __minifat_uninstrument(mode);
    return fdopen(fd, mode);
}

// char *minifat_fgetln(FILE *f, size_t *plen) {
//     plen = __minifat_uninstrument(plen);
//     char* ret = fgetln(f, plen);
//     if (ret) {
//         // TODO: suboptimal due to mem allocation on each call to fgetln
//         ret = __minifat_memdup(ret, *plen);
//     }
//     return ret;
// }

FILE *minifat_fmemopen(void *__restrict__ buf, size_t size, const char *__restrict__ mode) {
    buf  = __minifat_uninstrument(buf);
    mode = __minifat_uninstrument(mode);
    return fmemopen(buf, size, mode);
}

FILE *minifat_fopen(const char *__restrict__ filename, const char *__restrict__ mode) {
    filename  = __minifat_uninstrument(filename);
    mode      = __minifat_uninstrument(mode);
    return fopen(filename, mode);
}

FILE *minifat_fopen64(const char *__restrict__ filename, const char *__restrict__ mode) {
    return fopen(filename, mode);
}

size_t minifat_fread(void *__restrict__ destv, size_t size, size_t nmemb, FILE *__restrict__ f) {
    destv = __minifat_uninstrument(destv);
    return fread(destv, size, nmemb, f);
}

size_t minifat_fread_unlocked(void *__restrict__ destv, size_t size, size_t nmemb, FILE *__restrict__ f) {
    return fread(destv, size, nmemb, f);
}

FILE *minifat_freopen(const char *__restrict__ filename, const char *__restrict__ mode, FILE *__restrict__ f) {
    filename  = __minifat_uninstrument(filename);
    mode      = __minifat_uninstrument(mode);
    return freopen(filename, mode, f);
}

FILE *minifat_freopen64(const char *__restrict__ filename, const char *__restrict__ mode, FILE *__restrict__ f) {
    return freopen(filename, mode, f);
}

size_t minifat_fwrite(const void *__restrict__ src, size_t size, size_t nmemb, FILE *__restrict__ f) {
    src = __minifat_uninstrument(src);
    return fwrite(src, size, nmemb, f);
}

size_t minifat_fwrite_unlocked(const void *__restrict__ src, size_t size, size_t nmemb, FILE *__restrict__ f) {
    return fwrite(src, size, nmemb, f);
}

ssize_t minifat_getdelim(char **__restrict__ s, size_t *__restrict__ n, int delim, FILE *__restrict__ f) {
    s = __minifat_uninstrument(s);
    n = __minifat_uninstrument(n);
    char* instoldss   = NULL;
    char* uninstoldss = NULL;
    if (*s) {
        instoldss = *s;
        uninstoldss =  __minifat_uninstrument(*s);
        *s = uninstoldss;
    }
    ssize_t ret = getdelim(s, n, delim, f);
    if (ret != -1 && *s != uninstoldss) {
        // *s is internally realloced, always use our memdup()
        char* oldbuf = *s;
        *s = __minifat_memdup(oldbuf, *n);
        free(oldbuf);
    } else {
        // *s is a user-supplied buffer, no need to malloc but instrument back
        *s = instoldss;
    }
    return ret;
}

ssize_t __getdelim(char **__restrict__ s, size_t *__restrict__ n, int delim, FILE *__restrict__ f) {
    return getdelim(s, n, delim, f);
}

ssize_t minifat_getline(char **__restrict__ s, size_t *__restrict__ n, FILE *__restrict__ f) {
    return getdelim(s, n, '\n', f);
}

FILE *minifat_open_memstream(char **bufp, size_t *sizep) {
    // TODO: this func is tricky because it resizes *bufp on its own;
    //       implementing its wrapper will be a huge pain
    return NULL;
}

void minifat_perror(const char *msg) {
    msg = __minifat_uninstrument(msg);
    perror(msg);
}

FILE *minifat_popen(const char *cmd, const char *mode) {
    cmd  = __minifat_uninstrument(cmd);
    mode = __minifat_uninstrument(mode);
    return popen(cmd, mode);
}

int minifat_remove(const char *path) {
    path = __minifat_uninstrument(path);
    return remove(path);
}

int minifat_rename(const char *old, const char *new) {
    old = __minifat_uninstrument(old);
    new = __minifat_uninstrument(new);
    return rename(old, new);
}

void minifat_setbuf(FILE *__restrict__ f, char *__restrict__ buf) {
    buf = __minifat_uninstrument(buf);
    setbuf(f, buf);
}

void minifat_setbuffer(FILE *f, char *buf, size_t size) {
    buf = __minifat_uninstrument(buf);
    setbuffer(f, buf, size);
}

int minifat_setvbuf(FILE *__restrict__ f, char *__restrict__ buf, int type, size_t size) {
    buf = __minifat_uninstrument(buf);
    return setvbuf(f, buf, type, size);
}

// char *minifat_tempnam(const char *dir, const char *pfx) {
//     // TODO: now it's suboptimal due to mem allocation on each call via strdup
//     dir = __minifat_uninstrument(dir);
//     pfx = __minifat_uninstrument(pfx);
//     char* ret = tempnam(dir, pfx);
//     if (!ret) return ret;
//     return __minifat_strdup(ret);
// }

// char *minifat_tmpnam(char *buf) {
//     if (!buf) {
//         static struct charbuf buf = {.lbnd = 0};
//         if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
//         char* ret = tmpnam(NULL);
//         if (!ret) return NULL;
//         strcpy(buf.buf, ret);
//         return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
//     }
//     // result will be stored in user-supplied buf, no need to strdup
//     char* bufval = __minifat_uninstrument(buf);
//     char* ret = tmpnam(bufval);
//     if (!ret) return ret;
//     return buf;
// }


/* ------------------------------------------------------------------------- */
/* ------------------------------ scanf family ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: we uninstrument only `format`, va_list will be uninstrumented
//       in vfscanf (we modified vfscanf in musl library)
int minifat_scanf(const char *__restrict__ fmt, ...);
int minifat_fscanf(FILE *__restrict__ f, const char *__restrict__ fmt, ...);
int minifat_vscanf(const char *__restrict__ fmt, va_list ap);
int minifat_vfscanf(FILE *__restrict__ f, const char *__restrict__ fmt, va_list ap);
int minifat_sscanf(const char *__restrict__ s, const char *__restrict__ fmt, ...);
int minifat_vsscanf(const char *__restrict__ s, const char *__restrict__ fmt, va_list ap);

int minifat_scanf(const char *__restrict__ fmt, ...) {
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vscanf(fmtval, ap);
    va_end(ap);
    return ret;
}

int minifat_fscanf(FILE *__restrict__ f, const char *__restrict__ fmt, ...) {
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vfscanf(f, fmtval, ap);
    va_end(ap);
    return ret;
}

int minifat_vfscanf(FILE *__restrict__ f, const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    fmt = __minifat_uninstrument((void*)fmt);
    return vfscanf(f, fmt, ap);
}

int minifat_vscanf(const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    fmt = __minifat_uninstrument((void*)fmt);
    return vscanf(fmt, ap);
}

int minifat_vsscanf(const char *__restrict__ s, const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    s   = __minifat_uninstrument((void*)s);
    fmt = __minifat_uninstrument((void*)fmt);
    return vsscanf(s, fmt, ap);
}

int minifat_sscanf(const char *__restrict__ s, const char *__restrict__ fmt, ...) {
    char* sval   = __minifat_uninstrument((void*)s);
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vsscanf(sval, fmtval, ap);
    va_end(ap);
    return ret;
}

/* ------------------------------------------------------------------------- */
/* ----------------------------- printf family ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: we uninstrument only `format`, va_list will be uninstrumented
//       in vfprintf (we modified printf_core in musl library)

int minifat_asprintf(char **s, const char *fmt, ...);
int minifat_vasprintf(char **s, const char *fmt, va_list ap);
int minifat_dprintf(int fd, const char *__restrict__ fmt, ...);
int minifat_vdprintf(int fd, const char *__restrict__ fmt, va_list ap);
int minifat_fprintf(FILE *__restrict__ f, const char *__restrict__ fmt, ...);
int minifat_snprintf(char *__restrict__ s, size_t n, const char *__restrict__ fmt, ...);
int minifat_vsnprintf(char *__restrict__ s, size_t n, const char *__restrict__ fmt, va_list ap);
int minifat_sprintf(char *__restrict__ s, const char *__restrict__ fmt, ...);
int minifat_vsprintf(char *__restrict__ s, const char *__restrict__ fmt, va_list ap);
int minifat_vprintf(const char *__restrict__ fmt, va_list ap);
int minifat_printf(const char *__restrict format, ...);
int minifat_vfprintf(FILE *__restrict f, const char *__restrict fmt, va_list ap);

#ifndef minifat_NO_ASPRINTF
int minifat_asprintf(char **s, const char *fmt, ...) {
    // TODO: now it's suboptimal because vasprintf() does internal malloc,
    //       and we need to perform our own malloc via strdup()
    char** sval  = __minifat_uninstrument(s);
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vasprintf(sval, fmtval, ap);
    va_end(ap);
    if (ret != -1) {
        char* oldbuf = *sval;
        *sval = __minifat_strdup(oldbuf);
        free(oldbuf);
    }
    return ret;
}
#endif

#ifndef minifat_NO_VASPRINTF
int minifat_vasprintf(char **s, const char *fmt, va_list ap) {
    // TODO: now it's suboptimal because vasprintf() does internal malloc,
    //       and we need to perform our own malloc via strdup()
    ap = __minifat_uninstrument((void*)ap);
    char** sval  = __minifat_uninstrument(s);
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret = vasprintf(sval, fmtval, ap);
    if (ret != -1) {
        char* oldbuf = *sval;
        *sval = __minifat_strdup(oldbuf);
        free(oldbuf);
    }
    return ret;
}
#endif

int minifat_dprintf(int fd, const char *__restrict__ fmt, ...) {
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vdprintf(fd, fmtval, ap);
    va_end(ap);
    return ret;
}

int minifat_vdprintf(int fd, const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    fmt = __minifat_uninstrument((void*)fmt);
    return vdprintf(fd, fmt, ap);
}

int minifat_fprintf(FILE *__restrict__ f, const char *__restrict__ fmt, ...) {
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vfprintf(f, fmtval, ap);
    va_end(ap);
    return ret;
}

int minifat_vfprintf(FILE *__restrict__ f, const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    fmt = __minifat_uninstrument((void*)fmt);
    return vfprintf(f, fmt, ap);
}

int minifat_snprintf(char *__restrict__ s, size_t n, const char *__restrict__ fmt, ...) {
    char* sval   = __minifat_uninstrument((void*)s);
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vsnprintf(sval, n, fmtval, ap);
    va_end(ap);
    return ret;
}

int minifat_sprintf(char *__restrict__ s, const char *__restrict__ fmt, ...) {
    char* sval   = __minifat_uninstrument((void*)s);
    char* fmtval = __minifat_uninstrument((void*)fmt);
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vsprintf(sval, fmtval, ap);
    va_end(ap);
    return ret;
}

int minifat_vprintf(const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    fmt = __minifat_uninstrument((void*)fmt);
    return vprintf(fmt, ap);
}

int minifat_vsnprintf(char *__restrict__ s, size_t n, const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    s   = __minifat_uninstrument((void*)s);
    fmt = __minifat_uninstrument((void*)fmt);
    return vsnprintf(s, n, fmt, ap);
}

int minifat_vsprintf(char *__restrict__ s, const char *__restrict__ fmt, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    s   = __minifat_uninstrument((void*)s);
    fmt = __minifat_uninstrument((void*)fmt);
    return vsprintf(s, fmt, ap);
}


int minifat_printf(const char *__restrict format, ...) {
    char* formatval = __minifat_uninstrument((void*)format);
    int ret;
    va_list ap;
    va_start(ap, format);
    ret = vfprintf(stdout, formatval, ap);
    va_end(ap);
    return ret;
}

/* ------------------------------------------------------------------------- */
/* ------------------------------- puts/gets ------------------------------- */
/* ------------------------------------------------------------------------- */
int minifat_puts(const char *s);
int minifat_fputs(const char *__restrict__ s, FILE *__restrict__ f);
int minifat_fputs_unlocked(const char *__restrict__ s, FILE *__restrict__ f);
// char *minifat_gets(char *s);
char *minifat_fgets(char *__restrict__ s, int n, FILE *__restrict__ f);
char *minifat_fgets_unlocked(char *__restrict__ s, int n, FILE *__restrict__ f);


int minifat_puts(const char *s) {
    s = __minifat_uninstrument((void*) s);
    return puts(s);
}

int minifat_fputs(const char *__restrict__ s, FILE *__restrict__ f) {
    s = __minifat_uninstrument((void*) s);
    return fputs(s, f);
}

int minifat_fputs_unlocked(const char *__restrict__ s, FILE *__restrict__ f) {
    return fputs(s, f);
}

// char *minifat_gets(char *s) {
//     char* sval = __minifat_uninstrument(s);
//     char* ret = gets(sval);
//     if (!ret) return ret;
//     return s;
// }

char *minifat_fgets(char *__restrict__ s, int n, FILE *__restrict__ f) {
    char* sval = __minifat_uninstrument(s);
    char* ret = fgets(sval, n, f);
    if (!ret) return ret;
    return s;
}

char *minifat_fgets_unlocked(char *__restrict__ s, int n, FILE *__restrict__ f) {
    return fgets(s, n, f);
}


/* ------------------------------------------------------------------------- */
/* ------------------------------- stdlib.h -------------------------------- */
/* ------------------------------------------------------------------------- */
typedef int (*cmpfun)(const void *, const void *);

int minifat_atoi(const char *s);
double minifat_atof(const char *s);
long minifat_atol(const char *s);
long long minifat_atoll(const char *s);

// TODO: bsearch ecvt fcvt gcvt ???
void minifat_qsort(void *base, size_t nel, size_t width, cmpfun cmp);

float minifat_strtof(const char *__restrict__ s, char **__restrict__ p);
double minifat_strtod(const char *__restrict__ s, char **__restrict__ p);
long double minifat_strtold(const char *__restrict__ s, char **__restrict__ p);
long minifat_strtol(const char *__restrict__ s, char **__restrict__ p, int base);
long long minifat_strtoll(const char *__restrict__ s, char **__restrict__ p, int base);
unsigned long minifat_strtoul(const char *restrict s, char **restrict p, int base);
unsigned long long minifat_strtoull(const char *restrict s, char **restrict p, int base);
intmax_t minifat_strtoimax(const char *__restrict__ s, char **__restrict__ p, int base);
uintmax_t minifat_strtoumax(const char *__restrict__ s, char **__restrict__ p, int base);

char *minifat_gcvt(double x, int n, char *b);
char *minifat_ecvt(double x, int n, int *dp, int *sign);
char *minifat_fcvt(double x, int n, int *dp, int *sign);

int minifat_atoi(const char *s) {
    s = __minifat_uninstrument((void*) s);
    return atoi(s);
}

double minifat_atof(const char *s) {
    s = __minifat_uninstrument((void*) s);
    return atof(s);
}

long minifat_atol(const char *s) {
    s = __minifat_uninstrument((void*) s);
    return atol(s);
}

long long minifat_atoll(const char *s)
{
    s = __minifat_uninstrument((void*) s);
    return atoll(s);
}

// TODO: bsearch ecvt fcvt gcvt ???

static __thread PTRTYPE qsort_ubnd;
static __thread cmpfun  qsort_cmp;

static int minifat_qsort_cmp(const void *v1, const void *v2) {
   v1 = __minifat_combine_ptr(v1, qsort_ubnd);
   v2 = __minifat_combine_ptr(v2, qsort_ubnd);
   return qsort_cmp(v1, v2);
}

void minifat_qsort(void *base, size_t nel, size_t width, cmpfun cmp) {
    // memorize ubnd of base and the real cmp function supplied by user
    qsort_ubnd = __minifat_extract_ubnd(base);
    qsort_cmp = cmp;
    // continue with real uninstrumented qsort(); it will call qsort_cmp
    // which instruments v1 and v2 with qsort_ubnd and forward to real cmp
    base = __minifat_uninstrument(base);
    qsort(base, nel, width, qsort_cmp);
}

float minifat_strtof(const char *__restrict__ s, char **__restrict__ p) {
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    float ret = strtof(sval, p);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

double minifat_strtod(const char *__restrict__ s, char **__restrict__ p) {
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    double ret = strtod(sval, p);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

long double minifat_strtold(const char *__restrict__ s, char **__restrict__ p) {
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    long double ret = strtold(sval, p);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

float minifat_strtof_l(const char *__restrict__ s, char **__restrict__ p) {
    return strtof(s, p);
}

double minifat_strtod_l(const char *__restrict__ s, char **__restrict__ p) {
    return strtod(s, p);
}

long double minifat_strtold_l(const char *__restrict__ s, char **__restrict__ p) {
    return strtold(s, p);
}

long minifat_strtol(const char *__restrict__ s, char **__restrict__ p, int base)
{
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    long ret = strtol(sval, p, base);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

long long minifat_strtoll(const char *__restrict__ s, char **__restrict__ p, int base)
{
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    long long ret = strtoll(sval, p, base);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

unsigned long minifat_strtoul(const char *restrict s, char **restrict p, int base) {
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    unsigned long ret = strtoul(sval, p, base);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

unsigned long long minifat_strtoull(const char *restrict s, char **restrict p, int base) {
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    unsigned long long ret = strtoull(sval, p, base);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}


intmax_t minifat_strtoimax(const char *__restrict__ s, char **__restrict__ p, int base)
{
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    intmax_t ret = strtoimax(sval, p, base);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

uintmax_t minifat_strtoumax(const char *__restrict__ s, char **__restrict__ p, int base)
{
    char* sval = __minifat_uninstrument((void*) s);
    if (p)
        p = (char **) __minifat_uninstrument((void*) p);
    uintmax_t ret = strtoumax(sval, p, base);
    if (p) {
        // *p points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        *p = __minifat_combine_ptr(*p, ubnd);
    }
    return ret;
}

char *minifat_gcvt(double x, int n, char *b) {
    char* bval = __minifat_uninstrument((void*) b);
    gcvt(x, n, bval);
    return b;
}

char *minifat_ecvt(double x, int n, int *dp, int *sign) {
    dp   = __minifat_uninstrument((void*) dp);
    sign = __minifat_uninstrument((void*) sign);
    PTRTYPE ubnd = __minifat_highest_bound();  // NOTE: not the best solution
    char* ret = ecvt(x, n, dp, sign);
    ret = __minifat_combine_ptr(ret, ubnd);
    return ret;
}

char *minifat_fcvt(double x, int n, int *dp, int *sign) {
    dp   = __minifat_uninstrument((void*) dp);
    sign = __minifat_uninstrument((void*) sign);
    PTRTYPE ubnd = __minifat_highest_bound();  // NOTE: not the best solution
    char* ret = fcvt(x, n, dp, sign);
    ret = __minifat_combine_ptr(ret, ubnd);
    return ret;
}


/* ------------------------------------------------------------------------- */
/* ----------------------------- time funcs -------------------------------- */
/* ------------------------------------------------------------------------- */
struct timecharbuf {
    char buf[26];
    PTRTYPE lbnd;
};

struct timetmbuf {
    struct tm buf;
    PTRTYPE lbnd;
};

char *minifat_asctime(const struct tm *tm);
char *minifat_asctime_r(const struct tm *__restrict__ tm, char *__restrict__ buf);
int minifat_clock_getcpuclockid(pid_t pid, clockid_t *clk);
int minifat_clock_getres(clockid_t clk, struct timespec *ts);
int minifat_clock_gettime(clockid_t clk, struct timespec *ts);
int minifat_clock_nanosleep(clockid_t clk, int flags, const struct timespec *req, struct timespec *rem);
int minifat_clock_settime(clockid_t clk, const struct timespec *ts);
char *minifat_ctime(const time_t *t);
char *minifat_ctime_r(const time_t *t, char *buf);
int minifat_ftime(struct timeb *tp);
struct tm *minifat_getdate(const char *s);
int minifat_gettimeofday(struct timeval *__restrict__ tv, void *__restrict__ tz);
struct tm *minifat_gmtime(const time_t *t);
struct tm *minifat_gmtime_r(const time_t *__restrict__ t, struct tm *__restrict__ tm);
struct tm *minifat_localtime(const time_t *t);
struct tm *minifat_localtime_r(const time_t *__restrict__ t, struct tm *__restrict__ tm);
time_t minifat_mktime(struct tm *tm);
int minifat_nanosleep(const struct timespec *req, struct timespec *rem);
size_t minifat_strftime(char *__restrict__ s, size_t n, const char *__restrict__ f, const struct tm *__restrict__ tm);
size_t minifat_strftime_l(char *__restrict__ s, size_t n, const char *__restrict__ f, const struct tm *__restrict__ tm, locale_t loc);
char *minifat_strptime(const char *__restrict__ s, const char *__restrict__ f, struct tm *__restrict__ tm);
time_t minifat_time(time_t *t);
time_t minifat_timegm(struct tm *tm);
int minifat_timer_create(clockid_t clk, struct sigevent *__restrict__ evp, timer_t *__restrict__ res);
int minifat_timer_gettime(timer_t t, struct itimerspec *val);
int minifat_timer_settime(timer_t t, int flags, const struct itimerspec *__restrict__ val, struct itimerspec *__restrict__ old);
clock_t minifat_times(struct tms *tms);
int minifat_timespec_get(struct timespec * ts, int base);
int minifat_utime(const char *path, const struct utimbuf *times);


char *minifat_asctime(const struct tm *tm) {
    static struct timecharbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;

    tm = __minifat_uninstrument((void*) tm);
    char* ret = asctime(tm);
    if (!ret) return ret;
    strncpy(buf.buf, ret, 26);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

char *minifat_asctime_r(const struct tm *__restrict__ tm, char *__restrict__ buf) {
    tm = __minifat_uninstrument((void*) tm);
    char* bufval = __minifat_uninstrument((void*) buf);
    char* ret = asctime_r(tm, bufval);
    if (!ret) return ret;
    return buf;
}

int minifat_clock_getcpuclockid(pid_t pid, clockid_t *clk) {
    clk = __minifat_uninstrument(clk);
    return clock_getcpuclockid(pid, clk);
}

int minifat_clock_getres(clockid_t clk, struct timespec *ts) {
    if (ts) {
        ts = __minifat_uninstrument(ts);
    }
    return clock_getres(clk, ts);
}

int minifat_clock_gettime(clockid_t clk, struct timespec *ts) {
    ts = __minifat_uninstrument(ts);
    return clock_gettime(clk, ts);
}

int minifat_clock_nanosleep(clockid_t clk, int flags, const struct timespec *req, struct timespec *rem) {
    if (req) {
        req = __minifat_uninstrument(req);
    }
    if (rem) {
        rem = __minifat_uninstrument(rem);
    }
    return clock_nanosleep(clk, flags, req, rem);
}

int minifat_clock_settime(clockid_t clk, const struct timespec *ts) {
    ts = __minifat_uninstrument(ts);
    return clock_settime(clk, ts);
}

char *minifat_ctime(const time_t *t) {
    static struct timecharbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;

    t = __minifat_uninstrument((void*) t);
    char* ret = ctime(t);
    if (!ret) return ret;
    strncpy(buf.buf, ret, 26);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

char *minifat_ctime_r(const time_t *t, char *buf) {
    t = __minifat_uninstrument((void*) t);
    char* bufval = __minifat_uninstrument(buf);
    char* ret = ctime_r(t, bufval);
    if (!ret) return ret;
    return buf;
}

int minifat_ftime(struct timeb *tp) {
    tp = __minifat_uninstrument((void*) tp);
    return ftime(tp);
}

struct tm *minifat_getdate(const char *s) {
    static struct timetmbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;

    s = __minifat_uninstrument((void*) s);
    struct tm* ret = getdate(s);
    if (!ret) return ret;
    memcpy(&buf.buf, ret, sizeof(struct tm));
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

int minifat_gettimeofday(struct timeval *__restrict__ tv, void *__restrict__ tz) {
    if (tv) {
        tv = __minifat_uninstrument(tv);
    }
    if (tz) {
        tz = __minifat_uninstrument(tz);
    }
    return gettimeofday(tv, tz);
}

struct tm *minifat_gmtime(const time_t *t) {
    static struct timetmbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;

    t = __minifat_uninstrument((void*) t);
    struct tm* ret = gmtime(t);
    if (!ret) return ret;
    memcpy(&buf.buf, ret, sizeof(struct tm));
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

struct tm *minifat_gmtime_r(const time_t *__restrict__ t, struct tm *__restrict__ tm) {
    t  = __minifat_uninstrument((void*) t);
    struct tm *tmval = __minifat_uninstrument((void*) tm);
    struct tm *ret = gmtime_r(t, tmval);
    if (!ret) return ret;
    return tm;
}

struct tm *minifat_localtime(const time_t *t) {
    static struct timetmbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;

    t = __minifat_uninstrument((void*) t);
    struct tm* ret = localtime(t);
    if (!ret) return ret;
    memcpy(&buf.buf, ret, sizeof(struct tm));
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

struct tm *minifat_localtime_r(const time_t *__restrict__ t, struct tm *__restrict__ tm) {
    t  = __minifat_uninstrument((void*) t);
    struct tm *tmval = __minifat_uninstrument((void*) tm);
    struct tm *ret = localtime_r(t, tmval);
    if (!ret) return ret;
    return tm;
}

time_t minifat_mktime(struct tm *tm) {
    tm = __minifat_uninstrument((void*) tm);
    return mktime(tm);
}

int minifat_nanosleep(const struct timespec *req, struct timespec *rem) {
    if (req) {
        req = __minifat_uninstrument(req);
    }
    if (rem) {
        rem = __minifat_uninstrument(rem);
    }
    return nanosleep(req, rem);
}

size_t minifat_strftime(char *__restrict__ s, size_t n, const char *__restrict__ f, const struct tm *__restrict__ tm) {
    s  = __minifat_uninstrument(s);
    f  = __minifat_uninstrument(f);
    tm = __minifat_uninstrument(tm);
    return strftime(s, n, f, tm);
}

size_t minifat_strftime_l(char *__restrict__ s, size_t n, const char *__restrict__ f, const struct tm *__restrict__ tm, locale_t loc) {
    s  = __minifat_uninstrument(s);
    f  = __minifat_uninstrument(f);
    tm = __minifat_uninstrument(tm);
    return strftime_l(s, n, f, tm, loc);
}

char *minifat_strptime(const char *__restrict__ s, const char *__restrict__ f, struct tm *__restrict__ tm) {
    char* sval  = __minifat_uninstrument(s);
    f  = __minifat_uninstrument(f);
    tm = __minifat_uninstrument(tm);
    char* ptr = strptime(sval, f, tm);
    if (ptr) {
        // ptr points into s, so it has the same bounds as s
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ptr = __minifat_combine_ptr(ptr, ubnd);
    }
    return ptr;
}

time_t minifat_time(time_t *t) {
    if (t) {
        t = __minifat_uninstrument(t);
    }
    return time(t);
}

time_t minifat_timegm(struct tm *tm) {
    if (tm) {
        tm = __minifat_uninstrument(tm);
    }
    return timegm(tm);
}

int minifat_timer_create(clockid_t clk, struct sigevent *__restrict__ evp, timer_t *__restrict__ res) {
    // TODO: we do not support signals...
    return -1;
}

int minifat_timer_gettime(timer_t t, struct itimerspec *val) {
    if (val) {
        val = __minifat_uninstrument(val);
    }
    return timer_gettime(t, val);
}

int minifat_timer_settime(timer_t t, int flags, const struct itimerspec *__restrict__ val, struct itimerspec *__restrict__ old) {
    if (val) {
        val = __minifat_uninstrument(val);
    }
    if (old) {
        old = __minifat_uninstrument(old);
    }
    return timer_settime(t, flags, val, old);
}

clock_t minifat_times(struct tms *tms) {
    tms = __minifat_uninstrument(tms);
    return times(tms);
}

int minifat_timespec_get(struct timespec * ts, int base) {
    ts = __minifat_uninstrument(ts);
    return timespec_get(ts, base);
}

int minifat_utime(const char *path, const struct utimbuf *times) {
    path = __minifat_uninstrument(path);
    if (times) {
        times = __minifat_uninstrument(times);
    }
    return utime(path, times);
}

/* ------------------------------------------------------------------------- */
/* ------------------------------ env funcs -------------------------------- */
/* ------------------------------------------------------------------------- */
char *minifat_getenv(const char *name);
int minifat_putenv(char *s);
int minifat_setenv(const char *var, const char *value, int overwrite);
int minifat_unsetenv(const char *name);

char *minifat_getenv(const char *name) {
    // TODO: now it's suboptimal due to mem allocation on each call via strdup
    name = __minifat_uninstrument(name);
    char* tmp = getenv(name);
    if (!tmp) return NULL;
    return __minifat_strdup(tmp);
}

int minifat_putenv(char *s) {
    s = __minifat_uninstrument(s);
    return putenv(s);
}

int minifat_setenv(const char *var, const char *value, int overwrite) {
    var = __minifat_uninstrument(var);
    value = __minifat_uninstrument(value);
    return setenv(var, value, overwrite);
}

int minifat_unsetenv(const char *name) {
    name = __minifat_uninstrument(name);
    return unsetenv(name);
}

/* ------------------------------------------------------------------------- */
/* ----------------------------- stat funcs -------------------------------- */
/* ------------------------------------------------------------------------- */
int minifat_chmod(const char *path, mode_t mode);
int minifat_fchmodat(int fd, const char *path, mode_t mode, int flag);
int minifat_fstat(int fd, struct stat *st);
int minifat_fstat64(int fd, struct stat *st);
int minifat_fstatat(int fd, const char *__restrict__ path, struct stat *__restrict__ buf, int flag);
int minifat_fstatat64(int fd, const char *__restrict__ path, struct stat *__restrict__ buf, int flag);
int minifat_futimens(int fd, const struct timespec times[2]);
int minifat_futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
// int minifat_lchmod(const char *path, mode_t mode);
int minifat_lstat(const char *__restrict__ path, struct stat *__restrict__ buf);
int minifat_lstat64(const char *__restrict__ path, struct stat *__restrict__ buf);
int minifat_mkdir(const char *path, mode_t mode);
int minifat_mkdirat(int fd, const char *path, mode_t mode);
int minifat_mkfifo(const char *path, mode_t mode);
int minifat_mkfifoat(int fd, const char *path, mode_t mode);
int minifat_mknod(const char *path, mode_t mode, dev_t dev);
int minifat_mknodat(int fd, const char *path, mode_t mode, dev_t dev);
int minifat_stat(const char *__restrict__ path, struct stat *__restrict__ buf);
int minifat_stat64(const char *__restrict__ path, struct stat *__restrict__ buf);
int minifat_statfs(const char *path, struct statfs *buf);
int minifat_statfs64(const char *path, struct statfs *buf);
int minifat_fstatfs(int fd, struct statfs *buf);
int minifat_fstatfs64(int fd, struct statfs *buf);
int minifat_statvfs(const char *__restrict__ path, struct statvfs *__restrict__ buf);
int minifat_statvfs64(const char *__restrict__ path, struct statvfs *__restrict__ buf);
int minifat_fstatvfs(int fd, struct statvfs *buf);
int minifat_fstatvfs64(int fd, struct statvfs *buf);
int minifat_utimensat(int fd, const char *path, const struct timespec times[2], int flags);

int minifat_chmod(const char *path, mode_t mode) {
    path = __minifat_uninstrument(path);
    return chmod(path, mode);
}

int minifat_fchmodat(int fd, const char *path, mode_t mode, int flag) {
    path = __minifat_uninstrument(path);
    return fchmodat(fd, path, mode, flag);
}

int minifat_fstat(int fd, struct stat *st) {
    st = __minifat_uninstrument(st);
    return fstat(fd, st);
}

int minifat_fstat64(int fd, struct stat *st) {
    return fstat(fd, st);
}

int minifat_fstatat(int fd, const char *__restrict__ path, struct stat *__restrict__ buf, int flag) {
    path = __minifat_uninstrument(path);
    buf = __minifat_uninstrument(buf);
    return fstatat(fd, path, buf, flag);
}

int minifat_fstatat64(int fd, const char *__restrict__ path, struct stat *__restrict__ buf, int flag) {
    return fstatat(fd, path, buf, flag);
}

int minifat_futimens(int fd, const struct timespec times[2]) {
    struct timespec* timesval = (struct timespec*)__minifat_uninstrument((void*) times);
    return futimens(fd, timesval);
}

int minifat_futimesat(int dirfd, const char *pathname, const struct timeval times[2]) {
    pathname = __minifat_uninstrument(pathname);
    struct timeval* timesval = (struct timeval*)__minifat_uninstrument((void*) times);
    return futimesat(dirfd, pathname, timesval);
}

// int minifat_lchmod(const char *path, mode_t mode) {
//     path = __minifat_uninstrument(path);
//     return lchmod(path, mode);
// }

int minifat_lstat(const char *__restrict__ path, struct stat *__restrict__ buf) {
    path = __minifat_uninstrument(path);
    buf = __minifat_uninstrument(buf);
    return lstat(path, buf);
}

int minifat_lstat64(const char *__restrict__ path, struct stat *__restrict__ buf) {
    return lstat(path, buf);
}

int minifat_mkdir(const char *path, mode_t mode) {
    path = __minifat_uninstrument(path);
    return mkdir(path, mode);
}

int minifat_mkdirat(int fd, const char *path, mode_t mode) {
    path = __minifat_uninstrument(path);
    return mkdirat(fd, path, mode);
}

int minifat_mkfifo(const char *path, mode_t mode) {
    path = __minifat_uninstrument(path);
    return mkfifo(path, mode);
}

int minifat_mkfifoat(int fd, const char *path, mode_t mode) {
    path = __minifat_uninstrument(path);
    return mkfifoat(fd, path, mode);
}

int minifat_mknod(const char *path, mode_t mode, dev_t dev) {
    path = __minifat_uninstrument(path);
    return mknod(path, mode, dev);
}

int minifat_mknodat(int fd, const char *path, mode_t mode, dev_t dev) {
    path = __minifat_uninstrument(path);
    return mknodat(fd, path, mode, dev);
}

int minifat_stat(const char *__restrict__ path, struct stat *__restrict__ buf) {
    path = __minifat_uninstrument(path);
    buf = __minifat_uninstrument(buf);
    return stat(path, buf);
}

int minifat_stat64(const char *__restrict__ path, struct stat *__restrict__ buf) {
    return stat(path, buf);
}

int minifat_statfs(const char *path, struct statfs *buf) {
    path = __minifat_uninstrument(path);
    buf = __minifat_uninstrument(buf);
    return statfs(path, buf);
}

int minifat_statfs64(const char *path, struct statfs *buf) {
    return statfs(path, buf);
}

int minifat_fstatfs(int fd, struct statfs *buf) {
    buf = __minifat_uninstrument(buf);
    return fstatfs(fd, buf);
}

int minifat_fstatfs64(int fd, struct statfs *buf) {
    return fstatfs(fd, buf);
}

int minifat_statvfs(const char *__restrict__ path, struct statvfs *__restrict__ buf) {
    path = __minifat_uninstrument(path);
    buf = __minifat_uninstrument(buf);
    return statvfs(path, buf);
}

int minifat_statvfs64(const char *__restrict__ path, struct statvfs *__restrict__ buf) {
    return statvfs(path, buf);
}

int minifat_fstatvfs(int fd, struct statvfs *buf) {
    buf = __minifat_uninstrument(buf);
    return fstatvfs(fd, buf);
}

int minifat_fstatvfs64(int fd, struct statvfs *buf) {
    return fstatvfs(fd, buf);
}

int minifat_utimensat(int fd, const char *path, const struct timespec times[2], int flags) {
    path = __minifat_uninstrument(path);
    struct timespec* timesval = (struct timespec*)__minifat_uninstrument((void*) times);
    return utimensat(fd, path, timesval, flags);
}

/* ------------------------------------------------------------------------- */
/* ------------------------------- exit funcs  ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: we do not instrument function ptrs, thus we do not uninstrument
//       arguments such as void (*func)(void *)

int minifat___cxa_atexit(void (*func)(void *), void *arg, void *dso);
void minifat___assert_fail(const char *expr, const char *file, int line, const char *func);

int minifat___cxa_atexit(void (*func)(void *), void *arg, void *dso) {
#if 0
    // TODO: args and dso can contain ptrs within, must uninstrument them?
    arg = __minifat_uninstrument(arg);
    dso = __minifat_uninstrument(dso);
#endif
    return __cxa_atexit(func, arg, dso);
}

void minifat___assert_fail(const char *expr, const char *file, int line, const char *func) {
    expr = __minifat_uninstrument(expr);
    file = __minifat_uninstrument(file);
    if (func)
        func = __minifat_uninstrument(func);
    __assert_fail(expr, file, line, func);
}

/* ------------------------------------------------------------------------- */
/* ------------------------------- prng funcs  ----------------------------- */
/* ------------------------------------------------------------------------- */
struct seed48buf {
    unsigned short buf[7];
    PTRTYPE lbnd;
};

double minifat_erand48(unsigned short s[3]);
void minifat_lcong48(unsigned short p[7]);
long minifat_nrand48(unsigned short s[3]);
long minifat_jrand48(unsigned short s[3]);
int minifat_rand_r(unsigned *seed);
// unsigned short *minifat_seed48(unsigned short *s);

double minifat_erand48(unsigned short s[3]) {
    unsigned short* sval = (unsigned short*)__minifat_uninstrument((void*) s);
    return erand48(sval);
}

void minifat_lcong48(unsigned short p[7]) {
    unsigned short* pval = (unsigned short*)__minifat_uninstrument((void*) p);
    lcong48(pval);
}

long minifat_nrand48(unsigned short s[3]) {
    unsigned short* sval = (unsigned short*)__minifat_uninstrument((void*) s);
    return nrand48(sval);
}

long minifat_jrand48(unsigned short s[3]) {
    unsigned short* sval = (unsigned short*)__minifat_uninstrument((void*) s);
    return jrand48(sval);
}

// TODO: initstate() and setstate() from random.c operate on internal char*, ignoring them for now

int minifat_rand_r(unsigned *seed) {
    seed = __minifat_uninstrument(seed);
    return rand_r(seed);
}

extern unsigned short __seed48[7];

// unsigned short *minifat_seed48(unsigned short *s) {
//     static struct seed48buf buf = {.lbnd = 0};
//     if (buf.lbnd == 0) {
//         memcpy(&buf.buf, __seed48, sizeof(buf.buf));
//         buf.lbnd = (PTRTYPE)&buf;
//     }
//     s = __minifat_uninstrument((void*) s);
//     if ((void*)s == (void*)&buf) {
//         // corner-case when user calls something like `seed = seed48(seed)` ->
//         //   this means that the underlying __seed48 is supposed to be used
//         memcpy(&buf.buf, __seed48, sizeof(buf.buf));
//     }
//     unsigned short * ret = seed48(s);
//     if (!ret) return ret;
//     memcpy(&buf.buf, ret, sizeof(unsigned short)*3);
//     return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
// }

/* ------------------------------------------------------------------------- */
/* ----------------------------- dirent funcs  ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: struct DIR* is opaque and must never be dereferenced; we use this
//       feature and do not instrument DIR* pointers -- leaving them with
//       NULL (always-failing) bounds, such that any attempt to deref them
//       leads to segfault on address `0`.
//       E.g., opendir() returns DIR* ptr -- we must not instrument this ptr.

struct direntbuf {
    struct dirent buf;
    PTRTYPE lbnd;
};

// int minifat_getdents(int fd, struct dirent *buf, size_t len);
// int minifat_getdents64(int fd, struct dirent *buf, size_t len);
DIR *minifat_opendir(const char *name);
struct dirent *minifat_readdir(DIR *dir);
struct dirent *minifat_readdir64(DIR *dir);
int minifat_readdir_r(DIR *__restrict__ dir, struct dirent *__restrict__ buf, struct dirent **__restrict__ result);
int minifat_readdir64_r(DIR *__restrict__ dir, struct dirent *__restrict__ buf, struct dirent **__restrict__ result);

// int minifat_getdents(int fd, struct dirent *buf, size_t len) {
//     buf = __minifat_uninstrument((void*) buf);
//     return getdents(fd, buf, len);
// }

// int minifat_getdents64(int fd, struct dirent *buf, size_t len) {
//     return getdents(fd, buf, len);
// }

DIR *minifat_opendir(const char *name) {
    name = __minifat_uninstrument(name);
    return opendir(name);
}

struct dirent *minifat_readdir(DIR *dir) {
    static struct direntbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    struct dirent *ret = readdir(dir);
    if (!ret) return ret;
    memcpy(&buf.buf, ret, sizeof(struct dirent));
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

struct dirent *minifat_readdir64(DIR *dir) {
    return readdir(dir);
}

int minifat_readdir_r(DIR *__restrict__ dir, struct dirent *__restrict__ buf, struct dirent **__restrict__ result) {
    struct dirent *bufval = __minifat_uninstrument(buf);
    result = __minifat_uninstrument(result);
    int ret = readdir_r(dir, bufval, result);
    if (*result) {
        *result = buf;
    }
    return ret;
}

int minifat_readdir64_r(DIR *__restrict__ dir, struct dirent *__restrict__ buf, struct dirent **__restrict__ result) {
    return readdir_r(dir, buf, result);
}

// NOTE: we do not instrument alphasort() and versionsort() because they are
//       supposed to be used *only* via scandir()
int minifat_versionsort(const struct dirent **a, const struct dirent **b);
int minifat_alphasort(const struct dirent **a, const struct dirent **b);

// need this wrapper around `struct dirent` because we need to memorize
// length for future minifat-instrumentation and survive swapping via qsort()
struct direntlen {
    struct dirent *d;
    PTRTYPE l;
};

int *minifat___errno_location(void);

int minifat_scandir(const char *path, struct dirent ***res,
    int (*sel)(const struct dirent *),
    int (*cmp)(const struct dirent **, const struct dirent **))
{
    // we completely re-implement scandir because it allocates `res` internally
    // in general, we use  versions of funcs, but malloc PTRSIZE more bytes
    // we also take care that sel() func receives instrumented argument
    path = __minifat_uninstrument(path);
    res  = __minifat_uninstrument(res);

    DIR *d = opendir(path);
    struct dirent *de;
    struct direntlen *names=0, *tmp;
    size_t cnt=0, len=0, i;
    int* errno_addr = minifat___errno_location();
    int old_errno = *errno_addr;

    if (!d) return -1;

    while ((*errno_addr=0), (de = readdir(d))) {
        if (sel && !sel(de)) continue;
        if (cnt >= len) {
            len = 2*len+1;
            if (len > SIZE_MAX/sizeof *names) break;
            tmp = realloc(names, len * sizeof *names);
            if (!tmp) break;
            names = tmp;
        }
        struct dirent *deval = __minifat_uninstrument(de);
        names[cnt].d = malloc(deval->d_reclen + PTRSIZE);
        names[cnt].l = deval->d_reclen;
        if (!names[cnt].d) break;
        memcpy(names[cnt++].d, deval, deval->d_reclen);
    }

    closedir(d);

    if (*errno_addr) {
        if (names) while (cnt-->0) free(names[cnt].d);
        free(names);
        return -1;
    }
    *errno_addr = old_errno;

    if (cmp) {
        assert(cmp == alphasort || cmp == versionsort); // we support only these two for now
        qsort(names, cnt, sizeof *names, (int (*)(const void *, const void *))cmp);
    }

    // instrument final *res and all its items (of type struct dirent*) with minifat
    *res = 0;
    if (names) {
        *res = malloc(cnt * sizeof(struct dirent *) + PTRSIZE);
        if (!*res) return -1;
        for (i = 0; i < cnt; i++) {
            (*res)[i] = minifat_specifybounds(names[i].d, names[i].l);
        }
        *res = minifat_specifybounds(*res, cnt * sizeof(struct dirent *));
        free(names);
    }

    return cnt;
}

int minifat_scandir64(const char *path, struct dirent ***res,
    int (*sel)(const struct dirent *),
    int (*cmp)(const struct dirent **, const struct dirent **))
{
    return minifat_scandir(path, res, sel, cmp);
}

/* ------------------------------------------------------------------------- */
/* ----------------------------- setjmp/longjmp ---------------------------- */
/* ------------------------------------------------------------------------- */
int setjmp(jmp_buf);
_Noreturn void longjmp(jmp_buf, int);

int minifat_setjmp(jmp_buf b) {
    b = __minifat_uninstrument(b);
    return setjmp(b);
}

_Noreturn void minifat_longjmp(jmp_buf b, int i) {
    b = __minifat_uninstrument(b);
    longjmp(b, i);
}

/* ------------------------------------------------------------------------- */
/* ------------------------------- misc funcs  ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: ignoring openpty, login_tty, forkpty, ptsname, ptsname_r, wordexp

long minifat_a64l(const char *s);
char *minifat_l64a(long x0);
char *minifat_basename(char *s);
char *minifat_dirname(char *s);
int minifat_fmtmsg(long classification, const char *label, int severity, const char *text, const char *action, const char *tag);
char *minifat_get_current_dir_name(void);
int minifat_getdomainname(char *name, size_t len);
int minifat_getopt(int argc, char * const argv[], const char *optstring);
int minifat_getopt_long(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx);
int minifat_getopt_long_only(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx);
int minifat_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
int minifat_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
int minifat_getrlimit(int resource, struct rlimit *rlim);
int minifat_getrlimit64(int resource, struct rlimit *rlim);
int minifat_getrusage(int who, struct rusage *ru);
int minifat_getsubopt(char **opt, char *const *keys, char **val);
int minifat_initgroups(const char *user, gid_t gid);
FILE *minifat_setmntent(const char *name, const char *mode);
struct mntent *minifat_getmntent_r(FILE *f, struct mntent *mnt, char *linebuf, int buflen);
struct mntent *minifat_getmntent(FILE *f);
int minifat_addmntent(FILE *f, const struct mntent *mnt);
char *minifat_hasmntopt(const struct mntent *mnt, const char *opt);
int minifat_nftw(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags);
int minifat_nftw64(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags);
char *minifat_realpath(const char *restrict filename, char *restrict resolved);
int minifat_setdomainname(const char *name, size_t len);
int minifat_setrlimit(int resource, const struct rlimit *rlim);
int minifat_setrlimit64(int resource, const struct rlimit *rlim);
void minifat_openlog(const char *ident, int opt, int facility);
void minifat_syslog(int priority, const char *message, ...);
void minifat_vsyslog(int priority, const char *message, va_list ap);
int minifat_uname(struct utsname *uts);
int minifat_ioctl(int fd, int req, ...);

long minifat_a64l(const char *s) {
    s = __minifat_uninstrument(s);
    return a64l(s);
}

struct smallcharbuf {
    char buf[7];
    PTRTYPE lbnd;
};

char *minifat_l64a(long x0) {
    static struct smallcharbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    char* ret = l64a(x0);
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

char *minifat_basename(char *s) {
    char* sval = NULL;
    if (s)  sval = __minifat_uninstrument(s);
    char* ret = basename(sval);
    if (strlen(ret) == 1 && ret[0] == '.') {
        // returned constant string "."
        static struct smallcharbuf buf = {.lbnd = 0};
        if (buf.lbnd == 0) {
            buf.lbnd = (PTRTYPE)&buf;
            strcpy(buf.buf, ".");
        }
        ret = __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
    } else {
        // ret points into s, so uses its bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

char *minifat_dirname(char *s) {
    char* sval = NULL;
    if (s)  sval = __minifat_uninstrument(s);
    char* ret = dirname(sval);
    if (strlen(ret) == 1 && ret[0] == '.') {
        // returned constant string "."
        static struct smallcharbuf buf = {.lbnd = 0};
        if (buf.lbnd == 0) {
            buf.lbnd = (PTRTYPE)&buf;
            strcpy(buf.buf, ".");
        }
        ret = __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
    } else if (strlen(ret) == 1 && ret[0] == '/') {
        // returned constant string "/"
        static struct smallcharbuf buf = {.lbnd = 0};
        if (buf.lbnd == 0) {
            buf.lbnd = (PTRTYPE)&buf;
            strcpy(buf.buf, "/");
        }
        ret = __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
    } else {
        // ret points into s, so uses its bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(s);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_fmtmsg(long classification, const char *label, int severity,
           const char *text, const char *action, const char *tag) {
    label  = __minifat_uninstrument(label);
    text   = __minifat_uninstrument(text);
    action = __minifat_uninstrument(action);
    tag    = __minifat_uninstrument(tag);
    return fmtmsg(classification, label, severity, text, action, tag);
}

char *minifat_get_current_dir_name(void) {
    // use tmp for real func and copy it using our instrumented version of strdup
    char* tmp = get_current_dir_name();
    char* ret =__minifat_strdup(tmp);
    free(tmp);
    return ret;
}

int minifat_getdomainname(char *name, size_t len) {
    name = __minifat_uninstrument(name);
    return getdomainname(name, len);
}

extern char* optarg;
int minifat_getopt(int argc, char * const argv[], const char *optstring) {
    char** inargv = malloc(sizeof(char*) * argc);
    optstring = __minifat_uninstrument(optstring);
    argv = __minifat_uninstrument(argv);
    for (int i=0; i<argc; i++)
        inargv[i] = __minifat_uninstrument(argv[i]);
    int ret = getopt(argc, inargv, optstring);
    if (ret != -1 && optarg) {
        PTRTYPE ubnd = __minifat_highest_bound();
        optarg = __minifat_combine_ptr(optarg, ubnd);
    }
    free(inargv);
    return ret;
}

int minifat_getopt_long(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx) {
    static struct option inlongopts[128];
    struct option *inlongoptsptr = NULL;

    char** inargv = malloc(sizeof(char*) * argc);
    optstring = __minifat_uninstrument(optstring);
    if (longopts) {
        longopts = __minifat_uninstrument(longopts);
        inlongoptsptr = &inlongopts[0];

        int i = 0;
        while (longopts[i].name) {
            inlongopts[i].name    = __minifat_uninstrument(longopts[i].name);
            inlongopts[i].flag    = __minifat_uninstrument(longopts[i].flag);
            inlongopts[i].has_arg = longopts[i].has_arg;
            inlongopts[i].val     = longopts[i].val;
            i++;
        }
        inlongopts[i].name = NULL;
        inlongopts[i].flag = NULL;
        inlongopts[i].has_arg = inlongopts[i].val = 0;
    }
    if (idx)
        idx = __minifat_uninstrument(idx);

    argv = __minifat_uninstrument(argv);
    for (int i=0; i<argc; i++)
        inargv[i] = __minifat_uninstrument(argv[i]);
    int ret = getopt_long(argc, inargv, optstring, inlongoptsptr, idx);
    if (ret != -1 && optarg) {
        PTRTYPE ubnd = __minifat_highest_bound();
        optarg = __minifat_combine_ptr(optarg, ubnd);
    }
    free(inargv);
    return ret;
}

#ifndef minifat_NO_GETOPTLONGONLY
int minifat_getopt_long_only(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx) {
    // NOTE: must be identical to getopt_long but calling another real func
    static struct option inlongopts[128];
    struct option *inlongoptsptr = NULL;

    char** inargv = malloc(sizeof(char*) * argc);
    optstring = __minifat_uninstrument(optstring);
    if (longopts) {
        longopts = __minifat_uninstrument(longopts);
        inlongoptsptr = &inlongopts[0];

        int i = 0;
        while (longopts[i].name) {
            inlongopts[i].name    = __minifat_uninstrument(longopts[i].name);
            inlongopts[i].flag    = __minifat_uninstrument(longopts[i].flag);
            inlongopts[i].has_arg = longopts[i].has_arg;
            inlongopts[i].val     = longopts[i].val;
            i++;
        }
        inlongopts[i].name = NULL;
        inlongopts[i].flag = NULL;
        inlongopts[i].has_arg = inlongopts[i].val = 0;
    }
    if (idx)
        idx = __minifat_uninstrument(idx);

    argv = __minifat_uninstrument(argv);
    for (int i=0; i<argc; i++)
        inargv[i] = __minifat_uninstrument(argv[i]);
    int ret = getopt_long_only(argc, inargv, optstring, inlongoptsptr, idx);
    if (ret != -1 && optarg) {
        PTRTYPE ubnd = __minifat_highest_bound();
        optarg = __minifat_combine_ptr(optarg, ubnd);
    }
    free(inargv);
    return ret;
}
#endif

int minifat_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
    rgid = __minifat_uninstrument(rgid);
    egid = __minifat_uninstrument(egid);
    sgid = __minifat_uninstrument(sgid);
    return getresgid(rgid, egid, sgid);
}

int minifat_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
    ruid = __minifat_uninstrument(ruid);
    euid = __minifat_uninstrument(euid);
    suid = __minifat_uninstrument(suid);
    return getresuid(ruid, euid, suid);
}

int minifat_getrlimit(int resource, struct rlimit *rlim) {
    rlim = __minifat_uninstrument(rlim);
    return getrlimit(resource, rlim);
}

int minifat_getrlimit64(int resource, struct rlimit *rlim) {
    return getrlimit(resource, rlim);
}

int minifat_getrusage(int who, struct rusage *ru) {
    ru = __minifat_uninstrument(ru);
    return getrusage(who, ru);
}

int minifat_getsubopt(char **opt, char *const *keys, char **val) {
    // NOTE: array size is chosen arbitrarily but must suffice
    char** inkeys = calloc(64, sizeof(char*));

    val = __minifat_uninstrument(val);
    opt = __minifat_uninstrument(opt);
    char* prevopt = *opt;
    *opt = __minifat_uninstrument(*opt);
    keys = __minifat_uninstrument(keys);
    for (int i=0; i<64; i++) {
        if (!keys[i])  break;
        inkeys[i] = __minifat_uninstrument(keys[i]);
    }
    inkeys[63] = NULL;  // for sanity

    int ret = getsubopt(opt, inkeys, val);
    if (*val) {
        // val points into *opt, so uses its bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(prevopt);
        *val = __minifat_combine_ptr(*val, ubnd);
    }
    if (*opt) {
        // *opt can be changed, but uses its own bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(prevopt);
        *opt = __minifat_combine_ptr(*opt, ubnd);
    }
    free(inkeys);
    return ret;
}

int minifat_initgroups(const char *user, gid_t gid) {
    user = __minifat_uninstrument(user);
    return initgroups(user, gid);
}

FILE *minifat_setmntent(const char *name, const char *mode) {
    name = __minifat_uninstrument(name);
    mode = __minifat_uninstrument(mode);
    return setmntent(name, mode);
}

struct mntent *minifat_getmntent_r(FILE *f, struct mntent *mnt, char *linebuf, int buflen) {
    struct mntent *mntval = __minifat_uninstrument(mnt);
    char * linebufval = __minifat_uninstrument(linebuf);
    struct mntent *ret = getmntent_r(f, mntval, linebufval, buflen);
    if (ret) {
        // all subfields of ret are ptrs inside linebuf, so use its bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(linebuf);
        ret->mnt_fsname = __minifat_combine_ptr(ret->mnt_fsname, ubnd);
        ret->mnt_dir    = __minifat_combine_ptr(ret->mnt_dir, ubnd);
        ret->mnt_type   = __minifat_combine_ptr(ret->mnt_type, ubnd);
        ret->mnt_opts   = __minifat_combine_ptr(ret->mnt_opts, ubnd);
        ret = mnt;  // func returns ptr to initial mnt
    }
    return ret;
}

struct mtentbuf {
    struct mntent buf;
    PTRTYPE lbnd;
};

struct mntent *minifat_minifat_getmntent(FILE *f) {
    static struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    static struct mtentbuf mnt = {.lbnd = 0};
    if (mnt.lbnd == 0)  mnt.lbnd = (PTRTYPE)&mnt;
    struct mntent *inmnt = __minifat_combine_ptr(&mnt, (PTRTYPE)&mnt.lbnd);
    char *inbuf = __minifat_combine_ptr(&buf, (PTRTYPE)&buf.lbnd);
    return getmntent_r(f, inmnt, inbuf, sizeof(buf.buf));
}

int minifat_addmntent(FILE *f, const struct mntent *mnt) {
    struct mntent inmnt;
    mnt = __minifat_uninstrument(mnt);
    inmnt.mnt_fsname = __minifat_uninstrument(mnt->mnt_fsname);
    inmnt.mnt_dir    = __minifat_uninstrument(mnt->mnt_dir);
    inmnt.mnt_type   = __minifat_uninstrument(mnt->mnt_type);
    inmnt.mnt_opts   = __minifat_uninstrument(mnt->mnt_opts);
    inmnt.mnt_freq   = mnt->mnt_freq;
    inmnt.mnt_passno = mnt->mnt_passno;
    return addmntent(f, &inmnt);
}

char *minifat_hasmntopt(const struct mntent *mnt, const char *opt) {
    struct mntent inmnt;
    mnt = __minifat_uninstrument(mnt);
    inmnt.mnt_opts = __minifat_uninstrument(mnt->mnt_opts);
    opt = __minifat_uninstrument(opt);
    char* ret = hasmntopt(&inmnt, opt);
    if (ret) {
        // ret points inside mnt->mnt_opts, so use its bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(mnt->mnt_opts);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

// typedef int (*nftw_fn_fun)(const char *, const struct stat *, int, struct FTW *);

// struct statbuf {
//     struct stat buf;
//     PTRTYPE lbnd;
// };

// struct ftwbuf {
//     struct FTW buf;
//     PTRTYPE lbnd;
// };

// static __thread nftw_fn_fun  nftw_fn_fun;

// static int minifat_nftw_fn(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftw) {
//     static __thread struct charbuf fpathbuf;
//     static __thread struct statbuf sbbuf;
//     static __thread struct ftwbuf  ftwbuf;

//     if (fpathbuf.lbnd == 0)  fpathbuf.lbnd = (PTRTYPE)&fpathbuf;
//     if (sbbuf.lbnd == 0)     sbbuf.lbnd    = (PTRTYPE)&sbbuf;
//     if (ftwbuf.lbnd == 0)    ftwbuf.lbnd   = (PTRTYPE)&ftwbuf;

//     strcpy(fpathbuf.buf, fpath);
//     memcpy(&sbbuf.buf, sb, sizeof(struct stat));
//     memcpy(&ftwbuf.buf, ftw, sizeof(struct FTW));

//     char *fpathbufptr     = __minifat_combine_ptr(&fpathbuf, (PTRTYPE)&fpathbuf.lbnd);
//     struct stat *sbbufptr = __minifat_combine_ptr(&sbbuf, (PTRTYPE)&sbbuf.lbnd);
//     struct FTW *ftwbufptr = __minifat_combine_ptr(&ftwbuf, (PTRTYPE)&ftwbuf.lbnd);

//     return nftw_fn_fun(fpathbufptr, sbbufptr, typeflag, ftwbufptr);
// }

// int minifat_nftw(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags) {
//     // memorize the real fn function supplied by user
//     nftw_fn_fun = fn;
//     // continue with real uninstrumented nftw(); it will call fn
//     // which copies & instruments all args and forwards to real fn
//     path = __minifat_uninstrument(path);
//     return nftw(path, nftw_fn, fd_limit, flags);
// }

// int minifat_nftw64(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags) {
//     return nftw(path, fn, fd_limit, flags);
// }

char *minifat_realpath(const char *restrict filename, char *restrict resolved) {
    filename = __minifat_uninstrument(filename);
    char* resolvedval = __minifat_uninstrument(resolved);
    char* ret = realpath(filename, resolvedval);
    if (ret)
        ret = resolved;
    return ret;
}

int minifat_minifat_setdomainname(const char *name, size_t len) {
    name = __minifat_uninstrument(name);
    return setdomainname(name, len);
}

int minifat_setrlimit(int resource, const struct rlimit *rlim) {
    rlim = __minifat_uninstrument(rlim);
    return setrlimit(resource, rlim);
}

int minifat_setrlimit64(int resource, const struct rlimit *rlim) {
    return setrlimit(resource, rlim);
}

void minifat_openlog(const char *ident, int opt, int facility) {
    ident = __minifat_uninstrument(ident);
    openlog(ident, opt, facility);
}

void minifat_syslog(int priority, const char *message, ...) {
    message = __minifat_uninstrument(message);
    va_list ap;
    va_start(ap, message);
    vsyslog(priority, message, ap);
    va_end(ap);
}

void minifat_vsyslog(int priority, const char *message, va_list ap) {
    ap = __minifat_uninstrument((void*)ap);
    message = __minifat_uninstrument(message);
    vsyslog(priority, message, ap);
}

int minifat_uname(struct utsname *uts) {
    uts = __minifat_uninstrument(uts);
    return uname(uts);
}

int minifat_ioctl(int fd, int req, ...) {
    void *arg;
    va_list ap;
    va_start(ap, req);
    arg = va_arg(ap, void *);
    va_end(ap);

    if (arg)  arg = __minifat_uninstrument(arg);
    return ioctl(fd, req, arg);
}


/* ------------------------------------------------------------------------- */
/* ----------------------------- select funcs  ----------------------------- */
/* ------------------------------------------------------------------------- */
int minifat_poll(struct pollfd *fds, nfds_t n, int timeout);
int minifat_pselect(int n, fd_set *restrict rfds, fd_set *restrict wfds, fd_set *restrict efds, const struct timespec *restrict ts, const sigset_t *restrict mask);
int minifat_select(int n, fd_set *restrict rfds, fd_set *restrict wfds, fd_set *restrict efds, struct timeval *restrict tv);

int minifat_poll(struct pollfd *fds, nfds_t n, int timeout) {
    fds = __minifat_uninstrument(fds);
    return poll(fds, n, timeout);
}

int minifat_pselect(int n, fd_set *restrict rfds, fd_set *restrict wfds, fd_set *restrict efds, const struct timespec *restrict ts, const sigset_t *restrict mask) {
    if (rfds)
        rfds = __minifat_uninstrument(rfds);
    if (wfds)
        wfds = __minifat_uninstrument(wfds);
    if (efds)
        efds = __minifat_uninstrument(efds);
    if (ts)
        ts = __minifat_uninstrument(ts);
    if (mask)
        mask = __minifat_uninstrument(mask);
    return pselect(n, rfds, wfds, efds, ts, mask);
}

int minifat_select(int n, fd_set *restrict rfds, fd_set *restrict wfds, fd_set *restrict efds, struct timeval *restrict tv) {
    if (rfds)
        rfds = __minifat_uninstrument(rfds);
    if (wfds)
        wfds = __minifat_uninstrument(wfds);
    if (efds)
        efds = __minifat_uninstrument(efds);
    if (tv)
        tv = __minifat_uninstrument(tv);
    return select(n, rfds, wfds, efds, tv);
}

/* ------------------------------------------------------------------------- */
/* ----------------------------- thread funcs  ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: ignore all funcs to do with clone, fork, and raw syscalls
// NOTE: pthread_t is treated as opaque and thus not instrumented, but others
//       (e.g., pthread_attr_t) are allocated by app and thus instrumented
int minifat_pthread_attr_getdetachstate(const pthread_attr_t *a, int *state);
int minifat_pthread_attr_getguardsize(const pthread_attr_t *restrict a, size_t *restrict size);
int minifat_pthread_attr_getinheritsched(const pthread_attr_t *restrict a, int *restrict inherit);
int minifat_pthread_attr_getschedparam(const pthread_attr_t *restrict a, struct sched_param *restrict param);
int minifat_pthread_attr_getschedpolicy(const pthread_attr_t *restrict a, int *restrict policy);
int minifat_pthread_attr_getscope(const pthread_attr_t *restrict a, int *restrict scope);
int minifat_pthread_attr_getstack(const pthread_attr_t *restrict a, void **restrict addr, size_t *restrict size);
int minifat_pthread_attr_getstacksize(const pthread_attr_t *restrict a, size_t *restrict size);
int minifat_pthread_barrierattr_getpshared(const pthread_barrierattr_t *restrict a, int *restrict pshared);
int minifat_pthread_condattr_getclock(const pthread_condattr_t *restrict a, clockid_t *restrict clk);
int minifat_pthread_condattr_getpshared(const pthread_condattr_t *restrict a, int *restrict pshared);
int minifat_pthread_mutexattr_getprotocol(const pthread_mutexattr_t *restrict a, int *restrict protocol);
int minifat_pthread_mutexattr_getpshared(const pthread_mutexattr_t *restrict a, int *restrict pshared);
int minifat_pthread_mutexattr_getrobust(const pthread_mutexattr_t *restrict a, int *restrict robust);
int minifat_pthread_mutexattr_gettype(const pthread_mutexattr_t *restrict a, int *restrict type);
int minifat_pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *restrict a, int *restrict pshared);
int minifat_pthread_attr_setstack(pthread_attr_t *a, void *addr, size_t size);
int minifat_pthread_cond_timedwait(pthread_cond_t *restrict c, pthread_mutex_t *restrict m, const struct timespec *restrict ts);
int minifat_pthread_create(pthread_t *restrict res, const pthread_attr_t *restrict attrp, void *(*entry)(void *), void *restrict arg);
int minifat_pthread_getcpuclockid(pthread_t t, clockid_t *clockid);
int minifat_pthread_getschedparam(pthread_t t, int *restrict policy, struct sched_param *restrict param);
int minifat_pthread_join(pthread_t t, void **res);
int minifat_pthread_mutex_getprioceiling(const pthread_mutex_t *restrict m, int *restrict ceiling);
int minifat_pthread_mutex_setprioceiling(pthread_mutex_t *restrict m, int ceiling, int *restrict old);
int minifat_pthread_mutex_timedlock(pthread_mutex_t *restrict m, const struct timespec *restrict at);
int minifat_pthread_rwlock_timedrdlock(pthread_rwlock_t *restrict rw, const struct timespec *restrict at);
int minifat_pthread_rwlock_timedwrlock(pthread_rwlock_t *restrict rw, const struct timespec *restrict at);
int minifat_pthread_setcancelstate(int new, int *old);
int minifat_pthread_setcanceltype(int new, int *old);
int minifat_pthread_setschedparam(pthread_t t, int policy, const struct sched_param *param);
int minifat_pthread_setspecific(pthread_key_t k, const void *x);
void *minifat_pthread_getspecific(pthread_key_t k);
int minifat_sem_getvalue(sem_t *restrict sem, int *restrict valp);
sem_t *minifat_minifat_sem_open(const char *name, int flags, ...);
int minifat_sem_timedwait(sem_t *restrict sem, const struct timespec *restrict at);
int minifat_sem_unlink(const char *name);
int minifat_pthread_attr_destroy(pthread_attr_t *a);
int minifat_pthread_attr_init(pthread_attr_t *a);
int minifat_pthread_attr_setdetachstate(pthread_attr_t *a, int state);
int minifat_pthread_attr_setguardsize(pthread_attr_t *a, size_t size);
int minifat_pthread_attr_setinheritsched(pthread_attr_t *a, int inherit);
int minifat_pthread_attr_setschedparam(pthread_attr_t *restrict a, const struct sched_param *restrict param);
int minifat_pthread_attr_setschedpolicy(pthread_attr_t *a, int policy);
int minifat_pthread_attr_setscope(pthread_attr_t *a, int scope);
int minifat_pthread_attr_setstacksize(pthread_attr_t *a, size_t size);
int minifat_pthread_barrierattr_destroy(pthread_barrierattr_t *a);
int minifat_pthread_barrierattr_init(pthread_barrierattr_t *a);
int minifat_pthread_barrierattr_setpshared(pthread_barrierattr_t *a, int pshared);
int minifat_pthread_barrier_destroy(pthread_barrier_t *b);
int minifat_pthread_barrier_init(pthread_barrier_t *restrict b, const pthread_barrierattr_t *restrict a, unsigned count);
int minifat_pthread_barrier_wait(pthread_barrier_t *b);
int minifat_pthread_condattr_destroy(pthread_condattr_t *a);
int minifat_pthread_condattr_init(pthread_condattr_t *a);
int minifat_pthread_condattr_setclock(pthread_condattr_t *a, clockid_t clk);
int minifat_pthread_condattr_setpshared(pthread_condattr_t *a, int pshared);
int minifat_pthread_cond_broadcast(pthread_cond_t *c);
int minifat_pthread_cond_destroy(pthread_cond_t *c);
int minifat_pthread_cond_init(pthread_cond_t *restrict c, const pthread_condattr_t *restrict a);
int minifat_pthread_cond_signal(pthread_cond_t *c);
int minifat_pthread_cond_wait(pthread_cond_t *restrict c, pthread_mutex_t *restrict m);
int minifat_pthread_getattr_np(pthread_t t, pthread_attr_t *a);
int minifat_pthread_key_create(pthread_key_t *k, void (*dtor)(void *));
int minifat_pthread_mutexattr_destroy(pthread_mutexattr_t *a);
int minifat_pthread_mutexattr_init(pthread_mutexattr_t *a);
int minifat_pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int protocol);
int minifat_pthread_mutexattr_setpshared(pthread_mutexattr_t *a, int pshared);
int minifat_pthread_mutexattr_setrobust(pthread_mutexattr_t *a, int robust);
int minifat_pthread_mutexattr_settype(pthread_mutexattr_t *a, int type);
int minifat_pthread_mutex_consistent(pthread_mutex_t *m);
int minifat_pthread_mutex_destroy(pthread_mutex_t *mutex);
int minifat_pthread_mutex_init(pthread_mutex_t *restrict m, const pthread_mutexattr_t *restrict a);
int minifat_pthread_mutex_lock(pthread_mutex_t *m);
int minifat_pthread_mutex_trylock(pthread_mutex_t *m);
int minifat_pthread_mutex_unlock(pthread_mutex_t *m);
int minifat_pthread_once(pthread_once_t *control, void (*init)(void));
int minifat_pthread_rwlockattr_destroy(pthread_rwlockattr_t *a);
int minifat_pthread_rwlockattr_init(pthread_rwlockattr_t *a);
int minifat_pthread_rwlockattr_setpshared(pthread_rwlockattr_t *a, int pshared);
int minifat_pthread_rwlock_destroy(pthread_rwlock_t *rw);
int minifat_pthread_rwlock_init(pthread_rwlock_t *restrict rw, const pthread_rwlockattr_t *restrict a);
int minifat_pthread_rwlock_rdlock(pthread_rwlock_t *rw);
int minifat_pthread_rwlock_tryrdlock(pthread_rwlock_t *rw);
int minifat_pthread_rwlock_trywrlock(pthread_rwlock_t *rw);
int minifat_pthread_rwlock_unlock(pthread_rwlock_t *rw);
int minifat_pthread_rwlock_wrlock(pthread_rwlock_t *rw);
int minifat_pthread_sigmask(int how, const sigset_t *restrict set, sigset_t *restrict old);
int minifat_sem_destroy(sem_t *sem);
int minifat_sem_init(sem_t *sem, int pshared, unsigned value);
int minifat_sem_post(sem_t *sem);
int minifat_sem_trywait(sem_t *sem);
int minifat_sem_wait(sem_t *sem);

int minifat_pthread_attr_getdetachstate(const pthread_attr_t *a, int *state) {
    a = __minifat_uninstrument(a);
    state = __minifat_uninstrument(state);
    return pthread_attr_getdetachstate(a, state);
}

int minifat_pthread_attr_getguardsize(const pthread_attr_t *restrict a, size_t *restrict size) {
    a = __minifat_uninstrument(a);
    size = __minifat_uninstrument(size);
    return pthread_attr_getguardsize(a, size);
}

int minifat_pthread_attr_getinheritsched(const pthread_attr_t *restrict a, int *restrict inherit) {
    a = __minifat_uninstrument(a);
    inherit = __minifat_uninstrument(inherit);
    return pthread_attr_getinheritsched(a, inherit);
}

int minifat_pthread_attr_getschedparam(const pthread_attr_t *restrict a, struct sched_param *restrict param) {
    a = __minifat_uninstrument(a);
    param = __minifat_uninstrument(param);
    return pthread_attr_getschedparam(a, param);
}

int minifat_pthread_attr_getschedpolicy(const pthread_attr_t *restrict a, int *restrict policy) {
    a = __minifat_uninstrument(a);
    policy = __minifat_uninstrument(policy);
    return pthread_attr_getschedpolicy(a, policy);
}

int minifat_pthread_attr_getscope(const pthread_attr_t *restrict a, int *restrict scope) {
    a = __minifat_uninstrument(a);
    scope = __minifat_uninstrument(scope);
    return pthread_attr_getscope(a, scope);
}

int minifat_pthread_attr_getstack(const pthread_attr_t *restrict a, void **restrict addr, size_t *restrict size) {
    // NOTE: this func messes with stack, we disallow it
    return 1;
}

int minifat_pthread_attr_getstacksize(const pthread_attr_t *restrict a, size_t *restrict size) {
    a = __minifat_uninstrument(a);
    size = __minifat_uninstrument(size);
    return pthread_attr_getstacksize(a, size);
}

int minifat_pthread_barrierattr_getpshared(const pthread_barrierattr_t *restrict a, int *restrict pshared) {
    a = __minifat_uninstrument(a);
    pshared = __minifat_uninstrument(pshared);
    return pthread_barrierattr_getpshared(a, pshared);
}

int minifat_pthread_condattr_getclock(const pthread_condattr_t *restrict a, clockid_t *restrict clk) {
    a = __minifat_uninstrument(a);
    clk = __minifat_uninstrument(clk);
    return pthread_condattr_getclock(a, clk);
}

int minifat_pthread_condattr_getpshared(const pthread_condattr_t *restrict a, int *restrict pshared) {
    a = __minifat_uninstrument(a);
    pshared = __minifat_uninstrument(pshared);
    return pthread_condattr_getpshared(a, pshared);
}

int minifat_pthread_mutexattr_getprotocol(const pthread_mutexattr_t *restrict a, int *restrict protocol) {
    a = __minifat_uninstrument(a);
    protocol = __minifat_uninstrument(protocol);
    return pthread_mutexattr_getprotocol(a, protocol);
}

int minifat_pthread_mutexattr_getpshared(const pthread_mutexattr_t *restrict a, int *restrict pshared) {
    a = __minifat_uninstrument(a);
    pshared = __minifat_uninstrument(pshared);
    return pthread_mutexattr_getpshared(a, pshared);
}

int minifat_pthread_mutexattr_getrobust(const pthread_mutexattr_t *restrict a, int *restrict robust) {
    a = __minifat_uninstrument(a);
    robust = __minifat_uninstrument(robust);
    return pthread_mutexattr_getrobust(a, robust);
}

int minifat_pthread_mutexattr_gettype(const pthread_mutexattr_t *restrict a, int *restrict type) {
    a = __minifat_uninstrument(a);
    type = __minifat_uninstrument(type);
    return pthread_mutexattr_gettype(a, type);
}

int minifat_pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *restrict a, int *restrict pshared) {
    a = __minifat_uninstrument(a);
    pshared = __minifat_uninstrument(pshared);
    return pthread_rwlockattr_getpshared(a, pshared);
}

int minifat_pthread_attr_setstack(pthread_attr_t *a, void *addr, size_t size) {
    // NOTE: this func messes with stack, we disallow it
    return 1;
}

int minifat_pthread_cond_timedwait(pthread_cond_t *restrict c, pthread_mutex_t *restrict m, const struct timespec *restrict ts) {
    c = __minifat_uninstrument(c);
    m = __minifat_uninstrument(m);
    ts = __minifat_uninstrument(ts);
    return pthread_cond_timedwait(c, m, ts);
}

int minifat_pthread_create(pthread_t *restrict res, const pthread_attr_t *restrict attrp, void *(*entry)(void *), void *restrict arg) {
    // NOTE: no need to uninstrument:
    //         - entry is function ptr which we do not instrument
    //         - arg will be forwarded to entry() as-is, instrumented
    res = __minifat_uninstrument(res);
    if (attrp)  attrp = __minifat_uninstrument(attrp);

    return pthread_create(res, attrp, entry, arg);
}

int minifat_pthread_getcpuclockid(pthread_t t, clockid_t *clockid) {
    clockid = __minifat_uninstrument(clockid);
    return pthread_getcpuclockid(t, clockid);
}

int minifat_pthread_getschedparam(pthread_t t, int *restrict policy, struct sched_param *restrict param) {
    policy = __minifat_uninstrument(policy);
    param  = __minifat_uninstrument(param);
    return pthread_getschedparam(t, policy, param);
}

int minifat_pthread_join(pthread_t t, void **res) {
    // NOTE: no need to care about *res since it is passed between instrumented funcs
    if (res)
        res  = __minifat_uninstrument(res);
    return pthread_join(t, res);
}

int minifat_pthread_mutex_getprioceiling(const pthread_mutex_t *restrict m, int *restrict ceiling) {
    m       = __minifat_uninstrument(m);
    ceiling = __minifat_uninstrument(ceiling);
    return pthread_mutex_getprioceiling(m, ceiling);
}

int minifat_pthread_mutex_setprioceiling(pthread_mutex_t *restrict m, int ceiling, int *restrict old) {
    m   = __minifat_uninstrument(m);
    old = __minifat_uninstrument(old);
    return pthread_mutex_setprioceiling(m, ceiling, old);
}

int minifat_pthread_mutex_timedlock(pthread_mutex_t *restrict m, const struct timespec *restrict at) {
    m  = __minifat_uninstrument(m);
    at = __minifat_uninstrument(at);
    return pthread_mutex_timedlock(m, at);
}

int minifat_pthread_rwlock_timedrdlock(pthread_rwlock_t *restrict rw, const struct timespec *restrict at) {
    rw = __minifat_uninstrument(rw);
    at = __minifat_uninstrument(at);
    return pthread_rwlock_timedrdlock(rw, at);
}

int minifat_pthread_rwlock_timedwrlock(pthread_rwlock_t *restrict rw, const struct timespec *restrict at) {
    rw = __minifat_uninstrument(rw);
    at = __minifat_uninstrument(at);
    return pthread_rwlock_timedwrlock(rw, at);
}

int minifat_pthread_setcancelstate(int new, int *old) {
    old = __minifat_uninstrument(old);
    return pthread_setcancelstate(new, old);
}

int minifat_pthread_setcanceltype(int new, int *old) {
    old = __minifat_uninstrument(old);
    return pthread_setcanceltype(new, old);
}

int minifat_pthread_setschedparam(pthread_t t, int policy, const struct sched_param *param) {
    param = __minifat_uninstrument(param);
    return pthread_setschedparam(t, policy, param);
}

int minifat_pthread_setspecific(pthread_key_t k, const void *x) {
    // NOTE: set value is not manipulated by libc so can keep instrumented
    return pthread_setspecific(k, x);
}

void *minifat_pthread_getspecific(pthread_key_t k) {
    // NOTE: ret value is not manipulated by libc so can keep instrumented
    return pthread_getspecific(k);
}

int minifat_sem_getvalue(sem_t *restrict sem, int *restrict valp) {
    sem  = __minifat_uninstrument(sem);
    valp = __minifat_uninstrument(valp);
    return sem_getvalue(sem, valp);
}

sem_t *minifat_sem_open(const char *name, int flags, ...) {
    //TODO: returned semaphor is not instrumented, and if passed to
    //      some other funcs will error since they expect instrumented
    va_list ap;
    name = __minifat_uninstrument(name);
    if (flags & O_CREAT) {
        va_start(ap, flags);
        mode_t mode = va_arg(ap, mode_t);
        unsigned value = va_arg(ap, unsigned);
        va_end(ap);
        return sem_open(name, flags, mode, value);
    }
    // no O_CREAT in flags, call 2-arg version of sem_open()
    return sem_open(name, flags);
}

int minifat_sem_timedwait(sem_t *restrict sem, const struct timespec *restrict at) {
    sem = __minifat_uninstrument(sem);
    at = __minifat_uninstrument(at);
    return sem_timedwait(sem, at);
}

int minifat_sem_unlink(const char *name) {
    name = __minifat_uninstrument(name);
    return sem_unlink(name);
}

int minifat_pthread_attr_destroy(pthread_attr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_attr_destroy(a);
}

int minifat_pthread_attr_init(pthread_attr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_attr_init(a);
}

int minifat_pthread_attr_setdetachstate(pthread_attr_t *a, int state) {
    a = __minifat_uninstrument(a);
    return pthread_attr_setdetachstate(a, state);
}

int minifat_pthread_attr_setguardsize(pthread_attr_t *a, size_t size) {
    a = __minifat_uninstrument(a);
    return pthread_attr_setguardsize(a, size);
}

int minifat_pthread_attr_setinheritsched(pthread_attr_t *a, int inherit) {
    a = __minifat_uninstrument(a);
    return pthread_attr_setinheritsched(a, inherit);
}

int minifat_pthread_attr_setschedparam(pthread_attr_t *restrict a, const struct sched_param *restrict param) {
    a = __minifat_uninstrument(a);
    param = __minifat_uninstrument(param);
    return pthread_attr_setschedparam(a, param);
}

int minifat_pthread_attr_setschedpolicy(pthread_attr_t *a, int policy) {
    a = __minifat_uninstrument(a);
    return pthread_attr_setschedpolicy(a, policy);
}

int minifat_pthread_attr_setscope(pthread_attr_t *a, int scope) {
    a = __minifat_uninstrument(a);
    return pthread_attr_setscope(a, scope);
}

int minifat_pthread_attr_setstacksize(pthread_attr_t *a, size_t size) {
    a = __minifat_uninstrument(a);
    return pthread_attr_setstacksize(a, size);
}

int minifat_pthread_barrierattr_destroy(pthread_barrierattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_barrierattr_destroy(a);
}

int minifat_pthread_barrierattr_init(pthread_barrierattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_barrierattr_init(a);
}

int minifat_pthread_barrierattr_setpshared(pthread_barrierattr_t *a, int pshared) {
    a = __minifat_uninstrument(a);
    return pthread_barrierattr_setpshared(a, pshared);
}

int minifat_pthread_barrier_destroy(pthread_barrier_t *b) {
    b = __minifat_uninstrument(b);
    return pthread_barrier_destroy(b);
}

int minifat_pthread_barrier_init(pthread_barrier_t *restrict b, const pthread_barrierattr_t *restrict a, unsigned count) {
    b = __minifat_uninstrument(b);
    if (a)  a = __minifat_uninstrument(a);
    return pthread_barrier_init(b, a, count);
}

int minifat_pthread_barrier_wait(pthread_barrier_t *b) {
    b = __minifat_uninstrument(b);
    return pthread_barrier_wait(b);
}

int minifat_pthread_condattr_destroy(pthread_condattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_condattr_destroy(a);
}

int minifat_pthread_condattr_init(pthread_condattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_condattr_init(a);
}

int minifat_pthread_condattr_setclock(pthread_condattr_t *a, clockid_t clk) {
    a = __minifat_uninstrument(a);
    return pthread_condattr_setclock(a, clk);
}

int minifat_pthread_condattr_setpshared(pthread_condattr_t *a, int pshared) {
    a = __minifat_uninstrument(a);
    return pthread_condattr_setpshared(a, pshared);
}

int minifat_pthread_cond_broadcast(pthread_cond_t *c) {
    c = __minifat_uninstrument(c);
    return pthread_cond_broadcast(c);
}

int minifat_pthread_cond_destroy(pthread_cond_t *c) {
    c = __minifat_uninstrument(c);
    return pthread_cond_destroy(c);
}

int minifat_pthread_cond_init(pthread_cond_t *restrict c, const pthread_condattr_t *restrict a) {
    c = __minifat_uninstrument(c);
    if (a)  a = __minifat_uninstrument(a);
    return pthread_cond_init(c, a);
}

int minifat_pthread_cond_signal(pthread_cond_t *c) {
    c = __minifat_uninstrument(c);
    return pthread_cond_signal(c);
}

int minifat_pthread_cond_wait(pthread_cond_t *restrict c, pthread_mutex_t *restrict m) {
    c = __minifat_uninstrument(c);
    m = __minifat_uninstrument(m);
    return pthread_cond_wait(c, m);
}

int minifat_pthread_getattr_np(pthread_t t, pthread_attr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_getattr_np(t, a);
}

int minifat_pthread_key_create(pthread_key_t *k, void (*dtor)(void *)) {
    k = __minifat_uninstrument(k);
    return pthread_key_create(k, dtor);
}

int minifat_pthread_mutexattr_destroy(pthread_mutexattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_mutexattr_destroy(a);
}

int minifat_pthread_mutexattr_init(pthread_mutexattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_mutexattr_init(a);
}

int minifat_pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int protocol) {
    a = __minifat_uninstrument(a);
    return pthread_mutexattr_setprotocol(a, protocol);
}

int minifat_pthread_mutexattr_setpshared(pthread_mutexattr_t *a, int pshared) {
    a = __minifat_uninstrument(a);
    return pthread_mutexattr_setpshared(a, pshared);
}

int minifat_pthread_mutexattr_setrobust(pthread_mutexattr_t *a, int robust) {
    a = __minifat_uninstrument(a);
    return pthread_mutexattr_setrobust(a, robust);
}

int minifat_pthread_mutexattr_settype(pthread_mutexattr_t *a, int type) {
    a = __minifat_uninstrument(a);
    return pthread_mutexattr_settype(a, type);
}

int minifat_pthread_mutex_consistent(pthread_mutex_t *m) {
    m = __minifat_uninstrument(m);
    return pthread_mutex_consistent(m);
}

int minifat_pthread_mutex_destroy(pthread_mutex_t *mutex) {
    mutex = __minifat_uninstrument(mutex);
    return pthread_mutex_destroy(mutex);
}

int minifat_pthread_mutex_init(pthread_mutex_t *restrict m, const pthread_mutexattr_t *restrict a) {
    m = __minifat_uninstrument(m);
    if (a)  a = __minifat_uninstrument(a);
    return pthread_mutex_init(m, a);
}

//__attribute__((noinline))
int minifat_pthread_mutex_lock(pthread_mutex_t *m) {
    m = __minifat_uninstrument(m);
    return pthread_mutex_lock(m);
}

int minifat_pthread_mutex_trylock(pthread_mutex_t *m) {
    m = __minifat_uninstrument(m);
    return pthread_mutex_trylock(m);
}

int minifat_pthread_mutex_unlock(pthread_mutex_t *m) {
    m = __minifat_uninstrument(m);
    return pthread_mutex_unlock(m);
}

int minifat_pthread_once(pthread_once_t *control, void (*init)(void)) {
    control = __minifat_uninstrument(control);
    return pthread_once(control, init);
}

int minifat_pthread_rwlockattr_destroy(pthread_rwlockattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_rwlockattr_destroy(a);
}

int minifat_pthread_rwlockattr_init(pthread_rwlockattr_t *a) {
    a = __minifat_uninstrument(a);
    return pthread_rwlockattr_init(a);
}

int minifat_pthread_rwlockattr_setpshared(pthread_rwlockattr_t *a, int pshared) {
    a = __minifat_uninstrument(a);
    return pthread_rwlockattr_setpshared(a, pshared);
}

int minifat_pthread_rwlock_destroy(pthread_rwlock_t *rw) {
    rw = __minifat_uninstrument(rw);
    return pthread_rwlock_destroy(rw);
}

int minifat_pthread_rwlock_init(pthread_rwlock_t *restrict rw, const pthread_rwlockattr_t *restrict a) {
    rw = __minifat_uninstrument(rw);
    if (a)  a = __minifat_uninstrument(a);
    return pthread_rwlock_init(rw, a);
}

int minifat_pthread_rwlock_rdlock(pthread_rwlock_t *rw) {
    rw = __minifat_uninstrument(rw);
    return pthread_rwlock_rdlock(rw);
}

int minifat_pthread_rwlock_tryrdlock(pthread_rwlock_t *rw) {
    rw = __minifat_uninstrument(rw);
    return pthread_rwlock_tryrdlock(rw);
}

int minifat_pthread_rwlock_trywrlock(pthread_rwlock_t *rw) {
    rw = __minifat_uninstrument(rw);
    return pthread_rwlock_trywrlock(rw);
}

int minifat_pthread_rwlock_unlock(pthread_rwlock_t *rw) {
    rw = __minifat_uninstrument(rw);
    return pthread_rwlock_unlock(rw);
}

int minifat_pthread_rwlock_wrlock(pthread_rwlock_t *rw) {
    rw = __minifat_uninstrument(rw);
    return pthread_rwlock_wrlock(rw);
}

int minifat_pthread_sigmask(int how, const sigset_t *restrict set, sigset_t *restrict old) {
    set = __minifat_uninstrument(set);
    if (old)  old = __minifat_uninstrument(old);
    return pthread_sigmask(how, set, old);
}

int minifat_sem_destroy(sem_t *sem) {
    sem = __minifat_uninstrument(sem);
    return sem_destroy(sem);
}

int minifat_sem_init(sem_t *sem, int pshared, unsigned value) {
    sem = __minifat_uninstrument(sem);
    return sem_init(sem, pshared, value);
}

int minifat_sem_post(sem_t *sem) {
    sem = __minifat_uninstrument(sem);
    return sem_post(sem);
}

int minifat_sem_trywait(sem_t *sem) {
    sem = __minifat_uninstrument(sem);
    return sem_trywait(sem);
}

int minifat_sem_wait(sem_t *sem) {
    sem = __minifat_uninstrument(sem);
    return sem_wait(sem);
}

/* ------------------------------------------------------------------------- */
/* ----------------------------- locale funcs  ----------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: locale_t & iconv_t are opaque and thus not instrumented
char *minifat_bind_textdomain_codeset(const char *domainname, const char *codeset);
char *minifat_catgets(nl_catd catd, int set_id, int msg_id, const char *s);
nl_catd minifat_catopen(const char *name, int oflag);
char *minifat_bindtextdomain(const char *domainname, const char *dirname);
char *minifat_dcngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long int n, int category);
char *minifat_dcgettext(const char *domainname, const char *msgid, int category);
char *minifat_dngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long int n);
char *minifat_dgettext(const char *domainname, const char *msgid);
char *minifat_gettext(const char *msgid);
char *minifat_ngettext(const char *msgid1, const char *msgid2, unsigned long int n);
iconv_t minifat_iconv_open(const char *to, const char *from);
size_t minifat_iconv(iconv_t cd0, char **restrict in, size_t *restrict inb, char **restrict out, size_t *restrict outb);
char *minifat_nl_langinfo(nl_item item);
char *minifat_nl_langinfo_l(nl_item item, locale_t loc);
struct lconv *minifat_localeconv(void);
locale_t minifat_newlocale(int mask, const char *name, locale_t loc);
char *minifat_setlocale(int cat, const char *name);
int minifat_strcoll_l(const char *l, const char *r, locale_t loc);
int minifat_strcoll(const char *l, const char *r);
ssize_t minifat_strfmon_l(char *restrict s, size_t n, locale_t loc, const char *restrict fmt, ...);
ssize_t minifat_strfmon(char *restrict s, size_t n, const char *restrict fmt, ...);
size_t minifat_strxfrm_l(char *restrict dest, const char *restrict src, size_t n, locale_t loc);
size_t minifat_strxfrm(char *restrict dest, const char *restrict src, size_t n);
char *minifat_textdomain(const char *domainname);


char *minifat_bind_textdomain_codeset(const char *domainname, const char *codeset) {
    static struct charbuf sbuf;
    if (sbuf.lbnd == 0)  sbuf.lbnd = (PTRTYPE)&sbuf;
    if (domainname)  domainname = __minifat_uninstrument(domainname);
    if (codeset)  codeset = __minifat_uninstrument(codeset);
    char* ret = bind_textdomain_codeset(domainname, codeset);
    if (ret) {
        strcpy(sbuf.buf, ret);
        ret = __minifat_combine_ptr(&sbuf, (PTRTYPE)&sbuf.lbnd);
    }
    return ret;
}

char *minifat_catgets(nl_catd catd, int set_id, int msg_id, const char *s) {
    static struct charbuf sbuf;
    if (sbuf.lbnd == 0)  sbuf.lbnd = (PTRTYPE)&sbuf;
    char* sval = __minifat_uninstrument(s);
    char* ret = catgets(catd, set_id, msg_id, sval);
    if (ret == sval) {
        // on failure, returns s
        return (char*)s;
    }
    strcpy(sbuf.buf, ret);
    return __minifat_combine_ptr(&sbuf, (PTRTYPE)&sbuf.lbnd);
}

nl_catd catopen(const char *name, int oflag) {
    name = __minifat_uninstrument(name);
    return catopen(name, oflag);
}

char *minifat_bindtextdomain(const char *domainname, const char *dirname) {
    static struct charbuf sbuf;
    if (sbuf.lbnd == 0)  sbuf.lbnd = (PTRTYPE)&sbuf;
    if (domainname)  domainname = __minifat_uninstrument(domainname);
    if (dirname)  dirname = __minifat_uninstrument(dirname);
    char* ret = bindtextdomain(domainname, dirname);
    if (ret) {
        strcpy(sbuf.buf, ret);
        ret = __minifat_combine_ptr(&sbuf, (PTRTYPE)&sbuf.lbnd);
    }
    return ret;
}

char *minifat_dcngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long int n, int category) {
    static struct charbuf sbuf;
    if (sbuf.lbnd == 0)  sbuf.lbnd = (PTRTYPE)&sbuf;
    char *msgid1val = NULL, *msgid2val = NULL;
    if (domainname)  domainname = __minifat_uninstrument(domainname);
    if (msgid1)  msgid1val = __minifat_uninstrument(msgid1);
    if (msgid2)  msgid2val = __minifat_uninstrument(msgid2);
    char* ret = dcngettext(domainname, msgid1val, msgid2val, n, category);
    if (ret == msgid1val)  return (char*) msgid1;
    if (ret == msgid2val)  return (char*) msgid2;
    strcpy(sbuf.buf, ret);
    return __minifat_combine_ptr(&sbuf, (PTRTYPE)&sbuf.lbnd);

}

// NOTE: for next 5 funcs, it is easier to call wrappers
char *minifat_dcgettext(const char *domainname, const char *msgid, int category) {
    return dcngettext(domainname, msgid, 0, 1, category);
}

char *minifat_dngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long int n) {
    return dcngettext(domainname, msgid1, msgid2, n, LC_MESSAGES);
}

char *minifat_dgettext(const char *domainname, const char *msgid) {
    return dcngettext(domainname, msgid, 0, 1, LC_MESSAGES);
}

char *minifat_gettext(const char *msgid) {
    return dgettext(0, msgid);
}

char *minifat_ngettext(const char *msgid1, const char *msgid2, unsigned long int n) {
    return dngettext(0, msgid1, msgid2, n);
}


iconv_t minifat_iconv_open(const char *to, const char *from) {
    to   = __minifat_uninstrument(to);
    from = __minifat_uninstrument(from);
    return iconv_open(to, from);
}

size_t minifat_iconv(iconv_t cd0, char **restrict in, size_t *restrict inb, char **restrict out, size_t *restrict outb) {
    char *inoldval = NULL, *outoldval = NULL;
    if (in) {
        in  = __minifat_uninstrument(in);
        if (*in) {
            inoldval = *in;
            *in = __minifat_uninstrument(*in);
        }
    }
    if (out) {
        out  = __minifat_uninstrument(out);
        if (*out) {
            outoldval = *out;
            *out = __minifat_uninstrument(*out);
        }
    }
    if (inb)   inb   = __minifat_uninstrument(inb);
    if (outb)  outb  = __minifat_uninstrument(outb);
    size_t ret = iconv(cd0, in, inb, out, outb);
    if (in && *in) {
        // *in points into inoldval, so it has the same bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(inoldval);
        *in = __minifat_combine_ptr(*in, ubnd);
    }
    if (out && *out) {
        // *out points into outoldval, so it has the same bounds
        PTRTYPE ubnd = __minifat_extract_ubnd(outoldval);
        *out = __minifat_combine_ptr(*out, ubnd);
    }
    return ret;
}

char *minifat_nl_langinfo_l(nl_item item, locale_t loc) {
    static struct charbuf sbuf;
    if (sbuf.lbnd == 0)  sbuf.lbnd = (PTRTYPE)&sbuf;
    char* ret = nl_langinfo_l(item, loc);
    if (ret) {
        strcpy(sbuf.buf, ret);
        ret = __minifat_combine_ptr(&sbuf, (PTRTYPE)&sbuf.lbnd);
    }
    return ret;
}

char *minifat_nl_langinfo(nl_item item) {
    static struct charbuf sbuf;
    if (sbuf.lbnd == 0)  sbuf.lbnd = (PTRTYPE)&sbuf;
    char* ret = nl_langinfo(item);
    if (ret) {
        strcpy(sbuf.buf, ret);
        ret = __minifat_combine_ptr(&sbuf, (PTRTYPE)&sbuf.lbnd);
    }
    return ret;
}

struct lconvbuf {
    struct lconv buf;
    PTRTYPE lbnd;
};

struct lconvcharsbuf {
    char decimal_point[5];
    char thousands_sep[5];
    char grouping[5];
    char int_curr_symbol[5];
    char currency_symbol[5];
    char mon_decimal_point[5];
    char mon_thousands_sep[5];
    char mon_grouping[5];
    char positive_sign[5];
    char negative_sign[5];
    PTRTYPE lbnd;
};

struct lconv *minifat_localeconv(void) {
    static struct lconvbuf buf;
    static struct lconvcharsbuf charsbuf;
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    if (charsbuf.lbnd == 0)  charsbuf.lbnd = (PTRTYPE)&charsbuf;
    struct lconv *ret = localeconv();
    memcpy(&buf.buf, ret, sizeof(struct lconv));

    strncpy(charsbuf.decimal_point, buf.buf.decimal_point, 5);
    buf.buf.decimal_point = __minifat_combine_ptr(&charsbuf.decimal_point, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.thousands_sep, buf.buf.thousands_sep, 5);
    buf.buf.thousands_sep = __minifat_combine_ptr(&charsbuf.thousands_sep, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.grouping, buf.buf.grouping, 5);
    buf.buf.grouping = __minifat_combine_ptr(&charsbuf.grouping, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.int_curr_symbol, buf.buf.int_curr_symbol, 5);
    buf.buf.int_curr_symbol = __minifat_combine_ptr(&charsbuf.int_curr_symbol, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.currency_symbol, buf.buf.currency_symbol, 5);
    buf.buf.currency_symbol = __minifat_combine_ptr(&charsbuf.currency_symbol, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.mon_decimal_point, buf.buf.mon_decimal_point, 5);
    buf.buf.mon_decimal_point = __minifat_combine_ptr(&charsbuf.mon_decimal_point, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.mon_thousands_sep, buf.buf.mon_thousands_sep, 5);
    buf.buf.mon_thousands_sep = __minifat_combine_ptr(&charsbuf.mon_thousands_sep, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.mon_grouping, buf.buf.mon_grouping, 5);
    buf.buf.mon_grouping = __minifat_combine_ptr(&charsbuf.mon_grouping, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.positive_sign, buf.buf.positive_sign, 5);
    buf.buf.positive_sign = __minifat_combine_ptr(&charsbuf.positive_sign, (PTRTYPE)&charsbuf.lbnd);
    strncpy(charsbuf.negative_sign, buf.buf.negative_sign, 5);
    buf.buf.negative_sign = __minifat_combine_ptr(&charsbuf.negative_sign, (PTRTYPE)&charsbuf.lbnd);

    return __minifat_combine_ptr(&buf, (PTRTYPE)&buf.lbnd);
}

locale_t minifat_newlocale(int mask, const char *name, locale_t loc) {
    if (name)  name = __minifat_uninstrument(name);
    return newlocale(mask, name, loc);
}

char *minifat_setlocale(int cat, const char *name) {
    // NOTE: setlocale returns an opaque string, no need to instrument it
    if (name)  name = __minifat_uninstrument(name);
    return setlocale(cat, name);
}

int minifat_strcoll_l(const char *l, const char *r, locale_t loc) {
    l = __minifat_uninstrument(l);
    r = __minifat_uninstrument(r);
    return strcoll_l(l, r, loc);
}

int minifat_strcoll(const char *l, const char *r) {
    l = __minifat_uninstrument(l);
    r = __minifat_uninstrument(r);
    return strcoll(l, r);
}

ssize_t minifat_strfmon_l(char *restrict s, size_t n, locale_t loc, const char *restrict fmt, ...) {
    // NOTE: too specific to implement
    return -1;
}

ssize_t minifat_strfmon(char *restrict s, size_t n, const char *restrict fmt, ...) {
    // NOTE: too specific to implement
    return -1;
}

size_t minifat_strxfrm_l(char *restrict dest, const char *restrict src, size_t n, locale_t loc) {
    dest = __minifat_uninstrument(dest);
    src  = __minifat_uninstrument(src);
    return strxfrm_l(dest, src, n, loc);
}

size_t minifat_strxfrm(char *restrict dest, const char *restrict src, size_t n) {
    dest = __minifat_uninstrument(dest);
    src  = __minifat_uninstrument(src);
    return strxfrm(dest, src, n);
}

char *minifat_textdomain(const char *domainname) {
    static struct charbuf sbuf;
    if (sbuf.lbnd == 0)  sbuf.lbnd = (PTRTYPE)&sbuf;
    if (domainname)  domainname = __minifat_uninstrument(domainname);
    char* ret = textdomain(domainname);
    if (ret) {
        strcpy(sbuf.buf, ret);
        ret = __minifat_combine_ptr(&sbuf, (PTRTYPE)&sbuf.lbnd);
    }
    return ret;
}

/* ------------------------------------------------------------------------- */
/* ------------------------------ wide chars ------------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: minimal set of wchar-related funcs to make C++ init/fini happy
size_t minifat_wcrtomb(char *restrict s, wchar_t wc, mbstate_t *restrict st);

size_t minifat_wcrtomb(char *restrict s, wchar_t wc, mbstate_t *restrict st) {
    if (s)  s  = __minifat_uninstrument(s);
    if (st) st = __minifat_uninstrument(st);
    return wcrtomb(s, wc, st);
}


/* ------------------------------------------------------------------------- */
/* --------------------------------- errno --------------------------------- */
/* ------------------------------------------------------------------------- */
int *minifat___errno_location(void);

int *minifat___errno_location(void) {
    PTRTYPE ubnd = __minifat_highest_bound();
    int* ret = __errno_location();
    ret = __minifat_combine_ptr(ret, ubnd);
    return ret;
}

/* ------------------------------------------------------------------------- */
/* -------------------------------- network -------------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE:  ignore all DNS funcs: res_ninit, res_nquery, res_nsearch, res_nquerydomain,
//         res_nmkquery, res_nsend, res_init, res_query, res_search, res_querydomain,
//         res_mkquery, res_send, dn_comp, dn_expand
// NOTE2: ignore all ether funcs: ether_aton, ether_ntoa, ether_ntohost,
//          ether_hostton, ether_line, ether_ntoa_r, ether_aton_r
// NOTE3: ignore all resolver funcs (from ns_parse.c)
int minifat_accept(int fd, struct sockaddr *restrict addr, socklen_t *restrict len);
int minifat_accept4(int fd, struct sockaddr *restrict addr, socklen_t *restrict len, int flg);
int minifat_bind(int fd, const struct sockaddr *addr, socklen_t len);
int minifat_connect(int fd, const struct sockaddr *addr, socklen_t len);
struct hostent *minifat_gethostent(void);
int minifat_getaddrinfo(const char *restrict host, const char *restrict serv, const struct addrinfo *restrict hint, struct addrinfo **restrict res);
void minifat_freeaddrinfo(struct addrinfo *p);
const char *minifat_gai_strerror(int ecode);
struct hostent *minifat_gethostbyaddr(const void *a, socklen_t l, int af);
int minifat_gethostbyaddr_r(const void *a, socklen_t l, int af, struct hostent *h, char *buf, size_t buflen, struct hostent **res, int *err);
struct hostent *minifat_gethostbyname(const char *name);
struct hostent *minifat_gethostbyname2(const char *name, int af);
int minifat_gethostbyname2_r(const char *name, int af, struct hostent *h, char *buf, size_t buflen, struct hostent **res, int *err);
int minifat_gethostbyname_r(const char *name, struct hostent *h, char *buf, size_t buflen, struct hostent **res, int *err);
void minifat_freeifaddrs(struct ifaddrs *ifp);
int minifat_getifaddrs(struct ifaddrs **ifap);
int minifat_getnameinfo(const struct sockaddr *restrict sa, socklen_t sl, char *restrict node, socklen_t nodelen, char *restrict serv, socklen_t servlen, int flags);
int minifat_getpeername(int fd, struct sockaddr *restrict addr, socklen_t *restrict len);
struct servent *minifat_getservbyname(const char *name, const char *prots);
int minifat_getservbyname_r(const char *name, const char *prots, struct servent *se, char *buf, size_t buflen, struct servent **res);
struct servent *minifat_getservbyport(int port, const char *prots);
int minifat_getservbyport_r(int port, const char *prots, struct servent *se, char *buf, size_t buflen, struct servent **res);
int minifat_getsockname(int fd, struct sockaddr *restrict addr, socklen_t *restrict len);
int minifat_getsockopt(int fd, int level, int optname, void *restrict optval, socklen_t *restrict optlen);
int *minifat___h_errno_location(void);
void minifat_herror(const char *msg);
const char *minifat_hstrerror(int ecode);
void minifat_if_freenameindex(struct if_nameindex *idx);
struct if_nameindex *minifat_if_nameindex();
char *minifat_if_indextoname(unsigned index, char *name);
unsigned minifat_if_nametoindex(const char *name);
in_addr_t minifat_inet_addr(const char *p);
int minifat_inet_aton(const char *s0, struct in_addr *dest);
in_addr_t minifat_inet_network(const char *p);
char *minifat_inet_ntoa(struct in_addr in);
const char *minifat_inet_ntop(int af, const void *restrict a0, char *restrict s, socklen_t l);
int minifat_inet_pton(int af, const char *restrict s, void *restrict a0);
struct netent *minifat_getnetbyaddr(uint32_t net, int type);
struct netent *minifat_getnetbyname(const char *name);
struct protoent *minifat_getprotoent(void);
struct protoent *minifat_getprotobyname(const char *name);
struct protoent *minifat_getprotobynumber(int num);
ssize_t minifat_recv(int fd, void *buf, size_t len, int flags);
ssize_t minifat_recvfrom(int fd, void *restrict buf, size_t len, int flags, struct sockaddr *restrict addr, socklen_t *restrict alen);
ssize_t minifat_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t minifat_send(int fd, const void *buf, size_t len, int flags);
ssize_t minifat_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t minifat_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t alen);
struct servent *minifat_getservent(void);
int minifat_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
int minifat_socketpair(int domain, int type, int protocol, int fd[2]);

int minifat_accept(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    if (addr)  addr = __minifat_uninstrument(addr);
    if (len)   len  = __minifat_uninstrument(len);
    return accept(fd, addr, len);
}

int minifat_accept4(int fd, struct sockaddr *restrict addr, socklen_t *restrict len, int flg) {
    if (addr)  addr = __minifat_uninstrument(addr);
    if (len)   len  = __minifat_uninstrument(len);
    return accept4(fd, addr, len, flg);
}

int minifat_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    addr = __minifat_uninstrument(addr);
    return bind(fd, addr, len);
}

int minifat_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    addr = __minifat_uninstrument(addr);
    return connect(fd, addr, len);
}

struct hostent *minifat_gethostent(void) {
    static struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    void* ret = gethostent();
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

int minifat_getaddrinfo(const char *restrict host, const char *restrict serv, const struct addrinfo *restrict hint, struct addrinfo **restrict res) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();

    if (host)  host = __minifat_uninstrument(host);
    if (serv)  serv = __minifat_uninstrument(serv);
    if (res)   res  = __minifat_uninstrument(res);
    if (hint)  hint = __minifat_uninstrument(hint);

    int ret = getaddrinfo(host, serv, hint, res);
    if (!ret) {
        struct addrinfo *rp;
        for (rp = *res; rp != NULL; ) {
            struct addrinfo *ainext = rp->ai_next;
            rp->ai_addr      = __minifat_combine_ptr(rp->ai_addr, ubnd);
            rp->ai_canonname = __minifat_combine_ptr(rp->ai_canonname, ubnd);
            if (rp->ai_next)
                rp->ai_next  = __minifat_combine_ptr(rp->ai_next, ubnd);
            rp = ainext;
        }
    }
    *res = __minifat_combine_ptr(*res, ubnd);
    return ret;
}

void minifat_freeaddrinfo(struct addrinfo *p) {
    if (p)  p = __minifat_uninstrument(p);
    freeaddrinfo(p);
}

const char *minifat_gai_strerror(int ecode) {
    static __thread struct charbuf buf;
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    void* ret = (void*) gai_strerror(ecode);
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

struct hostent *minifat_gethostbyaddr(const void *a, socklen_t l, int af) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    a = __minifat_uninstrument(a);
    struct hostent* ret = gethostbyaddr(a, l, af);
    if (ret) {
        ret->h_name = __minifat_combine_ptr(ret->h_name, ubnd);
        for (i=0; ret->h_aliases[i] != NULL; i++)
            ret->h_aliases[i] = __minifat_combine_ptr(ret->h_aliases[i], ubnd);
        ret->h_aliases = __minifat_combine_ptr(ret->h_aliases, ubnd);
        for (i=0; ret->h_addr_list[i] != NULL; i++)
            ret->h_addr_list[i] = __minifat_combine_ptr(ret->h_addr_list[i], ubnd);
        ret->h_addr_list = __minifat_combine_ptr(ret->h_addr_list, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_gethostbyaddr_r(const void *a, socklen_t l, int af, struct hostent *h, char *buf, size_t buflen, struct hostent **res, int *err) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    a = __minifat_uninstrument(a);
    h = __minifat_uninstrument(h);
    buf = __minifat_uninstrument(buf);
    res = __minifat_uninstrument(res);
    if (err)  err = __minifat_uninstrument(err);
    int ret = gethostbyaddr_r(a, l, af, h, buf, buflen, res, err);
    if (!ret) {
        h->h_name = __minifat_combine_ptr(h->h_name, ubnd);
        for (i=0; h->h_aliases[i] != NULL; i++)
            h->h_aliases[i] = __minifat_combine_ptr(h->h_aliases[i], ubnd);
        h->h_aliases = __minifat_combine_ptr(h->h_aliases, ubnd);
        for (i=0; h->h_addr_list[i] != NULL; i++)
            h->h_addr_list[i] = __minifat_combine_ptr(h->h_addr_list[i], ubnd);
        h->h_addr_list = __minifat_combine_ptr(h->h_addr_list, ubnd);
        *res = __minifat_combine_ptr(*res, ubnd);
    }
    return ret;
}

struct hostent *minifat_gethostbyname(const char *name) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    name = __minifat_uninstrument(name);
    struct hostent* ret = gethostbyname(name);
    if (ret) {
        ret->h_name = __minifat_combine_ptr(ret->h_name, ubnd);
        for (i=0; ret->h_aliases[i] != NULL; i++)
            ret->h_aliases[i] = __minifat_combine_ptr(ret->h_aliases[i], ubnd);
        ret->h_aliases = __minifat_combine_ptr(ret->h_aliases, ubnd);
        for (i=0; ret->h_addr_list[i] != NULL; i++)
            ret->h_addr_list[i] = __minifat_combine_ptr(ret->h_addr_list[i], ubnd);
        ret->h_addr_list = __minifat_combine_ptr(ret->h_addr_list, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct hostent *minifat_gethostbyname2(const char *name, int af) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    name = __minifat_uninstrument(name);
    struct hostent* ret = gethostbyname2(name, af);
    if (ret) {
        ret->h_name = __minifat_combine_ptr(ret->h_name, ubnd);
        for (i=0; ret->h_aliases[i] != NULL; i++)
            ret->h_aliases[i] = __minifat_combine_ptr(ret->h_aliases[i], ubnd);
        ret->h_aliases = __minifat_combine_ptr(ret->h_aliases, ubnd);
        for (i=0; ret->h_addr_list[i] != NULL; i++)
            ret->h_addr_list[i] = __minifat_combine_ptr(ret->h_addr_list[i], ubnd);
        ret->h_addr_list = __minifat_combine_ptr(ret->h_addr_list, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_gethostbyname2_r(const char *name, int af, struct hostent *h, char *buf, size_t buflen, struct hostent **res, int *err) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    name = __minifat_uninstrument(name);
    h    = __minifat_uninstrument(h);
    buf  = __minifat_uninstrument(buf);
    res  = __minifat_uninstrument(res);
    if (err)  err = __minifat_uninstrument(err);
    int ret = gethostbyname2_r(name, af, h, buf, buflen, res, err);
    if (!ret) {
        h->h_name = __minifat_combine_ptr(h->h_name, ubnd);
        for (i=0; h->h_aliases[i] != NULL; i++)
            h->h_aliases[i] = __minifat_combine_ptr(h->h_aliases[i], ubnd);
        h->h_aliases = __minifat_combine_ptr(h->h_aliases, ubnd);
        for (i=0; h->h_addr_list[i] != NULL; i++)
            h->h_addr_list[i] = __minifat_combine_ptr(h->h_addr_list[i], ubnd);
        h->h_addr_list = __minifat_combine_ptr(h->h_addr_list, ubnd);
        *res = __minifat_combine_ptr(*res, ubnd);
    }
    return ret;
}

int minifat_gethostbyname_r(const char *name, struct hostent *h, char *buf, size_t buflen, struct hostent **res, int *err) {
    return gethostbyname2_r(name, AF_INET, h, buf, buflen, res, err);
}

void minifat_freeifaddrs(struct ifaddrs *ifp) {
    // NOTE: we re-implement functionality of real freeifaddrs
    struct ifaddrs *n;
    while (ifp) {
        ifp = __minifat_uninstrument(ifp);
        n = ifp->ifa_next;
        free(ifp);
        ifp = n;
    }
}

int minifat_getifaddrs(struct ifaddrs **ifap) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();

    ifap = __minifat_uninstrument(ifap);
    int ret = getifaddrs(ifap);
    if (!ret) {
        struct ifaddrs *ifp;
        for (ifp = *ifap; ifp != NULL; ) {
            struct ifaddrs *ifanext = ifp->ifa_next;
            ifp->ifa_name      = __minifat_combine_ptr(ifp->ifa_name, ubnd);
            ifp->ifa_addr      = __minifat_combine_ptr(ifp->ifa_addr, ubnd);
            ifp->ifa_netmask   = __minifat_combine_ptr(ifp->ifa_netmask, ubnd);
            ifp->ifa_broadaddr = __minifat_combine_ptr(ifp->ifa_broadaddr, ubnd);
            ifp->ifa_data      = __minifat_combine_ptr(ifp->ifa_data, ubnd);
            if (ifp->ifa_next)
                ifp->ifa_next  = __minifat_combine_ptr(ifp->ifa_next, ubnd);
            ifp = ifanext;
        }
        *ifap = __minifat_combine_ptr(*ifap, ubnd);
    }
    return ret;
}

int minifat_getnameinfo(const struct sockaddr *restrict sa, socklen_t sl, char *restrict node, socklen_t nodelen, char *restrict serv, socklen_t servlen, int flags) {
    if (sa)    sa   = __minifat_uninstrument(sa);
    if (node)  node = __minifat_uninstrument(node);
    if (serv)  serv = __minifat_uninstrument(serv);
    return getnameinfo(sa, sl, node, nodelen, serv, servlen, flags);
}

int minifat_getpeername(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    addr = __minifat_uninstrument(addr);
    len  = __minifat_uninstrument(len);
    return getpeername(fd, addr, len);
}

struct servent *minifat_getservbyname(const char *name, const char *prots) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    if (name)  name = __minifat_uninstrument(name);
    if (prots) prots = __minifat_uninstrument(prots);
    struct servent* ret = getservbyname(name, prots);
    if (ret) {
        ret->s_name  = __minifat_combine_ptr(ret->s_name, ubnd);
        ret->s_proto = __minifat_combine_ptr(ret->s_proto, ubnd);
        for (i=0; ret->s_aliases[i] != NULL; i++)
            ret->s_aliases[i] = __minifat_combine_ptr(ret->s_aliases[i], ubnd);
        ret->s_aliases = __minifat_combine_ptr(ret->s_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_getservbyname_r(const char *name, const char *prots, struct servent *se, char *buf, size_t buflen, struct servent **res) {
    int i;
    PTRTYPE se_ubnd  = __minifat_extract_ubnd(se);
    PTRTYPE buf_ubnd = __minifat_extract_ubnd(buf);
    if (name)  name = __minifat_uninstrument(name);
    if (prots) prots = __minifat_uninstrument(prots);
    se  = __minifat_uninstrument(se);
    buf = __minifat_uninstrument(buf);
    res = __minifat_uninstrument(res);
    int ret = getservbyname_r(name, prots, se, buf, buflen, res);
    if (!ret) {
        se->s_name  = __minifat_combine_ptr(se->s_name, buf_ubnd);
        se->s_proto = __minifat_combine_ptr(se->s_proto, buf_ubnd);
        for (i=0; se->s_aliases[i] != NULL; i++)
            se->s_aliases[i] = __minifat_combine_ptr(se->s_aliases[i], buf_ubnd);
        se->s_aliases = __minifat_combine_ptr(se->s_aliases, buf_ubnd);
        if (*res)  *res = __minifat_combine_ptr(*res, se_ubnd);
    }
    return ret;
}

struct servent *minifat_getservbyport(int port, const char *prots) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    if (prots) prots = __minifat_uninstrument(prots);
    struct servent* ret = getservbyport(port, prots);
    if (ret) {
        ret->s_name  = __minifat_combine_ptr(ret->s_name, ubnd);
        ret->s_proto = __minifat_combine_ptr(ret->s_proto, ubnd);
        for (i=0; ret->s_aliases[i] != NULL; i++)
            ret->s_aliases[i] = __minifat_combine_ptr(ret->s_aliases[i], ubnd);
        ret->s_aliases = __minifat_combine_ptr(ret->s_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_getservbyport_r(int port, const char *prots, struct servent *se, char *buf, size_t buflen, struct servent **res) {
    int i;
    PTRTYPE se_ubnd  = __minifat_extract_ubnd(se);
    PTRTYPE buf_ubnd = __minifat_extract_ubnd(buf);
    if (prots) prots = __minifat_uninstrument(prots);
    se  = __minifat_uninstrument(se);
    buf = __minifat_uninstrument(buf);
    res = __minifat_uninstrument(res);
    int ret = getservbyport_r(port, prots, se, buf, buflen, res);
    if (!ret) {
        se->s_name  = __minifat_combine_ptr(se->s_name, buf_ubnd);
        se->s_proto = __minifat_combine_ptr(se->s_proto, buf_ubnd);
        for (i=0; se->s_aliases[i] != NULL; i++)
            se->s_aliases[i] = __minifat_combine_ptr(se->s_aliases[i], buf_ubnd);
        se->s_aliases = __minifat_combine_ptr(se->s_aliases, buf_ubnd);
        if (*res)  *res = __minifat_combine_ptr(*res, se_ubnd);
    }
    return ret;
}

int minifat_getsockname(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    addr = __minifat_uninstrument(addr);
    len  = __minifat_uninstrument(len);
    return getsockname(fd, addr, len);
}

int minifat_getsockopt(int fd, int level, int optname, void *restrict optval, socklen_t *restrict optlen) {
    if (optval)  optval = __minifat_uninstrument(optval);
    if (optlen)  optlen = __minifat_uninstrument(optlen);
    return getsockopt(fd, level, optname, optval, optlen);
}

int *minifat___h_errno_location(void) {
    PTRTYPE ubnd = __minifat_highest_bound();
    int* ret = __h_errno_location();
    ret = __minifat_combine_ptr(ret, ubnd);
    return ret;
}

void minifat_herror(const char *msg) {
    msg  = __minifat_uninstrument(msg);
    herror(msg);
}

const char *minifat_hstrerror(int ecode) {
    static __thread struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    char* ret = (char*) hstrerror(ecode);
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

void minifat_if_freenameindex(struct if_nameindex *idx) {
    idx  = __minifat_uninstrument(idx);
    if_freenameindex(idx);
}

struct if_nameindex *minifat_if_nameindex() {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    struct if_nameindex *ret = if_nameindex();
    if (ret) {
        for (i=0; ret[i].if_name != NULL; i++)
            ret[i].if_name = __minifat_combine_ptr(ret[i].if_name, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

char *minifat_if_indextoname(unsigned index, char *name) {
    PTRTYPE name_ubnd  = __minifat_extract_ubnd(name);
    name  = __minifat_uninstrument(name);
    char* ret = if_indextoname(index, name);
    if (ret)  ret = __minifat_combine_ptr(ret, name_ubnd);
    return ret;
}

unsigned minifat_if_nametoindex(const char *name) {
    name  = __minifat_uninstrument(name);
    return if_nametoindex(name);
}

in_addr_t minifat_inet_addr(const char *p) {
    p  = __minifat_uninstrument(p);
    return inet_addr(p);
}

int minifat_inet_aton(const char *s0, struct in_addr *dest) {
    s0   = __minifat_uninstrument(s0);
    dest = __minifat_uninstrument(dest);
    return inet_aton(s0, dest);
}

in_addr_t minifat_inet_network(const char *p) {
    p = __minifat_uninstrument(p);
    return inet_network(p);
}

char *minifat_inet_ntoa(struct in_addr in) {
    static struct charbuf buf = {.lbnd = 0};
    if (buf.lbnd == 0)  buf.lbnd = (PTRTYPE)&buf;
    char* ret = inet_ntoa(in);
    if (!ret) return NULL;
    strcpy(buf.buf, ret);
    return __minifat_combine_ptr(&buf, (PTRTYPE)&(buf.lbnd));
}

const char *minifat_inet_ntop(int af, const void *restrict a0, char *restrict s, socklen_t l) {
    PTRTYPE s_ubnd  = __minifat_extract_ubnd(s);
    a0 = __minifat_uninstrument(a0);
    s  = __minifat_uninstrument(s);
    char* ret = (char*) inet_ntop(af, a0, s, l);
    if (ret) {
        ret = __minifat_combine_ptr(ret, s_ubnd);
    }
    return ret;
}

int minifat_inet_pton(int af, const char *restrict s, void *restrict a0) {
    a0 = __minifat_uninstrument(a0);
    s  = __minifat_uninstrument(s);
    return inet_pton(af, s, a0);
}

struct netent *minifat_getnetbyaddr(uint32_t net, int type) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    struct netent* ret = getnetbyaddr(net, type);
    if (ret) {
        ret->n_name = __minifat_combine_ptr(ret->n_name, ubnd);
        for (i=0; ret->n_aliases[i] != NULL; i++)
            ret->n_aliases[i] = __minifat_combine_ptr(ret->n_aliases[i], ubnd);
        ret->n_aliases = __minifat_combine_ptr(ret->n_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct netent *minifat_getnetbyname(const char *name) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    name = __minifat_uninstrument(name);
    struct netent* ret = getnetbyname(name);
    if (ret) {
        ret->n_name = __minifat_combine_ptr(ret->n_name, ubnd);
        for (i=0; ret->n_aliases[i] != NULL; i++)
            ret->n_aliases[i] = __minifat_combine_ptr(ret->n_aliases[i], ubnd);
        ret->n_aliases = __minifat_combine_ptr(ret->n_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct protoent *minifat_getprotoent(void) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    struct protoent* ret = getprotoent();
    if (ret) {
        ret->p_name = __minifat_combine_ptr(ret->p_name, ubnd);
        for (i=0; ret->p_aliases[i] != NULL; i++)
            ret->p_aliases[i] = __minifat_combine_ptr(ret->p_aliases[i], ubnd);
        ret->p_aliases = __minifat_combine_ptr(ret->p_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct protoent *minifat_getprotobyname(const char *name) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    name = __minifat_uninstrument(name);
    struct protoent* ret = getprotobyname(name);
    if (ret) {
        ret->p_name = __minifat_combine_ptr(ret->p_name, ubnd);
        for (i=0; ret->p_aliases[i] != NULL; i++)
            ret->p_aliases[i] = __minifat_combine_ptr(ret->p_aliases[i], ubnd);
        ret->p_aliases = __minifat_combine_ptr(ret->p_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct protoent *minifat_getprotobynumber(int num) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    struct protoent* ret = getprotobynumber(num);
    if (ret) {
        ret->p_name = __minifat_combine_ptr(ret->p_name, ubnd);
        for (i=0; ret->p_aliases[i] != NULL; i++)
            ret->p_aliases[i] = __minifat_combine_ptr(ret->p_aliases[i], ubnd);
        ret->p_aliases = __minifat_combine_ptr(ret->p_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

ssize_t minifat_recv(int fd, void *buf, size_t len, int flags) {
    if (buf)  buf = __minifat_uninstrument_check(buf, &len);
    if (!len) {errno = EINVAL; return -1;} // detected out-of-bounds, silently return
    return recv(fd, buf, len, flags);
}

ssize_t minifat_recvfrom(int fd, void *restrict buf, size_t len, int flags, struct sockaddr *restrict addr, socklen_t *restrict alen) {
    if (buf)  buf = __minifat_uninstrument_check(buf, &len);
    if (!len) {errno = EINVAL; return -1;} // detected out-of-bounds, silently return
    if (addr)  addr = __minifat_uninstrument(addr);
    if (alen)  alen = __minifat_uninstrument(alen);
    return recvfrom(fd, buf, len, flags, addr, alen);
}

ssize_t minifat_recvmsg(int fd, struct msghdr *msg, int flags) {
    int i;
    struct msghdr msgval = {.msg_name = NULL, .msg_namelen = 0, .msg_iov = NULL, .msg_iovlen = 0, .msg_control = NULL, .msg_controllen = 0, .msg_flags = 0};
    msg = __minifat_uninstrument(msg);

    if (msg->msg_name)    msgval.msg_name    = __minifat_uninstrument(msg->msg_name);
    if (msg->msg_control) msgval.msg_control = __minifat_uninstrument(msg->msg_control);
    msgval.msg_namelen = msg->msg_namelen;
    msgval.msg_iovlen  = msg->msg_iovlen;
    msgval.msg_controllen  = msg->msg_controllen;
    msgval.msg_flags   = msg->msg_flags;

    struct iovec* iovval = malloc(msg->msg_iovlen * sizeof(struct iovec));
    for (i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *msgiov = __minifat_uninstrument(msg->msg_iov);
        iovval[i].iov_base = __minifat_uninstrument(msgiov[i].iov_base);
        iovval[i].iov_len  = msgiov[i].iov_len;
    }
    msgval.msg_iov = iovval;

    ssize_t ret = recvmsg(fd, &msgval, flags);
    free(iovval);
    return ret;
}

ssize_t minifat_send(int fd, const void *buf, size_t len, int flags) {
    if (buf)  buf = __minifat_uninstrument_check(buf, &len);
    if (!len) {errno = EINVAL; return -1;} // detected out-of-bounds, silently return
    return send(fd, buf, len, flags);
}

ssize_t minifat_sendmsg(int fd, const struct msghdr *msg, int flags) {
    int i;
    struct msghdr msgval = {.msg_name = NULL, .msg_namelen = 0, .msg_iov = NULL, .msg_iovlen = 0, .msg_control = NULL, .msg_controllen = 0, .msg_flags = 0};
    msg = __minifat_uninstrument(msg);

    if (msg->msg_name)    msgval.msg_name    = __minifat_uninstrument(msg->msg_name);
    if (msg->msg_control) msgval.msg_control = __minifat_uninstrument(msg->msg_control);
    msgval.msg_namelen = msg->msg_namelen;
    msgval.msg_iovlen  = msg->msg_iovlen;
    msgval.msg_controllen  = msg->msg_controllen;
    msgval.msg_flags   = msg->msg_flags;

    struct iovec* iovval = malloc(msg->msg_iovlen * sizeof(struct iovec));
    for (i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *msgiov = __minifat_uninstrument(msg->msg_iov);
        iovval[i].iov_base = __minifat_uninstrument(msgiov[i].iov_base);
        iovval[i].iov_len  = msgiov[i].iov_len;
    }
    msgval.msg_iov = iovval;

    ssize_t ret = sendmsg(fd, &msgval, flags);
    free(iovval);
    return ret;
}

ssize_t minifat_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t alen) {
    if (buf)  buf = __minifat_uninstrument_check(buf, &len);
    if (!len) {errno = EINVAL; return -1;} // detected out-of-bounds, silently return
    if (addr)  addr = __minifat_uninstrument(addr);
    return sendto(fd, buf, len, flags, addr, alen);
}

struct servent *minifat_getservent(void) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;
    struct servent* ret = getservent();
    if (ret) {
        ret->s_name  = __minifat_combine_ptr(ret->s_name, ubnd);
        ret->s_proto = __minifat_combine_ptr(ret->s_proto, ubnd);
        for (i=0; ret->s_aliases[i] != NULL; i++)
            ret->s_aliases[i] = __minifat_combine_ptr(ret->s_aliases[i], ubnd);
        ret->s_aliases = __minifat_combine_ptr(ret->s_aliases, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    if (optval)  optval = __minifat_uninstrument(optval);
    return setsockopt(fd, level, optname, optval, optlen);
}

int minifat_socketpair(int domain, int type, int protocol, int fd[2]) {
    int* fdval = (int*)__minifat_uninstrument((void*) fd);
    return socketpair(domain, type, protocol, fdval);
}

/* ------------------------------------------------------------------------- */
/* -------------------------------- linux ---------------------------------- */
/* ------------------------------------------------------------------------- */
int minifat_epoll_ctl(int fd, int op, int fd2, struct epoll_event *ev);
int minifat_epoll_wait(int fd, struct epoll_event *ev, int cnt, int to);
int minifat_epoll_pwait(int fd, struct epoll_event *ev, int cnt, int to, const sigset_t *sigs);
ssize_t minifat_sendfile(int out_fd, int in_fd, off_t *ofs, size_t count);

int minifat_epoll_ctl(int fd, int op, int fd2, struct epoll_event *ev) {
    // NOTE: hope that noone uses ev->data.ptr (otherwise need to uninstrument union)
    if (ev)  ev = __minifat_uninstrument(ev);
    return epoll_ctl(fd, op, fd2, ev);
}

int minifat_epoll_wait(int fd, struct epoll_event *ev, int cnt, int to) {
    // NOTE: hope that noone uses ev->data.ptr (otherwise need to uninstrument union)
    if (ev)  ev = __minifat_uninstrument(ev);
    return epoll_wait(fd, ev, cnt, to);
}

int minifat_epoll_pwait(int fd, struct epoll_event *ev, int cnt, int to, const sigset_t *sigs) {
    // NOTE: hope that noone uses ev->data.ptr (otherwise need to uninstrument union)
    if (ev)    ev = __minifat_uninstrument(ev);
    if (sigs)  sigs = __minifat_uninstrument(sigs);
    return epoll_pwait(fd, ev, cnt, to, sigs);
}

ssize_t minifat_sendfile(int out_fd, int in_fd, off_t *ofs, size_t count) {
    if (ofs)  ofs = __minifat_uninstrument(ofs);
    return sendfile(out_fd, in_fd, ofs, count);
}


/* ------------------------------------------------------------------------- */
/* --------------------------------- temp ---------------------------------- */
/* ------------------------------------------------------------------------- */
char *minifat_mkdtemp(char *template);
int minifat_mkostemp(char *template, int flags);
int minifat_mkostemp64(char *template, int flags);
int minifat_mkostemps(char *template, int len, int flags);
int minifat_mkostemps64(char *template, int len, int flags);
int minifat_mkstemp(char *template);
int minifat_mkstemp64(char *template);
int minifat_mkstemps(char *template, int len);
int minifat_mkstemps64(char *template, int len);
// char *minifat_mktemp(char *template);

char *minifat_mkdtemp(char *template) {
    PTRTYPE ubnd  = __minifat_extract_ubnd(template);
    template = __minifat_uninstrument(template);
    char* ret = mkdtemp(template);
    return __minifat_combine_ptr(ret, ubnd);
}

int minifat_mkostemp(char *template, int flags) {
    template = __minifat_uninstrument(template);
    return mkostemp(template, flags);
}

int minifat_mkostemp64(char *template, int flags) {
    return mkostemp(template, flags);
}

int minifat_mkostemps(char *template, int len, int flags) {
    template = __minifat_uninstrument(template);
    return mkostemps(template, len, flags);
}

int minifat_mkostemps64(char *template, int len, int flags) {
    return mkostemps(template, len, flags);
}

int minifat_mkstemp(char *template) {
    template = __minifat_uninstrument(template);
    return mkstemp(template);
}

int minifat_mkstemp64(char *template) {
    return mkstemp(template);
}

int minifat_mkstemps(char *template, int len) {
    template = __minifat_uninstrument(template);
    return mkstemps(template, len);
}

int minifat_mkstemps64(char *template, int len) {
    return mkstemps(template, len);
}

// char *minifat_mktemp(char *template) {
//     PTRTYPE ubnd  = __minifat_extract_ubnd(template);
//     template = __minifat_uninstrument(template);
//     char* ret = mktemp(template);
//     return __minifat_combine_ptr(ret, ubnd);
// }

/* ------------------------------------------------------------------------- */
/* ------------------------------- passwd ---------------------------------- */
/* ------------------------------------------------------------------------- */
struct group *minifat_fgetgrent(FILE *f);
struct passwd *minifat_fgetpwent(FILE *f);
struct spwd *minifat_fgetspent(FILE *f);
struct group *minifat_getgrent();
struct group *minifat_getgrgid(gid_t gid);
struct group *minifat_getgrnam(const char *name);
int minifat_getgrouplist(const char *user, gid_t gid, gid_t *groups, int *ngroups);
int minifat_getgrnam_r(const char *name, struct group *gr, char *buf, size_t size, struct group **res);
int minifat_getgrgid_r(gid_t gid, struct group *gr, char *buf, size_t size, struct group **res);
struct passwd *minifat_getpwent();
struct passwd *minifat_getpwuid(uid_t uid);
struct passwd *minifat_getpwnam(const char *name);
int minifat_getpwnam_r(const char *name, struct passwd *pw, char *buf, size_t size, struct passwd **res);
int minifat_getpwuid_r(uid_t uid, struct passwd *pw, char *buf, size_t size, struct passwd **res);
struct spwd *minifat_getspnam(const char *name);
int minifat_getspnam_r(const char *name, struct spwd *sp, char *buf, size_t size, struct spwd **res);
int minifat_putgrent(const struct group *gr, FILE *f);
int minifat_putpwent(const struct passwd *pw, FILE *f);
int minifat_putspent(const struct spwd *sp, FILE *f);

struct group *minifat_fgetgrent(FILE *f) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;

    struct group* ret = fgetgrent(f);
    if (ret) {
        ret->gr_name   = __minifat_combine_ptr(ret->gr_name, ubnd);
        ret->gr_passwd = __minifat_combine_ptr(ret->gr_passwd, ubnd);
        for (i=0; ret->gr_mem[i] != NULL; i++)
            ret->gr_mem[i] = __minifat_combine_ptr(ret->gr_mem[i], ubnd);
        ret->gr_mem = __minifat_combine_ptr(ret->gr_mem, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct passwd *minifat_fgetpwent(FILE *f) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    struct passwd* ret = fgetpwent(f);
    if (ret) {
        ret->pw_name   = __minifat_combine_ptr(ret->pw_name, ubnd);
        ret->pw_passwd = __minifat_combine_ptr(ret->pw_passwd, ubnd);
        ret->pw_gecos  = __minifat_combine_ptr(ret->pw_gecos, ubnd);
        ret->pw_dir    = __minifat_combine_ptr(ret->pw_dir, ubnd);
        ret->pw_shell  = __minifat_combine_ptr(ret->pw_shell, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct spwd *minifat_fgetspent(FILE *f) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    struct spwd* ret = fgetspent(f);
    if (ret) {
        ret->sp_namp = __minifat_combine_ptr(ret->sp_namp, ubnd);
        ret->sp_pwdp = __minifat_combine_ptr(ret->sp_pwdp, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct group *minifat_getgrent() {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;

    struct group* ret = getgrent();
    if (ret) {
        ret->gr_name   = __minifat_combine_ptr(ret->gr_name, ubnd);
        ret->gr_passwd = __minifat_combine_ptr(ret->gr_passwd, ubnd);
        for (i=0; ret->gr_mem[i] != NULL; i++)
            ret->gr_mem[i] = __minifat_combine_ptr(ret->gr_mem[i], ubnd);
        ret->gr_mem = __minifat_combine_ptr(ret->gr_mem, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct group *minifat_getgrgid(gid_t gid) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;

    struct group* ret = getgrgid(gid);
    if (ret) {
        ret->gr_name   = __minifat_combine_ptr(ret->gr_name, ubnd);
        ret->gr_passwd = __minifat_combine_ptr(ret->gr_passwd, ubnd);
        for (i=0; ret->gr_mem[i] != NULL; i++)
            ret->gr_mem[i] = __minifat_combine_ptr(ret->gr_mem[i], ubnd);
        ret->gr_mem = __minifat_combine_ptr(ret->gr_mem, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}


struct group *minifat_getgrnam(const char *name) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    int i;

    name = __minifat_uninstrument(name);
    struct group* ret = getgrnam(name);
    if (ret) {
        ret->gr_name   = __minifat_combine_ptr(ret->gr_name, ubnd);
        ret->gr_passwd = __minifat_combine_ptr(ret->gr_passwd, ubnd);
        for (i=0; ret->gr_mem[i] != NULL; i++)
            ret->gr_mem[i] = __minifat_combine_ptr(ret->gr_mem[i], ubnd);
        ret->gr_mem = __minifat_combine_ptr(ret->gr_mem, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_getgrouplist(const char *user, gid_t gid, gid_t *groups, int *ngroups) {
    user = __minifat_uninstrument(user);
    groups = __minifat_uninstrument(groups);
    ngroups = __minifat_uninstrument(ngroups);
    return getgrouplist(user, gid, groups, ngroups);
}

int minifat_getgrnam_r(const char *name, struct group *gr, char *buf, size_t size, struct group **res) {
    PTRTYPE grubnd  = __minifat_extract_ubnd(gr);
    PTRTYPE bufubnd  = __minifat_extract_ubnd(buf);

    name = __minifat_uninstrument(name);
    gr   = __minifat_uninstrument(gr);
    buf  = __minifat_uninstrument(buf);
    res  = __minifat_uninstrument(res);
    int ret = getgrnam_r(name, gr, buf, size, res);
    if (!ret) {
        gr->gr_name   = __minifat_combine_ptr(gr->gr_name, bufubnd);
        gr->gr_passwd = __minifat_combine_ptr(gr->gr_passwd, bufubnd);
        int i;
        for (i=0; gr->gr_mem[i] != NULL; i++)
            gr->gr_mem[i] = __minifat_combine_ptr(gr->gr_mem[i], bufubnd);
        gr->gr_mem = __minifat_combine_ptr(gr->gr_mem, bufubnd);
        if (*res)  *res = __minifat_combine_ptr(*res, grubnd);
    }
    return ret;
}

int minifat_getgrgid_r(gid_t gid, struct group *gr, char *buf, size_t size, struct group **res) {
    PTRTYPE grubnd  = __minifat_extract_ubnd(gr);
    PTRTYPE bufubnd  = __minifat_extract_ubnd(buf);

    gr   = __minifat_uninstrument(gr);
    buf  = __minifat_uninstrument(buf);
    res  = __minifat_uninstrument(res);
    int ret = getgrgid_r(gid, gr, buf, size, res);
    if (!ret) {
        gr->gr_name   = __minifat_combine_ptr(gr->gr_name, bufubnd);
        gr->gr_passwd = __minifat_combine_ptr(gr->gr_passwd, bufubnd);
        int i;
        for (i=0; gr->gr_mem[i] != NULL; i++)
            gr->gr_mem[i] = __minifat_combine_ptr(gr->gr_mem[i], bufubnd);
        gr->gr_mem = __minifat_combine_ptr(gr->gr_mem, bufubnd);
        if (*res)  *res = __minifat_combine_ptr(*res, grubnd);
    }
    return ret;
}

struct passwd *minifat_getpwent() {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    struct passwd* ret = getpwent();
    if (ret) {
        ret->pw_name   = __minifat_combine_ptr(ret->pw_name, ubnd);
        ret->pw_passwd = __minifat_combine_ptr(ret->pw_passwd, ubnd);
        ret->pw_gecos  = __minifat_combine_ptr(ret->pw_gecos, ubnd);
        ret->pw_dir    = __minifat_combine_ptr(ret->pw_dir, ubnd);
        ret->pw_shell  = __minifat_combine_ptr(ret->pw_shell, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct passwd *minifat_getpwuid(uid_t uid) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    struct passwd* ret = getpwuid(uid);
    if (ret) {
        ret->pw_name   = __minifat_combine_ptr(ret->pw_name, ubnd);
        ret->pw_passwd = __minifat_combine_ptr(ret->pw_passwd, ubnd);
        ret->pw_gecos  = __minifat_combine_ptr(ret->pw_gecos, ubnd);
        ret->pw_dir    = __minifat_combine_ptr(ret->pw_dir, ubnd);
        ret->pw_shell  = __minifat_combine_ptr(ret->pw_shell, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

struct passwd *minifat_getpwnam(const char *name) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    name = __minifat_uninstrument(name);
    struct passwd* ret = getpwnam(name);
    if (ret) {
        ret->pw_name   = __minifat_combine_ptr(ret->pw_name, ubnd);
        ret->pw_passwd = __minifat_combine_ptr(ret->pw_passwd, ubnd);
        ret->pw_gecos  = __minifat_combine_ptr(ret->pw_gecos, ubnd);
        ret->pw_dir    = __minifat_combine_ptr(ret->pw_dir, ubnd);
        ret->pw_shell  = __minifat_combine_ptr(ret->pw_shell, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_getpwnam_r(const char *name, struct passwd *pw, char *buf, size_t size, struct passwd **res) {
    PTRTYPE pwubnd  = __minifat_extract_ubnd(pw);
    PTRTYPE bufubnd  = __minifat_extract_ubnd(buf);

    name = __minifat_uninstrument(name);
    pw   = __minifat_uninstrument(pw);
    buf  = __minifat_uninstrument(buf);
    res  = __minifat_uninstrument(res);
    int ret = getpwnam_r(name, pw, buf, size, res);
    if (!ret) {
        pw->pw_name   = __minifat_combine_ptr(pw->pw_name, bufubnd);
        pw->pw_passwd = __minifat_combine_ptr(pw->pw_passwd, bufubnd);
        pw->pw_gecos  = __minifat_combine_ptr(pw->pw_gecos, bufubnd);
        pw->pw_dir    = __minifat_combine_ptr(pw->pw_dir, bufubnd);
        pw->pw_shell  = __minifat_combine_ptr(pw->pw_shell, bufubnd);
        if (*res)  *res = __minifat_combine_ptr(*res, pwubnd);
    }
    return ret;
}

int minifat_getpwuid_r(uid_t uid, struct passwd *pw, char *buf, size_t size, struct passwd **res) {
    PTRTYPE pwubnd  = __minifat_extract_ubnd(pw);
    PTRTYPE bufubnd  = __minifat_extract_ubnd(buf);

    pw   = __minifat_uninstrument(pw);
    buf  = __minifat_uninstrument(buf);
    res  = __minifat_uninstrument(res);
    int ret = getpwuid_r(uid, pw, buf, size, res);
    if (!ret) {
        pw->pw_name   = __minifat_combine_ptr(pw->pw_name, bufubnd);
        pw->pw_passwd = __minifat_combine_ptr(pw->pw_passwd, bufubnd);
        pw->pw_gecos  = __minifat_combine_ptr(pw->pw_gecos, bufubnd);
        pw->pw_dir    = __minifat_combine_ptr(pw->pw_dir, bufubnd);
        pw->pw_shell  = __minifat_combine_ptr(pw->pw_shell, bufubnd);
        if (*res)  *res = __minifat_combine_ptr(*res, pwubnd);
    }
    return ret;
}

struct spwd *minifat_getspnam(const char *name) {
    // TODO: uses dummy (highest) bounds, no security here!
    PTRTYPE ubnd = __minifat_highest_bound();
    name = __minifat_uninstrument(name);
    struct spwd* ret = getspnam(name);
    if (ret) {
        ret->sp_namp = __minifat_combine_ptr(ret->sp_namp, ubnd);
        ret->sp_pwdp = __minifat_combine_ptr(ret->sp_pwdp, ubnd);
        ret = __minifat_combine_ptr(ret, ubnd);
    }
    return ret;
}

int minifat_getspnam_r(const char *name, struct spwd *sp, char *buf, size_t size, struct spwd **res) {
    PTRTYPE spubnd  = __minifat_extract_ubnd(sp);
    PTRTYPE bufubnd  = __minifat_extract_ubnd(buf);

    name = __minifat_uninstrument(name);
    sp   = __minifat_uninstrument(sp);
    buf  = __minifat_uninstrument(buf);
    res  = __minifat_uninstrument(res);
    int ret = getspnam_r(name, sp, buf, size, res);
    if (!ret) {
        sp->sp_namp = __minifat_combine_ptr(sp->sp_namp, bufubnd);
        sp->sp_pwdp = __minifat_combine_ptr(sp->sp_pwdp, bufubnd);
        if (*res)  *res = __minifat_combine_ptr(*res, spubnd);
    }
    return ret;
}

int minifat_putgrent(const struct group *gr, FILE *f) {
    // TODO: need to thread-safely copy-and-uninstrument gr
    //       such that original gr is not modified
    return -1;
}

int minifat_putpwent(const struct passwd *pw, FILE *f) {
    struct passwd inpw;
    pw = __minifat_uninstrument(pw);
    inpw.pw_name   = __minifat_uninstrument(pw->pw_name);
    inpw.pw_passwd = __minifat_uninstrument(pw->pw_passwd);
    inpw.pw_gecos  = __minifat_uninstrument(pw->pw_gecos);
    inpw.pw_dir    = __minifat_uninstrument(pw->pw_dir);
    inpw.pw_shell  = __minifat_uninstrument(pw->pw_shell);
    inpw.pw_uid    = pw->pw_uid;
    inpw.pw_gid    = pw->pw_gid;
    return putpwent(&inpw, f);
}

int minifat_putspent(const struct spwd *sp, FILE *f) {
    struct spwd insp;
    sp = __minifat_uninstrument(sp);
    insp.sp_namp   = __minifat_uninstrument(sp->sp_namp);
    insp.sp_pwdp   = __minifat_uninstrument(sp->sp_pwdp);
    insp.sp_lstchg = sp->sp_lstchg;
    insp.sp_min    = sp->sp_min;
    insp.sp_max    = sp->sp_max;
    insp.sp_warn   = sp->sp_warn;
    insp.sp_inact  = sp->sp_inact;
    insp.sp_expire = sp->sp_expire;
    insp.sp_flag   = sp->sp_flag;
    return putspent(&insp, f);
}

/* ------------------------------------------------------------------------- */
/* --------------------------------- math ---------------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: added only those needed by Apache and SPEC2006
double minifat_modf(double x, double *iptr);
double minifat_frexp(double x, int *e);

double minifat_modf(double x, double *iptr) {
    iptr = __minifat_uninstrument(iptr);
    return modf(x, iptr);
}

double minifat_frexp(double x, int *e) {
    e = __minifat_uninstrument(e);
    return frexp(x, e);
}


/* ------------------------------------------------------------------------- */
/* -------------------------------- signal --------------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: struct sigaction contains only func-ptrs -> no need to deep-uninstrument
int minifat_setitimer(int which, const struct itimerval *restrict new, struct itimerval *restrict old);
int minifat_sigaction(int sig, const struct sigaction *restrict sa, struct sigaction *restrict old);
int minifat_sigaddset(sigset_t *set, int sig);
int minifat_sigaltstack(const stack_t *restrict ss, stack_t *restrict old);
int minifat_sigandset(sigset_t *dest, const sigset_t *left, const sigset_t *right);
int minifat_sigdelset(sigset_t *set, int sig);
int minifat_sigemptyset(sigset_t *set);
int minifat_sigfillset(sigset_t *set);
int minifat_sigisemptyset(const sigset_t *set);
int minifat_sigismember(const sigset_t *set, int sig);
int minifat_sigsetjmp(sigjmp_buf buf, int ret);
_Noreturn void minifat_siglongjmp(sigjmp_buf buf, int ret);
int minifat_sigorset(sigset_t *dest, const sigset_t *left, const sigset_t *right);
int minifat_sigpending(sigset_t *set);
int minifat_sigprocmask(int how, const sigset_t *restrict set, sigset_t *restrict old);
int minifat_sigsuspend(const sigset_t *mask);
int minifat_sigwait(const sigset_t *restrict mask, int *restrict sig);
int minifat_sigtimedwait(const sigset_t *restrict mask, siginfo_t *restrict si, const struct timespec *restrict timeout);
int minifat_sigwaitinfo(const sigset_t *restrict mask, siginfo_t *restrict si);
void minifat_psignal(int sig, const char *msg);
void minifat_psiginfo(const siginfo_t *si, const char *msg);
int minifat_getitimer(int which, struct itimerval *old);

int minifat_getitimer(int which, struct itimerval *old) {
    if (old) old = __minifat_uninstrument(old);
    return getitimer(which, old);
}

void minifat_psiginfo(const siginfo_t *si, const char *msg) {
    si  = __minifat_uninstrument(si);
    msg = __minifat_uninstrument(msg);
    psiginfo(si, msg);
}

void minifat_psignal(int sig, const char *msg) {
    msg = __minifat_uninstrument(msg);
    psignal(sig, msg);
}

int minifat_setitimer(int which, const struct itimerval *restrict new, struct itimerval *restrict old) {
    if (new) new = __minifat_uninstrument(new);
    if (old) old = __minifat_uninstrument(old);
    return setitimer(which, new, old);
}

int minifat_sigaction(int sig, const struct sigaction *restrict sa, struct sigaction *restrict old) {
    if (sa)  sa = __minifat_uninstrument(sa);
    if (old) old = __minifat_uninstrument(old);
    return sigaction(sig, sa, old);
}

int minifat_sigaddset(sigset_t *set, int sig) {
    if (set)  set = __minifat_uninstrument(set);
    return sigaddset(set, sig);
}

int minifat_sigaltstack(const stack_t *restrict ss, stack_t *restrict old) {
    // TODO: implement it?
    return -1;
}

int minifat_sigandset(sigset_t *dest, const sigset_t *left, const sigset_t *right) {
    if (dest)  dest = __minifat_uninstrument(dest);
    if (left)  left = __minifat_uninstrument(left);
    if (right) right = __minifat_uninstrument(right);
    return sigandset(dest, left, right);
}

int minifat_sigdelset(sigset_t *set, int sig) {
    if (set)  set = __minifat_uninstrument(set);
    return sigdelset(set, sig);
}

int minifat_sigemptyset(sigset_t *set) {
    if (set)  set = __minifat_uninstrument(set);
    return sigemptyset(set);
}

int minifat_sigfillset(sigset_t *set) {
    if (set)  set = __minifat_uninstrument(set);
    return sigfillset(set);
}

int minifat_sigisemptyset(const sigset_t *set) {
    set = __minifat_uninstrument(set);
    return sigisemptyset(set);
}

int minifat_sigismember(const sigset_t *set, int sig) {
    set = __minifat_uninstrument(set);
    return sigismember(set, sig);
}

int minifat_sigsetjmp(sigjmp_buf buf, int ret) {
    buf = __minifat_uninstrument(buf);
    return sigsetjmp(buf, ret);
}

_Noreturn void minifat_siglongjmp(sigjmp_buf buf, int ret) {
    buf = __minifat_uninstrument(buf);
    siglongjmp(buf, ret);
}

int minifat_sigorset(sigset_t *dest, const sigset_t *left, const sigset_t *right) {
    if (dest)  dest = __minifat_uninstrument(dest);
    if (left)  left = __minifat_uninstrument(left);
    if (right) right = __minifat_uninstrument(right);
    return sigorset(dest, left, right);
}

int minifat_sigpending(sigset_t *set) {
    set = __minifat_uninstrument(set);
    return sigpending(set);
}

int minifat_sigprocmask(int how, const sigset_t *restrict set, sigset_t *restrict old) {
    if (set) set = __minifat_uninstrument(set);
    if (old) old = __minifat_uninstrument(old);
    return sigprocmask(how, set, old);
}

int minifat_sigsuspend(const sigset_t *mask) {
    mask = __minifat_uninstrument(mask);
    return sigsuspend(mask);
}

int minifat_sigwait(const sigset_t *restrict mask, int *restrict sig) {
    if (mask) mask = __minifat_uninstrument(mask);
    if (sig)  sig = __minifat_uninstrument(sig);
    return sigwait(mask, sig);
}

int minifat_sigtimedwait(const sigset_t *restrict mask, siginfo_t *restrict si, const struct timespec *restrict timeout) {
    if (mask) mask = __minifat_uninstrument(mask);
    if (si)   si = __minifat_uninstrument(si);
    if (timeout)   timeout = __minifat_uninstrument(timeout);
    return sigtimedwait(mask, si, timeout);
}

int minifat_sigwaitinfo(const sigset_t *restrict mask, siginfo_t *restrict si) {
    if (mask) mask = __minifat_uninstrument(mask);
    if (si)   si = __minifat_uninstrument(si);
    return sigwaitinfo(mask, si);
}

/* ------------------------------------------------------------------------- */
/* --------------------------------- ipc ----------------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: added only those needed by Apache stack
int minifat_semop(int id, struct sembuf *buf, size_t n);
int minifat_semtimedop(int id, struct sembuf *buf, size_t n, const struct timespec *ts);

int minifat_semop(int id, struct sembuf *buf, size_t n) {
    buf = __minifat_uninstrument(buf);
    return semop(id, buf, n);
}

int minifat_semtimedop(int id, struct sembuf *buf, size_t n, const struct timespec *ts) {
    buf = __minifat_uninstrument(buf);
    ts  = __minifat_uninstrument(ts);
    return semtimedop(id, buf, n, ts);
}


/* ------------------------------------------------------------------------- */
/* ------------------------------ multibyte -------------------------------- */
/* ------------------------------------------------------------------------- */
// NOTE: added only those needed by xalancbmk from SPEC2006

int minifat_mbtowc(wchar_t *restrict wc, const char *restrict src, size_t n);
int minifat_mblen(const char *s, size_t n);
size_t minifat_wcstombs(char *restrict s, const wchar_t *restrict ws, size_t n);
size_t minifat_mbstowcs(wchar_t *restrict ws, const char *restrict s, size_t wn);

int minifat_mbtowc(wchar_t *restrict wc, const char *restrict src, size_t n) {
    wc  = __minifat_uninstrument(wc);
    src = __minifat_uninstrument(src);
    return mbtowc(wc, src, n);
}

int minifat_mblen(const char *s, size_t n) {
    s  = __minifat_uninstrument(s);
    return mblen(s, n);
}

size_t minifat_wcstombs(char *restrict s, const wchar_t *restrict ws, size_t n) {
    ws = __minifat_uninstrument(ws);
    s  = __minifat_uninstrument(s);
    return wcstombs(s, ws, n);
}

size_t minifat_mbstowcs(wchar_t *restrict ws, const char *restrict s, size_t wn) {
    ws = __minifat_uninstrument(ws);
    s  = __minifat_uninstrument(s);
    return mbstowcs(ws, s, wn);
}


#ifdef __cplusplus
}
#endif
