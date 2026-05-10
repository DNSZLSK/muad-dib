/*
 * uname-spoof.so - LD_PRELOAD shim that hides gVisor kernel signatures
 * by intercepting the uname(2) syscall and rewriting the release/version
 * fields with a credible Ubuntu AWS kernel string.
 *
 * Build: gcc -shared -fPIC -o uname-spoof.so uname-spoof.c -ldl
 *
 * Why: gVisor populates utsname.release with values like "4.4.0-gvisor"
 * which is a trivial sandbox fingerprint. Replacing it lets cli tools
 * (uname -a), Python platform.uname(), Go runtime/syscall and any other
 * native code see a believable kernel string.
 *
 * Only release and version are rewritten. sysname=Linux, nodename=<host>,
 * machine=x86_64 are real values that never leak gVisor identity.
 */
#define _GNU_SOURCE
#include <sys/utsname.h>
#include <string.h>
#include <dlfcn.h>

static int (*real_uname)(struct utsname *) = 0;

int uname(struct utsname *buf) {
    if (!real_uname) {
        real_uname = (int (*)(struct utsname *)) dlsym(RTLD_NEXT, "uname");
    }
    int r = real_uname ? real_uname(buf) : 0;
    if (r == 0 && buf) {
        strncpy(buf->release, "6.5.0-1015-aws", sizeof(buf->release) - 1);
        buf->release[sizeof(buf->release) - 1] = '\0';
        strncpy(buf->version, "#15-Ubuntu SMP Tue Jan 1 00:00:00 UTC 2026", sizeof(buf->version) - 1);
        buf->version[sizeof(buf->version) - 1] = '\0';
    }
    return r;
}
