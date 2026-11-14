/* Loads a BPF object's programs into the kernel (the verifier runs) on fresh, unpinned maps and attaches
 * nothing: proof that the object loads on this kernel, without touching a running layer. Root.
 * usage: bpf_verify OBJECT [PROGRAM...]   (programs: load only those; BPF_VERIFY_LOG=2: their full verifier log) */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

static int print(enum libbpf_print_level level, const char* format, va_list args)
{
    return level == LIBBPF_DEBUG ? 0 : vfprintf(stderr, format, args);
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: bpf_verify OBJECT [PROGRAM...]\n");
        return 2;
    }
    libbpf_set_print(print);
    struct rlimit files;   /* a descriptor per program: kfilter's syscall entry points pass a shell's 1024 */
    if (getrlimit(RLIMIT_NOFILE, &files) == 0 && files.rlim_cur < files.rlim_max) {
        files.rlim_cur = files.rlim_max;
        setrlimit(RLIMIT_NOFILE, &files);
    }
    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    if (!object) {
        perror("bpf_verify: open");
        return 1;
    }
    struct bpf_map* map;
    bpf_object__for_each_map(map, object) bpf_map__set_pin_path(map, NULL);   /* never a running layer's maps */
    struct bpf_program* program;
    const char* level = getenv("BPF_VERIFY_LOG");
    if (argc > 2) {
        bpf_object__for_each_program(program, object) {
            int keep = 0;
            for (int i = 2; i < argc; i++) keep |= strcmp(bpf_program__name(program), argv[i]) == 0;
            bpf_program__set_autoload(program, keep);
            if (keep && level) bpf_program__set_log_level(program, (__u32)atoi(level));
        }
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int error = bpf_object__load(object);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    unsigned total = 0, count = 0;
    if (error == 0) {
        bpf_object__for_each_program(program, object) {
            if (!bpf_program__autoload(program)) continue;
            struct bpf_prog_info info;
            __u32 length = sizeof(info);
            memset(&info, 0, sizeof(info));
            bpf_prog_get_info_by_fd(bpf_program__fd(program), &info, &length);
            printf("%-34s %8u verified insns\n", bpf_program__name(program), info.verified_insns);
            total += info.verified_insns;
            count++;
        }
    }
    printf("%s: %u programs, %u verified insns, load %.2f s: %s\n", argv[1], count, total,
           (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9, error ? strerror(-error) : "ok");
    bpf_object__close(object);
    return error ? 1 : 0;
}
