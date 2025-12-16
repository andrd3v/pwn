#define _POSIX_C_SOURCE 200809L
#include <spawn.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

extern char **environ;

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

static unsigned char *parse_escapes(const char *s, size_t *out_len) {
    size_t cap = strlen(s) + 1;
    unsigned char *buf = malloc(cap);
    if (!buf) return NULL;
    size_t wi = 0;
    for (size_t i = 0; s[i] != '\0'; ++i) {
        if (s[i] == '\\') {
            ++i;
            if (s[i] == '\0') break;
            char c = s[i];
            if (c == 'n') buf[wi++] = '\n';
            else if (c == 'r') buf[wi++] = '\r';
            else if (c == 't') buf[wi++] = '\t';
            else if (c == '\\') buf[wi++] = '\\';
            else if (c == '0') buf[wi++] = '\0';
            else if (c == 'x' || c == 'X') {
                int hi = 0, lo = -1;
                if (isxdigit((unsigned char)s[i+1])) {
                    hi = (s[i+1] <= '9') ? s[i+1]-'0' : (tolower(s[i+1]) - 'a' + 10);
                    i++;
                    if (isxdigit((unsigned char)s[i+1])) {
                        lo = (s[i+1] <= '9') ? s[i+1]-'0' : (tolower(s[i+1]) - 'a' + 10);
                        i++;
                    }
                    if (lo >= 0) buf[wi++] = (unsigned char)((hi<<4) | lo);
                    else buf[wi++] = (unsigned char)(hi & 0xff);
                } else {
                    buf[wi++] = 'x';
                }
            } else {
                buf[wi++] = (unsigned char)c;
            }
        } else {
            buf[wi++] = (unsigned char)s[i];
        }
        if (wi + 4 >= cap) {
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
    }
    *out_len = wi;
    return buf;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program-to-run> [args...]\n", argv[0]);
        fprintf(stderr, "  Or: %s --suffix <program> [args...]  (runs program.orig)\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -ne \"...\"    provide bytes (C-style escapes) as stdin to the child\n");
        fprintf(stderr, "  -ie          interactive mode: each line is parsed with escapes and sent to child stdin\n");
        fprintf(stderr, "  -b           stop child with SIGSTOP right after spawn for debugger attach\n");
        return 2;
    }

    int use_suffix = 0;
    int arg_index = 1;
    char *ne_string = NULL;
    int break_at_main = 0;
    int interactive_ne = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--suffix") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing program after --suffix\n"); return 2; }
            use_suffix = 1;
            arg_index = i + 1;
            break;
        }
        if (strcmp(argv[i], "-ne") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "-ne requires an argument\n"); return 2; }
            ne_string = argv[i+1];
        }
        if (strcmp(argv[i], "-ie") == 0) {
            interactive_ne = 1;
        }
        if (strcmp(argv[i], "-b") == 0) {
            break_at_main = 1;
        }
    }

    if (ne_string && interactive_ne) {
        fprintf(stderr, "cannot use -ne and -ie together\n");
        return 2;
    }

    if (!use_suffix) {
        int found = 0;
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-ne") == 0) { ++i; continue; }
            if (strcmp(argv[i], "-ie") == 0) { continue; }
            if (strcmp(argv[i], "-b") == 0) { continue; }
            if (strcmp(argv[i], "--suffix") == 0) { continue; }
            arg_index = i;
            found = 1;
            break;
        }
        if (!found) {
            fprintf(stderr, "No target program specified\n");
            return 2;
        }
    }

    const char *target_in = argv[arg_index];
    char *target = NULL;
    char *suffix = ".orig";

    if (use_suffix) {
        size_t n = strlen(target_in) + strlen(suffix) + 1;
        target = malloc(n);
        if (!target) { perror("malloc"); return 1; }
        snprintf(target, n, "%s%s", target_in, suffix);
    } else {
        target = strdup(target_in);
        if (!target) { perror("strdup"); return 1; }
    }

    int max_args = argc - arg_index;
    char **argv_for_target = malloc((max_args + 1) * sizeof(char *));
    if (!argv_for_target) { perror("malloc"); free(target); return 1; }

    argv_for_target[0] = target;
    int ti = 1;
    for (int i = arg_index + 1; i < argc; ++i) {
        if (strcmp(argv[i], "-ne") == 0) { ++i; continue; }
        if (strcmp(argv[i], "-ie") == 0) { continue; }
        if (strcmp(argv[i], "-b") == 0) { continue; }
        if (strcmp(argv[i], "--suffix") == 0) { continue; }
        argv_for_target[ti++] = argv[i];
    }
    argv_for_target[ti] = NULL;

    int pipefd[2] = { -1, -1 };
    unsigned char *ne_buf = NULL;
    size_t ne_len = 0;
    posix_spawn_file_actions_t file_actions;
    int use_file_actions = 0;

    if (ne_string || interactive_ne) {
        if (pipe(pipefd) == -1) {
            perror("pipe");
            free(argv_for_target);
            free(target);
            return 1;
        }

        if (ne_string) {
            ne_buf = parse_escapes(ne_string, &ne_len);
            if (!ne_buf) {
                fprintf(stderr, "failed to parse -ne string\n");
                close(pipefd[0]);
                close(pipefd[1]);
                free(argv_for_target);
                free(target);
                return 1;
            }

            size_t off = 0;
            while (off < ne_len) {
                ssize_t n = write(pipefd[1], ne_buf + off, ne_len - off);
                if (n == -1) {
                    if (errno == EINTR) continue;
                    perror("write to pipe");
                    close(pipefd[0]);
                    close(pipefd[1]);
                    free(ne_buf);
                    free(argv_for_target);
                    free(target);
                    return 1;
                }
                off += (size_t)n;
            }

            close(pipefd[1]);
            pipefd[1] = -1;
        }

        if (posix_spawn_file_actions_init(&file_actions) != 0) {
            perror("posix_spawn_file_actions_init");
            close(pipefd[0]);
            if (pipefd[1] != -1) close(pipefd[1]);
            free(ne_buf);
            free(argv_for_target);
            free(target);
            return 1;
        }
        if (posix_spawn_file_actions_adddup2(&file_actions, pipefd[0], STDIN_FILENO) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            posix_spawn_file_actions_destroy(&file_actions);
            close(pipefd[0]);
            if (pipefd[1] != -1) close(pipefd[1]);
            free(ne_buf);
            free(argv_for_target);
            free(target);
            return 1;
        }
        if (posix_spawn_file_actions_addclose(&file_actions, pipefd[0]) != 0) {
            perror("posix_spawn_file_actions_addclose");
            posix_spawn_file_actions_destroy(&file_actions);
            close(pipefd[0]);
            if (pipefd[1] != -1) close(pipefd[1]);
            free(ne_buf);
            free(argv_for_target);
            free(target);
            return 1;
        }
        use_file_actions = 1;
    }

    posix_spawnattr_t attr;
    pid_t pid;
    int rc;

    if ((rc = posix_spawnattr_init(&attr)) != 0) {
        fprintf(stderr, "posix_spawnattr_init: %s\n", strerror(rc));
        if (use_file_actions) posix_spawn_file_actions_destroy(&file_actions);
        if (pipefd[0] != -1) close(pipefd[0]);
        if (pipefd[1] != -1) close(pipefd[1]);
        free(ne_buf);
        free(argv_for_target);
        free(target);
        return 1;
    }

    if ((rc = posix_spawnattr_setflags(&attr, _POSIX_SPAWN_DISABLE_ASLR)) != 0) {
        fprintf(stderr, "posix_spawnattr_setflags: %s\n", strerror(rc));
        posix_spawnattr_destroy(&attr);
        if (use_file_actions) posix_spawn_file_actions_destroy(&file_actions);
        if (pipefd[0] != -1) close(pipefd[0]);
        if (pipefd[1] != -1) close(pipefd[1]);
        free(ne_buf);
        free(argv_for_target);
        free(target);
        return 1;
    }

    if (use_file_actions) {
        rc = posix_spawnp(&pid, argv_for_target[0], &file_actions, &attr, argv_for_target, environ);
    } else {
        rc = posix_spawnp(&pid, argv_for_target[0], NULL, &attr, argv_for_target, environ);
    }

    if (rc != 0) {
        fprintf(stderr, "posix_spawnp: %s\n", strerror(rc));
        posix_spawnattr_destroy(&attr);
        if (use_file_actions) posix_spawn_file_actions_destroy(&file_actions);
        if (pipefd[0] != -1) close(pipefd[0]);
        if (pipefd[1] != -1) close(pipefd[1]);
        free(ne_buf);
        free(argv_for_target);
        free(target);
        return 1;
    }

    if (break_at_main) {
        if (kill(pid, SIGSTOP) != 0) {
            perror("kill(SIGSTOP)");
        } else {
            fprintf(stderr, "child %d stopped, attach with: lldb -p %d\n", (int)pid, (int)pid);
        }
    }

    if (pipefd[0] != -1) {
        close(pipefd[0]);
        pipefd[0] = -1;
    }

    posix_spawnattr_destroy(&attr);
    if (use_file_actions) posix_spawn_file_actions_destroy(&file_actions);

    if (interactive_ne && pipefd[1] != -1) {
        char line[4096];
        while (fgets(line, sizeof(line), stdin) != NULL) {
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }

            size_t out_len = 0;
            unsigned char *buf = parse_escapes(line, &out_len);
            if (!buf) {
                fprintf(stderr, "failed to parse input line\n");
                break;
            }

            size_t off = 0;
            while (off < out_len) {
                ssize_t n = write(pipefd[1], buf + off, out_len - off);
                if (n == -1) {
                    if (errno == EINTR) continue;
                    perror("write to child stdin");
                    free(buf);
                    goto done_interactive;
                }
                off += (size_t)n;
            }
            free(buf);

            unsigned char nl = '\n';
            ssize_t n = write(pipefd[1], &nl, 1);
            if (n == -1) {
                if (errno == EINTR) continue;
                perror("write newline to child stdin");
                goto done_interactive;
            }
        }
    done_interactive:
        close(pipefd[1]);
        pipefd[1] = -1;
    }


    if (waitpid(pid, &rc, 0) == -1) {
        perror("waitpid");
        free(ne_buf);
        free(argv_for_target);
        free(target);
        return 1;
    }

    free(ne_buf);
    free(argv_for_target);
    free(target);

    if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    } else if (WIFSIGNALED(rc)) {
        fprintf(stderr, "child terminated by signal %d\n", WTERMSIG(rc));
        return 128 + WTERMSIG(rc);
    } else {
        fprintf(stderr, "child ended abnormally\n");
        return 1;
    }
}
