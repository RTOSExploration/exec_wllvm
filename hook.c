#define _GNU_SOURCE /* for execvpe() */
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
//#include <stdlib.h>

int log_fd = -1;

static void log_execve(const char *pathname, char *const argv[],
                       char *const envp[]) {
  if (log_fd < 0) return;
  //fprintf(stderr, "myexec: [%d] %s\n", getpid(), pathname);
  static char buf[10000];
  char *p = buf;
  char *bufend = buf + sizeof(buf) - 1; // -1 for '\n'
  int n;

#define LOG(...) \
  do { \
    n = snprintf(p, bufend - p, __VA_ARGS__); \
    if (n < 0) \
      return; \
    else if (n >= bufend - p) \
      p = bufend - 1; \
    else \
      p += n; \
  } while (0)

  LOG("%d %s, [", getpid(), pathname);
  for (; *argv; ++argv) {
    LOG("%s, ", *argv);
  }
  LOG("], [");
  for (; *envp; ++envp) {
    const char *ls_colors = "LS_COLORS";
    if (strncmp(*envp, ls_colors, strlen(ls_colors)) != 0) {
      LOG("%s, ", *envp);
    }
  }
  LOG("]");
  snprintf(p, 2, "\n");

  int len = p - buf + 1; // +1 for the terminating '\0'
  ssize_t ret = (ssize_t)syscall_no_intercept(SYS_write, log_fd, buf, len);
  int err = syscall_error_code(ret);
  if (err != 0)
    fprintf(stderr, "myexec: write: %s\n", strerror(err));
  else if (ret != len)
    fprintf(stderr, "myexec: write: %zd bytes transferred, expected %d bytes\n",
            ret, len);
}

static enum compiler_type { NOT_COMPILER, C_COMPILER, CXX_COMPILER }
is_compiler(const char *pathname) {
  regex_t regex;
  int reti;
  enum compiler_type com_t = NOT_COMPILER;

  reti = regcomp(&regex, "bin/arm-.*-(gcc|(c|g)\\+\\+)$", REG_EXTENDED);
  if (reti) {
    fprintf(stderr, "myexec: Could not compile regex\n");
    goto err;
  }
  reti = regexec(&regex, pathname, 0, NULL, 0);
  if (!reti) {
    //fprintf(stderr, "myexec: Match %s\n", pathname);
    com_t = pathname[strlen(pathname) - 1] == '+' ? CXX_COMPILER : C_COMPILER;
  }

err:
  regfree(&regex);
  return com_t;
}

static int exec_wllvm(const char *pathname, char *const argv[],
                      char *const envp[], enum compiler_type com_t) {
  int argc = 0;
  while (argv[argc])
    ++argc;
  char *new_argv[argc + 1];
  new_argv[0] = (com_t == C_COMPILER) ? "wllvm" : "wllvm++";
  memcpy(new_argv + 1, argv + 1, argc * sizeof(char *));

  const char *str_binutils = "BINUTILS_TARGET_PREFIX=";
  char env_binutils[strlen(str_binutils) + strlen(pathname) + 1];
  strcpy(env_binutils, str_binutils);
  strcat(env_binutils, pathname);
  env_binutils[strlen(env_binutils) - 4] = '\0';

  int envp_c = 0;
  while (envp[envp_c])
    ++envp_c;
  int new_envp_idx = 1;
  char *new_envp[envp_c + new_envp_idx + 1];
//  new_envp[0] = "WLLVM_OUTPUT_LEVEL=INFO",
//  new_envp[1] = "LLVM_COMPILER=hybrid",
//  new_envp[2] = "LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin",
  new_envp[0] = env_binutils;
  for (int i = 0; i < envp_c; i++) {
    const char *ld_preload = "LD_PRELOAD=";
    // do not copy LD_PRELOAD=
    if (strncmp(envp[i], ld_preload, strlen(ld_preload)) != 0) {
      new_envp[new_envp_idx++] = envp[i];
    }
  }
  new_envp[new_envp_idx] = NULL;
  //log_execve(new_argv[0], new_argv, new_envp);
  //(int)syscall_no_intercept(SYS_execve, new_argv[0], new_argv, new_envp);
  execvpe(new_argv[0], new_argv, new_envp);
  fprintf(stderr, "myexec: execvpe(\"wllvm\", ...) failed\n");
  return -errno;
}

static int
hook(long syscall_number,
     long arg0, long arg1,
     long arg2, long arg3,
     long arg4, long arg5,
     long *result)
{
  if (syscall_number == SYS_execve) {
    /*
     * Intercept execve syscall
     */
    const char *pathname = (const char *)arg0;
    char **argv = (char **)arg1;
    char **envp = (char **)arg2;
    log_execve(pathname, argv, envp);
    enum compiler_type com_t = is_compiler(pathname);
    if (com_t == NOT_COMPILER) {
      return 1;
    }
    *result = exec_wllvm(pathname, argv, envp, com_t);
    return 0;
  } else if (syscall_number == SYS_close && (int)arg0 == log_fd) {
    /* prevent log file from being closed */
    *result = -EBADF;
    return 0;
  } else {
    /*
     * Ignore any other syscalls
     * i.e.: pass them on to the kernel
     * as would normally happen.
     */
    return 1;
  }
}

static __attribute__((constructor)) void
init(void)
{
  // Set up the callback function
  intercept_hook_point = hook;
  log_fd = (int)syscall_no_intercept(
      SYS_open, "/tmp/intercept.log",
      O_WRONLY | O_CREAT | O_APPEND | O_SYNC | O_CLOEXEC, (mode_t)0600);
  int err = syscall_error_code(log_fd);
  if (err != 0)
    fprintf(stderr, "myexec: open: %s", strerror(err));
}
