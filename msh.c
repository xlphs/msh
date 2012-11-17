#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <wordexp.h>

#define MAX_CHAR_BUFF_LEN  512
#define MAX_HASHTABLE_LEN  1024
#define MSH_EXITINT        -99

extern int errno;
extern char **environ;

/* Constants for piping and redirection */
const int PIPE_READ = 0;
const int PIPE_WRITE = 1;
const int FD_READ = 0;
const int FD_WRITE = 1;

/* The current user's name */
static char *username;

/* Split PATH components */
static char **var_paths;
static char var_path_count;

/* Set global debugging on or off
 To turn on debugging: debug 1
 To turn off debugging: debug 0 */
static unsigned char is_debugging = '0';

/* Character Input Buffer */
static int ibuff_index = 0;
static char ibuffer[512] = {0};
static int ibuffer_len = sizeof (ibuffer);

/* Active foreground child process */
static unsigned int chpid = 0;

/* Number of background processes */
static unsigned int bgchld = 0;

static jmp_buf toplevel_jmp;

typedef struct WORD_LIST {
    char *word;
    char process; /* Process in wordlist_to_argv(1) */
    struct WORD_LIST *next;
} WordList;

enum redir_action {
    r_no_direction = 0,
    r_output_direction = 1,
    r_input_direction = 2,
    r_input_output = 3,
    r_appending_to = 4
};

typedef struct REDIRECT {
    char *filename; /* File to open */
    int flags; /* Flag value for open() */
    enum redir_action action; /* What to do with data */
    struct REDIRECT *next;
} Redirect;

enum command_type {
    c_ignore = 0, /* To indicate an invalid command */
    c_foreground = 1, /* Execute in foreground (default) */
    c_builtin = 2 /* Builtin shell command */
};

typedef struct COMMANDFLAGS {
    unsigned int cmd_bg:1; /* Overrides c_foreground */
    unsigned int cmd_file:1; /* Look for file in current directory */
} command_flags;

typedef struct COMMAND {
    enum command_type type;
    command_flags *flags;
    WordList *words;
    Redirect *redir; /* Redirection(s) to perform */
    struct COMMAND *pipe_to; /* Pipe(s) to to perform */
} Command;

typedef struct HASH_ITEM {
    unsigned int hash;
    char *key;
    char *data;
    int (*bfun)(Command *); /* Built-in function */
    struct HASH_ITEM *next;
} HashItem;

typedef struct HASH_TABLE {
    HashItem **entries;
    int count;
} HashTable;

HashTable *global_hashtable;

Command *global_command;

// This is here because it is important
int execute_command_simple(char *, char **, int *,
                           enum redir_action, enum command_type,
                           command_flags);

void trap_exit(int s) {
    if (s == SIGSEGV || s == SIGABRT) {
        longjmp(toplevel_jmp, 3);
        return;
    }
    if (bgchld > 0) {
        // warn user about background jobs
        longjmp(toplevel_jmp, 2);
        return;
    }
    if (chpid == 0) {
        // prompt user to use exit
        longjmp(toplevel_jmp, 1);
        return;
    }
}

void init_exit_traps() {
    signal(SIGINT, trap_exit);
    signal(SIGABRT, trap_exit);
    signal(SIGTERM, trap_exit);
    signal(SIGSEGV, trap_exit);
}

void restore_traps()  {
    signal(SIGINT, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
}

void chld_trap(int s) {
    // wait on bg child process to really finish
    int pid = waitpid(-1, NULL, WNOHANG);
    if (pid < 0) {
        // waitpid went wrong
        return;
    }
    if (pid != chpid && chpid != 0) {
        bgchld--;
    }
}

void init_child_traps() {
    // this is here for background jobs
    signal(SIGCHLD, chld_trap);
}

void dealloc_hashitem(HashItem *i) {
    if (i->key != NULL) free(i->key);
    if (i->data != NULL) free(i->data);
    if (i->next != NULL) dealloc_hashitem(i->next);
    free(i);
}

void dealloc_hashtable(HashTable *table) {
    if (table->entries != NULL) {
        int i = 0;
        for ( ; i < table->count; i++) {
            if (table->entries[i] != NULL) {
                dealloc_hashitem(table->entries[i]);
            }
        }
        free(table->entries);
    }
    free(table);
}

HashItem* alloc_hashitem() {
    HashItem *i = malloc( sizeof(HashItem) );
    i->hash = 0;
    i->key = NULL;
    i->bfun = NULL;
    i->data = NULL;
    i->next = NULL;
    return i;
}

HashTable* alloc_hashtable() {
    int i = 0;
    HashTable *t = malloc( sizeof(HashTable) );
    t->count = MAX_HASHTABLE_LEN;
    t->entries = malloc( t->count*sizeof(HashTable) );
    for ( ; i < t->count; i++) {
        t->entries[i] = NULL;
    }
    return t;
}

unsigned int hash_string(const char *s) {
    unsigned int hash = 0;
    
    /* "The best string hash function" from BASH
     The magic is in the interesting relationship between the special prime
     16777619 (2^24 + 403) and 2^32 and 2^8. */
    for (hash = 0; *s; s++) {
        hash *= 16777619;
        hash ^= *s;
    }
    
    // Reduce hash value, not a good idea
    // but I just want a tiny hash table
    while (!(hash < MAX_HASHTABLE_LEN)) {
        hash = hash % 64; // 64 is a power of 2
    }
    
    return hash;
}

/* Returns a newly allocated HashItem */
HashItem* hashtable_insert(HashTable *t, const char *s) {
    HashItem *item = alloc_hashitem();
    int hash = hash_string(s);
    item->hash = hash;
    item->key = malloc( (strlen(s)+1)*sizeof(char) );
    strcpy(item->key, s);
    if (t->entries[hash] == NULL) {
        t->entries[hash] = item;
    } else {
        HashItem *last = t->entries[hash];
        while (last->next != NULL) {
            last = last->next;
        }
        last->next = item;
    }
    return item;
}

/* Returns an existing HashItem or NULL,
   so we can free its memory */
HashItem* hashtable_remove(HashTable *t, const char *s) {
    int hash = hash_string(s);
    HashItem *i, *prev = NULL;
    
    if (t->entries[hash] == NULL) return (HashItem *)NULL;
    
    t->count--;
    i = t->entries[hash];
    while (i->next != NULL) {
        prev = i;
        i = i->next;
        if (strcmp(s, prev->key) == 0) {
            break;
        }
    }
    if (prev != NULL) {
        prev->next = NULL;
        return i;
    } else {
        t->entries[hash] = NULL;
    }
    return i;
}

/* Returns an existing HashItem or NULL */
HashItem* hashtable_find(HashTable *t, const char *s) {
    int hash = hash_string(s);
    HashItem *i = t->entries[hash];
    
    if (i == NULL) return (HashItem *)NULL;
    while (i->next != NULL) {
        if (strcmp(s, i->key) == 0) {
            return i;
        }
        i = i->next;
    }
    return i;
}

void dealloc_redir(Redirect *r) {
    if (r->filename != NULL) free(r->filename);
    if (r->next != NULL) dealloc_redir(r->next);
    free(r);
}

void dealloc_word_list(WordList* wl) {
    if (wl->word != NULL) free(wl->word);
    if (wl->next != NULL) dealloc_word_list(wl->next);
    free(wl);
}

void dealloc_command(Command *c) {
    if (c->words != NULL) dealloc_word_list(c->words);
    if (c->redir != NULL) dealloc_redir(c->redir);
    if (c->pipe_to != NULL) dealloc_command(c->pipe_to);
    if (c->flags != NULL) free(c->flags);
    free(c);
}

WordList* alloc_word_list() {
    WordList *wl = malloc( sizeof(WordList) );
    wl->word = NULL;
    wl->process = 0;
    wl->next = NULL;
    return wl;
}

Redirect* alloc_redirect() {
    Redirect *r = malloc( sizeof(Redirect) );
    r->filename = NULL;
    r->flags = 0;
    r->action = 0;
    r->next = NULL;
    return r;
}

Command* alloc_command() {
    Command *c = malloc( sizeof(Command) );
    c->type = 0;
    c->flags = malloc( sizeof(command_flags) );
    c->flags = memset(c->flags, 0, sizeof(command_flags));
    c->words = NULL;
    c->redir = NULL;
    c->pipe_to = NULL;
    return c;
}

/* If path is a directory, returns 0, otherwise -1 */
int is_directory(const char *path) {
    struct stat info;
    if (stat(path, &info) != 0) {
        return (-1);
    }
    if (S_ISDIR(info.st_mode) != 0 && S_ISREG(info.st_mode) == 0) return 0;
    return -1;
}

/* If path is a file, returns 0, otherwise -1 */
int is_file(const char *path) {
    struct stat info;
    if (stat(path, &info) != 0) {
        return (-1);
    }
    if (S_ISDIR(info.st_mode) == 0 && S_ISREG(info.st_mode) != 0) return 0;
    return -1;
}

/* Append file to path, returns a newly allocated string */
char* merge_path(char *path, char*file) {
    int len_a = (int)strlen(path), len_b = (int)strlen(file);
    char *s = malloc( (len_a+len_b+2)*sizeof(char) );
    s[0] = 0;
    strcat(s, path);
    strcat(s, "/");
    strcat(s, file);
    return s;
}

/* Converts WordList to an array of strings, for use with execv(). */
char** wordlist_to_argv(WordList *list) {
    char **argv;
    WordList *l = list;
    int len = 0, i = 0;
    while (l != NULL) {
        len++;
        l = l->next;
        /* Do additional processing here if process is set. */
        if (l != NULL && l->process > 0) {
            if (strchr(l->word, '~') != NULL) {
                // tilde expansion
                char *homedir = getenv("HOME");
                int hlen = (int)strlen(homedir);
                if (hlen < 0) {
                    printf("Home directory not found\n");
                } else {
                    // replace ~ with homedir
                    char *result = malloc( (strlen(l->word)+hlen+1)*sizeof(char) );
                    char *pch = l->word;
                    int i = 0;
                    // only replace the first occurrence
                    while (*pch != '~') {
                        result[i] = *pch;
                        i++;
                    }
                    result[i] = '\0';
                    strcat(result, homedir);
                    i += hlen;
                    result[i] = '\0';
                    pch++; // skip past ~
                    strcat(result, pch);
                    if (is_debugging == '1') {
                        printf("[%s] => %s\n", l->word, result);
                    }
                    free(l->word);
                    l->word = result;
                }
            }
            if (strchr(l->word, '*') != NULL || strchr(l->word, '?') != NULL) {
                // handle wildcards
                wordexp_t p;
                int r = wordexp(l->word, &p, WRDE_NOCMD);
                if (r == 0) {
                    int i;
                    char **w;
                    w = p.we_wordv;
                    if (is_debugging == '1') {
                        printf("[%s] => %i matches\n", l->word, (int)p.we_wordc);
                    }
                    for (i = 0; i < p.we_wordc; i++) {
                        if (i > 0) {
                            if (l->next == NULL) {
                                l->next = alloc_word_list();
                                len++;
                            }
                            l = l->next;
                        }
                        if (l->word != NULL) free(l->word);
                        l->word = strdup(w[i]);
                    }
                    // need a NULL at the end
                    if (l->next == NULL) {
                        l->next = alloc_word_list();
                        len++;
                    }
                }
                else if (r == WRDE_SYNTAX) {
                    printf("syntax error near %s\n", l->word);
                }
                wordfree(&p);
            }
        }
    }
    argv = malloc( len*sizeof(char*) );
    l = list;
    while (i < len) {
        argv[i] = l->word;
        l = l->next;
        i++;
    }
    return argv;
}

/* If path exists, returns 0, otherwise -1.
   For use with lookup_command() */
int file_exist(const char *path) {
    struct stat info;
    return stat(path, &info) < 0 ? -1 : 0;
}

/* Look up a command, returns a newly allocated string or NULL */
char* lookup_command(char *command) {
    int i = 0;
    for ( ; i<var_path_count; i++) {
        char *path = var_paths[i];
        char *fullpath = merge_path(path, command);
        if ( file_exist(fullpath) == 0) {
            return fullpath;
        } else {
            free(fullpath);
        }
    }
    return (char *)NULL;
}

/* For use with execute_command_pipeline() */
int do_piping(int pipe_in, int pipe_out, char *path, char **args) {
    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        if (pipe_in != STDIN_FILENO) {
            dup2(pipe_in, STDIN_FILENO);
            close(pipe_in);
        }
        if (pipe_out != STDOUT_FILENO) {
            dup2(pipe_out, STDOUT_FILENO);
            close(pipe_out);
        }
        
        restore_traps();
        int rs = execv(path, args);
        if (rs < 0) {
            // execv failed
            perror(path);
            return -1;
        }
        exit(0);
    } else {
        chpid = pid;
    }
    return pid;
}

int execute_command_pipeline(Command *comm) {
    int fds[2];
    int filedes[2] = {0};
    int in = 0, status;
    Command *cmd = comm;
    enum redir_action last_flag = r_no_direction;
    
    // fork all processes except for the last one
    while (cmd->pipe_to != NULL) {
        pipe(fds);
        
        // prepare for forking
        char *path = lookup_command(cmd->words->word);
        if (path == NULL) {
            printf("%s: command not found\n", cmd->words->word);
            free(path);
            return 0;
        }
        char **args = wordlist_to_argv(cmd->words);
        
        // check for redirection
        // only input redirection is allowed to be mixed with pipes
        int redirfd = in;
        if (cmd->redir != NULL && cmd->redir->action == r_input_direction) {
            // replace pipe_in with fd
            redirfd = open(cmd->redir->filename, cmd->redir->flags, 0006);
            if (redirfd < 0) {
                printf("Failed to open: %s\n", cmd->redir->filename);
                free(path);
                return 0;
            }
        }
        
        // use the in value from previous iteration
        status = do_piping(redirfd, fds[PIPE_WRITE], path, args);
        
        close(fds[PIPE_WRITE]);
        
        // keep track of the read end of the pipe
        // the next child process will read from there
        in = fds[PIPE_READ];
        
        cmd = cmd->pipe_to;
        free(path);
        if (cmd->redir != NULL && cmd->redir->action == r_input_direction) {
            close(redirfd);
        }
        
        if (status < 0) {
            if (is_debugging == '1') {
                printf("%s: error %d during pipe\n", path, errno);
            }
            exit(0);
        }
    }
    
    /* Last stage of the pipeline,
     set STDIN be the read end of the previous pipe
     and output to the current STDOUT. */
    if (in != STDIN_FILENO) {
        filedes[PIPE_READ] = in;
        last_flag = r_input_direction;
    }
    char *path = lookup_command(cmd->words->word);
    if (path == NULL) {
        printf("%s: command not found\n", cmd->words->word);
        free(path);
        return 0;
    }
    if (cmd->redir != NULL) {
        /* Do redirection */
        filedes[PIPE_WRITE] = open(cmd->redir->filename, cmd->redir->flags, 0666);
        if (filedes[PIPE_WRITE] < 0) {
            printf("Failed to open: %s\n", cmd->redir->filename);
            return 0;
        }
        last_flag = r_input_output;
    }
    
    char **args = wordlist_to_argv(cmd->words);
    status = execute_command_simple(path, args, filedes, last_flag, c_foreground, *cmd->flags);
    if (filedes[PIPE_WRITE] > 0) {
        close(filedes[PIPE_WRITE]);
    }
    free(args);
    return status;
}

int execute_command_simple(char *path, char **args, int fds[2],
                           enum redir_action fd_flag,
                           enum command_type cmd_type,
                           command_flags flags)
{
    // fork and execute
    int pid = fork();
    int status = 0;
    
    if (pid < 0) {
        printf("fork failed\n");
        return -1;
    }
    else if (pid == 0) {
        // child process
        switch (fd_flag) {
            case r_appending_to:
            case r_output_direction: {
                dup2(fds[PIPE_WRITE], STDOUT_FILENO);
                close(fds[PIPE_WRITE]);
            } break;
            case r_input_direction: {
                dup2(fds[PIPE_READ], STDIN_FILENO);
                close(fds[PIPE_READ]);
            } break;
            case r_input_output: {
                // for example: grep -i root < /etc/passwd > sorted
                // Make the fd of sorted as stdout of the command
                // AND make the fd of passwd as stdin of the command
                dup2(fds[PIPE_READ], STDIN_FILENO); // fds[PIPE_READ] is /etc/passwd
                dup2(fds[PIPE_WRITE], STDOUT_FILENO); // fd2 is sorted
                close(fds[PIPE_READ]);
                close(fds[PIPE_WRITE]);
            } break;
            default: break;
        }
        
        restore_traps();
        int rs = execv(path, args);
        if (rs == -1) {
            // execv failed
            perror(path);
        }
        
        exit(0);
    }
    else {
        // parent process
        if (flags.cmd_bg) {
            // Note: background process stdout/stderr not redirected
            bgchld++;
            init_child_traps();
            setpgid(0, 0);
            printf("bg: %i\n", pid);
            return 0;
        }
        
        chpid = pid;
        waitpid(pid, &status, 0);
        if (is_debugging == '1') {
            printf("child %i exited with %i\n", pid, status);
        }
        chpid = 0;
    }
    return status;
}

int msh_exit(Command *comm) {
    return MSH_EXITINT;
}

int msh_cd(Command *comm) {
    char **argv = wordlist_to_argv(comm->words);
    char *p = argv[1];
    if (strlen(p) == 0) {
        chdir(getenv("HOME"));
        return 0;
    }
    int r = chdir(p);
    if (r == -1) {
        perror("chdir");
    }
    free(argv);
    return 0;
}

int msh_set(Command *comm) {
    WordList *name = comm->words->next;
    if (name->word == NULL) return 0;
    if (name->next == NULL) return 0;
    WordList *val = name->next;
    if (val->word == NULL) return 0;
    
    HashItem *item = hashtable_find(global_hashtable, name->word);
    if (item == NULL) {
        item = hashtable_insert(global_hashtable, name->word);
        item->data = malloc( (strlen(val->word)+1)*sizeof(char) );
        strcpy(item->data, val->word);
    } else {
        free(item->data);
        item->data = malloc( (strlen(val->word)+1)*sizeof(char) );
        strcpy(item->data, val->word);
    }
    
    return 0;
}

int msh_unset(Command *comm) {
    WordList *name = comm->words->next;
    if (name->word == NULL) return 0;
    hashtable_remove(global_hashtable, name->word);
    return 0;
}

int msh_setdebug(Command *comm) {
    WordList *wl = comm->words->next;
    if (wl->word == NULL) return 0;
    is_debugging = *wl->word;
    return 0;
}

int msh_hash(Command *comm) {
    WordList *wl = comm->words->next;
    if (wl->word == NULL) return 0;
    printf("%i\n", hash_string(wl->word));
    return 0;
}

int msh_parse(Command *comm) {
    WordList *wl = comm->words->next;
    while (wl != NULL) {
        printf("%s%c", wl->word, (wl->next == NULL) ? ' ' : ',');
        wl = wl->next;
    }
    printf("\nredir:");
    Redirect *r = comm->redir;
    while (r != NULL) {
        printf("%s%c", r->filename, (r->next == NULL) ? ' ' : ',');
        r = r->next;
    }
    printf("\npipe:");
    Command *c = comm->pipe_to;
    while (c != NULL) {
        printf("%s%c", c->words->word, (c->pipe_to == NULL) ? ' ' : ',');
        c = c->pipe_to;
    }
    printf("\n");
    return 0;
}

int msh_printenv(Command *comm) {
    WordList *wl = comm->words->next;
    if (wl->word == NULL) {
        char **env = environ;
        for ( ; *env; env++) {
            printf("%s\n", *env);
        }
    }
    else {
        printf("%s\n", getenv(wl->word));
    }
    return 0;
}

void init_builtin_cmd() {
    HashItem *i;
    
    i = hashtable_insert(global_hashtable, "exit");
    i->bfun = msh_exit;
    
    i = hashtable_insert(global_hashtable, "cd");
    i->bfun = msh_cd;
    
    i = hashtable_insert(global_hashtable, "set");
    i->bfun = msh_set;
    
    i = hashtable_insert(global_hashtable, "unset");
    i->bfun = msh_unset;
    
    i = hashtable_insert(global_hashtable, "hash");
    i->bfun = msh_hash;
    
    i = hashtable_insert(global_hashtable, "debug");
    i->bfun = msh_setdebug;
    
    i = hashtable_insert(global_hashtable, "parse");
    i->bfun = msh_parse;
    
    i = hashtable_insert(global_hashtable, "printenv");
    i->bfun = msh_printenv;
}

/* Returns 1 for true, 0 for false. */
int is_builtin_cmd(char *command) {
    return (hashtable_find(global_hashtable, command) != NULL) ? 1:0;
}

/* Returns 0, or MSH_EXITINT */
int execute_command_builtin(Command *comm) {
    HashItem *i = hashtable_find(global_hashtable, comm->words->word);
    return i->bfun(comm);
}

int execute_command(Command *comm) {
    char *command = comm->words->word;
    
    // check for builtin command
    if (is_builtin_cmd(command)) {
        return execute_command_builtin(comm);
    }
    
    // check if we should do piping
    if (comm->pipe_to != NULL) {
        return execute_command_pipeline(comm);
    }
    
    char *path;
    
    // check for executable file
    if (comm->flags->cmd_file) {
        // prepend the exec file path with current directory
        char *pwd = getenv("PWD");
        char *file = comm->words->word;
        file++; // skip the beginning dot
        int len_a = (int)strlen(pwd), len_b = (int)strlen(file);
        path = malloc( (len_a+len_b+1)*sizeof(char) );
        path[0] = 0;
        strcat(path, pwd);
        strcat(path, file);
    }
    else {
        // look up (the first) command
        path = lookup_command(command);
        if (path == NULL) {
            if ( is_directory(command) == 0 ) {
                printf("%s: is a directory\n", command);
            } else {
                if ( is_file(command) == 0 ) {
                    printf("%s: is a file\n", command);
                } else {
                    printf("%s: command not found\n", command);
                }
            }
            return 0;
        }
    }
    
    char **args = wordlist_to_argv(comm->words);
    
    // handle redirection
    int result;
    int fileds[2] = {0};
    enum redir_action last_redir_act = 0;
    if (comm->redir != NULL) {
        last_redir_act = comm->redir->action;
        
        // prepare file descriptors
        switch (comm->redir->action) {
            case r_input_direction: {
                // 0006 => -------r--
                fileds[PIPE_READ] = open(comm->redir->filename, comm->redir->flags, 0006);
                if (fileds[PIPE_READ] < 0) {
                    printf("Failed to open: %s\n", comm->redir->filename);
                }
            } break;
            case r_output_direction: {
                // 0666 => -rw-r--r--
                fileds[PIPE_WRITE] = open(comm->redir->filename, comm->redir->flags, 0666);
                if (fileds[PIPE_WRITE] < 0) {
                    printf("Failed to open: %s\n", comm->redir->filename);
                }
            } break;
            case r_input_output: {
                // open file for read
                Redirect *re = comm->redir;
                fileds[PIPE_READ] = open(re->filename, re->flags, 0006);
                if (fileds[PIPE_READ] < 0) {
                    printf("Failed to open: %s\n", re->filename);
                    break;
                }
                // open file for write
                re = comm->redir->next;
                fileds[PIPE_WRITE] = open(re->filename, re->flags, 0666);
                if (fileds[PIPE_WRITE] < 0) {
                    printf("Failed to open: %s\n", re->filename);
                    close(fileds[PIPE_READ]);
                }
            } break;
            case r_appending_to: {
                // open file for append
                fileds[PIPE_WRITE] = open(comm->redir->filename, comm->redir->flags, 0666);
                if (fileds[PIPE_WRITE] < 0) {
                    printf("Failed to open: %s\n", comm->redir->filename);
                }
            } break;
            default: break;
        }
        if (fileds[PIPE_READ] < 0 || fileds[PIPE_WRITE] < 0) {
            free(path);
            return 1;
        }
    }
    
    result = execute_command_simple(path, args, fileds, last_redir_act, comm->type, *comm->flags);
    // close opened file descriptors
    if (fileds[PIPE_READ] > 0 ) close(fileds[PIPE_READ]);
    if (fileds[PIPE_WRITE] > 0) close(fileds[PIPE_WRITE]);
    
    free(path);
    free(args);
    
    return result;
}

void flush_toilet() {
    // clear buffer, cached data
    chpid = 0;
    int i = 0;
    for ( ; i<=ibuff_index; i++) ibuffer[i] = 0;
    ibuff_index = 0;
    dealloc_command(global_command);
    global_command = alloc_command();
    global_command->words = alloc_word_list();
}

void getchar_loop() {
    char c;
    while (c != '\n') {
        if ((c = getchar()) == EOF) {
            // terminate upon ctrl+D
            exit(0);
        }
        // check for allowed char
        if (c >= ' ' && c <= '~') {
            ibuffer[ibuff_index] = c;
            ibuff_index++;
            
            if (ibuff_index >= ibuffer_len) return;
        }
    }
}

/* Returns index of ending quote or -1 if not found */
int parse_find_end_quote(int ibuff_start) {
    int i = ibuff_start;
    
    if (ibuffer[i] == '"') i++;
    while (1) {
        if (ibuffer[i] == '"') {
            if ((i-1) != 0 && ibuffer[i-1] != '\\') {
                break;
            }
        }
        else if (ibuffer[i] == '\0') {
            return -1;
        }
        i++;
    }
    
    return i;
}

/* Read a potentially double quoted filename into s.
   Returns the modified read position.
   If syntax error occurred, s will be an empty string and
   return value will be -1. */
int parse_filename(int ibuff_start, char s[ibuffer_len], unsigned int *pflag) {
    int i = ibuff_start;
    int pos = 0;
    *pflag = 0;
    
    while (ibuffer[i] != '\0') {
        if (ibuffer[i] == '"') {
            i++;
            int j = parse_find_end_quote(i);
            if (j == -1) {
                s[0] = '\0';
                return -1;
            }
            for ( ; i < j; i++) {
                if (ibuffer[i] == '\\') i++;
                s[pos++] = ibuffer[i];
            }
            *pflag = 1;
            i++; // skip past the quote
        } else {
            if (ibuffer[i] != ' ') {
                s[pos++] = ibuffer[i++];
            } else {
                break; // stop at whitespace
            }
        }
    }
    
    return i;
}

/* Returns modified ibuffer read position */
int parse_command(int ibuff_start, Command *cmd) {
    WordList *wl;
    int i = ibuff_start;
    int pos = 0;
    unsigned int skipwrd = 0;
    unsigned int quoted = 0;
    char word[MAX_CHAR_BUFF_LEN] = {0};
    
    if (ibuffer[i] == 0) {
        return i;
    }
    
    if (cmd->words == NULL) {
        cmd->words = alloc_word_list();
    }
    cmd->type = c_foreground;
    wl = cmd->words;
    
    while (ibuffer[i] != '\0') {
        while (ibuffer[i] != '\0' && ibuffer[i] != ' ') {
            /* Double quotes */
            if (ibuffer[i] == '"') {
                i++;
                int j = parse_find_end_quote(i);
                if (j == -1) {
                    printf("syntax error near \"\n");
                    cmd->type = c_ignore;
                    return i;
                }
                for ( ; i < j; i++) {
                    if (ibuffer[i] == '\\') i++;
                    word[pos++] = ibuffer[i];
                }
                quoted = 1;
                i++; // skip past the quote
            }
            /* Pipes */
            else if (ibuffer[i] == '|') {
                i++;
                Command *pipe = alloc_command();
                // recursively build the pipeline
                i = parse_command(i, pipe);
                if (pipe->type != c_ignore) {
                    if (cmd->pipe_to == NULL) {
                        cmd->pipe_to = pipe;
                    } else {
                        Command *last = cmd->pipe_to;
                        while (last->pipe_to != NULL) {
                            last = last->pipe_to;
                        }
                        last->pipe_to = pipe;
                    }
                } else {
                    dealloc_command(pipe);
                    cmd->type = c_ignore;
                    return i;
                }
            }
            /* Output redirection
             note that > may appear after <,
             but not the other way around */
            else if (ibuffer[i] == '>') {
                char filename[MAX_CHAR_BUFF_LEN] = {0};
                enum redir_action rtype;
                
                // check for >>
                i++;
                if (ibuffer[i] == '>') {
                    i++;
                    rtype = r_appending_to;
                }
                while(ibuffer[i] == ' ') i++;
                i = parse_filename(i, filename, &quoted);
                // check filename
                if (strlen(filename) < 1) {
                    printf("synatx error near >\n");
                    cmd->type = c_ignore;
                    return i;
                }
                Redirect *r = alloc_redirect();
                if (rtype == r_appending_to) {
                    r->action = rtype;
                    r->flags = O_WRONLY|O_APPEND;
                } else {
                    r->flags = O_WRONLY|O_CREAT|O_TRUNC;
                }
                r->filename = malloc( (strlen(filename)+1)*sizeof(char) );
                strcpy(r->filename, filename);
                
                if (cmd->redir != NULL) {
                    // check for multiple redir (not allowed)
                    if (cmd->redir->action == r_output_direction) {
                        cmd->type = c_ignore;
                        return i;
                    }
                    
                    // >  appeared after <
                    if (r->action != r_appending_to) r->action = r_input_output;
                    cmd->redir->next = r;
                    cmd->redir->action = r_input_output;
                } else {
                    if (r->action != r_appending_to) r->action = r_output_direction;
                    cmd->redir = r;
                }
            }
            /* Input redirection */
            else if (ibuffer[i] == '<') {
                if (cmd->redir != NULL) {
                    // bad syntax, < cannot appear after >
                    cmd->type = c_ignore;
                    return i;
                } else {
                    char filename[MAX_CHAR_BUFF_LEN] = {0};
                    
                    i++;
                    while(ibuffer[i] == ' ') i++;
                    i = parse_filename(i, filename, &quoted);
                    // check filename
                    if (strlen(filename) < 1) {
                        printf("synatx error near <\n");
                        cmd->type = c_ignore;
                        return i;
                    }
                    cmd->redir = alloc_redirect();
                    cmd->redir->filename = malloc( (strlen(filename)+1)*sizeof(char) );
                    strcpy(cmd->redir->filename, filename);
                    cmd->redir->flags = O_RDONLY;
                    cmd->redir->action = r_input_direction;
                }
            }
            /* Shell var (substitution is done here) */
            else if (ibuffer[i] == '?') {
                int startpos = pos;
                i++;
                word[pos++] = '?';
                while (ibuffer[i] != '\0' && ibuffer[i] != ' '
                       && ibuffer[i] != '"' && ibuffer[i] != '?') {
                    word[pos++] = ibuffer[i++];
                }
                if (ibuffer[i] != ' ') {
                    skipwrd = 1;
                }
                char *p = word+startpos+1;
                HashItem *var = hashtable_find(global_hashtable, p);
                if (var != NULL && var->data != NULL) {
                    if (is_debugging == '1') printf("=> %s\n", var->data);
                    p = var->data;
                    int j = startpos;
                    for ( ; j<MAX_CHAR_BUFF_LEN; j++) {
                        word[j] = *p++;
                    }
                    pos = startpos + strlen(var->data);
                } else {
                    // erase from word
                    while (pos >= startpos) word[pos--] = 0;
                    pos++;
                    if (is_debugging == '1') printf("=> (NULL)\n");
                }
                break;
                // Note: shell var substitution is not performed for filenames
                // that are expected to come after < or >,
                // ie. it is only done for commands/arguments
            }
            else {
                word[pos++] = ibuffer[i++];
            }
        }
        if (pos > 0) {
            // special check for ./
            if (word[0] == '.' && word[1] == '/') {
                cmd->flags->cmd_file = 1;
            }
            // special check for background job
            if (pos == 1 && word[0] == '&') {
                cmd->flags->cmd_bg = 1;
                break; // ignore anything after &
            }
            if (skipwrd == 0) {
                if (quoted == 0) {
                    wl->process = '*';
                }
                if (wl->word != NULL) {
                    char *nword = malloc( (strlen(wl->word)+strlen(word)+1)*sizeof(char) );
                    strcpy(nword, wl->word);
                    strcat(nword, word);
                    free(wl->word);
                    wl->word = nword;
                } else {
                    wl->word = malloc( (strlen(word)+1)*sizeof(char) );
                    strcpy(wl->word, word);
                }
                wl->next = alloc_word_list();
                wl = wl->next;
            } else {
                // accumulate into current wordlist
                if (wl->word != NULL) {
                    char *nword = malloc( (strlen(wl->word)+strlen(word)+1)*sizeof(char) );
                    strcpy(nword, wl->word);
                    strcat(nword, word);
                    free(wl->word);
                    wl->word = nword;
                } else {
                    wl->word = malloc( (strlen(word)+1)*sizeof(char) );
                    strcpy(wl->word, word);
                }
                skipwrd = 0;
            }
            
            while (pos >= 0) {
                word[pos] = 0;
                pos--;
            }
            pos = 0;
        }
        while(ibuffer[i] == ' ') i++;
    }
    if (wl->word != NULL && wl->next == NULL) {
        wl->next = alloc_word_list();
        wl = wl->next;
    }
    
    if (is_debugging == '1') {
        wl = cmd->words;
        while (wl != NULL) {
            printf("%s%c", wl->word, (wl->next == NULL) ? ' ' : ',');
            wl = wl->next;
        }
        printf("\n");
    }
    
    return i;
}

/* Returns MSH_EXITINT indicating shell should terminate,
 otherwise always 0. */
int read_loop() {
    // setup jump
    int status = setjmp(toplevel_jmp);
    // handle jumps
    if (status != 0) {
        flush_toilet();
        if (status == 1) {
            printf("\nUse exit to leave the shell\n");
        }
        else if (status == 2) {
            printf("\nbackground jobs: %i\n", bgchld);
        }
        else if (status == 3) {
            printf("\nAn error occurred within the shell\n\n");
        }
        status = 0;
    }
    
    if (isatty(STDIN_FILENO) == 1) {
        // prompt if terminal
        printf("%s%% ", username);
    }
    
    getchar_loop();
    
    if (ibuffer[0] == '\0') return 0;
    
    parse_command(0, global_command);
    
    if (global_command->type == c_ignore) {
        flush_toilet();
        return 0;
    }
    
    status = execute_command(global_command);
    if (status != 0 && status != MSH_EXITINT) {
        if (is_debugging == '1') {
            printf("%s: error %d\n", global_command->words->word, errno);
        }
        status = 0;
    }
    
    flush_toilet();
    return status;
}

void init_env_vars() {
    username = getenv("USER");
    char *path = getenv("PATH");
    
    // parse the PATH into an array of paths
    int i = (int)strlen(path);
    char *cpath = malloc(i*sizeof(char));
    strcpy(cpath, path);
    i = 0;
    char *pch = strtok(cpath, ":");
    // first count the number of paths
    while (pch != NULL) {
        i++;
        pch = strtok(NULL, ":");
    }
    var_path_count = i;
    var_paths = malloc( i*sizeof(char*) );
    strcpy(cpath, path);
    i = 0;
    pch = strtok(cpath, ":");
    // store each path
    while (pch != NULL) {
        int l = (int)strlen(pch);
        char *ps = malloc( (l+1)*sizeof(char) );
        strcpy(ps, pch);
        var_paths[i] = ps;
        i++;
        pch = strtok(NULL, ":");
    }
    free(cpath);
    
    global_hashtable = alloc_hashtable();
    
    global_command = alloc_command();
    global_command->words = alloc_word_list();
}

void cleanup() {
    flush_toilet();
    dealloc_command(global_command);
    dealloc_hashtable(global_hashtable);
    printf("\n[msh completed]\n\n");
}

int main() {
    init_env_vars();
    init_exit_traps();
    init_builtin_cmd();
    atexit(cleanup);
    
    while (read_loop() == 0);
    
    return 0;
}
