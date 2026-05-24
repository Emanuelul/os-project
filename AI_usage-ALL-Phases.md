# AI Usage Documentation — All Phases

**Course:** Operating Systems / OS1  
**Project:** City Infrastructure Issue Reporting & Management System  
**Environment:** Unix / Linux (C System Interface)

---

## Project Context Overview

This document log details the compliant and strategic collaboration with the **Gemini AI Engine** to construct, debug, and optimize specific computational blocks across all three phases of the architecture. 

The AI was used to generate specialized string manipulation and parsing routines, which were then manually integrated into low-level Unix system call wrappers handling file descriptors, custom permission masks, process synchronization via POSIX signals, and unnamed inter-process communication (IPC) streams.

---

## Phase 1: Core File Systems & Dynamic Filtering

### 1. Prompts Provided
#### For `parse_condition`
> I am writing a C program for an OS project. I need a function `int parse_condition(const char *cond_str, char *field, char *op, char *value)` that takes a string like `'severity:>=:2'` and splits it into three parts using the colon as a delimiter. How can I do this?

#### For `match_condition`
> Help me write a C function `int match_condition(REPORT *r, const char *field, const char *op, const char *value)` that compares a struct named `REPORT` (which has fields like `int severity`, `char category[20]`, and `char inspector_name[40]`) against a field name, a comparison operator (like `==`, `>`, `<=`), and a value string. It should return 1 if it matches and 0 otherwise.

### Originally Generated Logic Blueprint
The AI provided a modular block implementing `sscanf` scanning patterns utilizing negated scansets to parse the colon delimiters safely, alongside an `if-else if` equality matrix matching data records:

```c
int parse_condition(const char *cond_str, char *field, char *op, char *value)
{
    if (sscanf(cond_str, "%[^:]:%[^:]:%s", field, op, value) == 3)
    {
        return 1;
    }
    return 0;
}

int match_condition(REPORT *r, const char *field, const char *op, const char *value)
{
    if (strcmp(field, "severity") == 0)
    {
        int val = atoi(value);
        if (strcmp(op, "==") == 0) return r->severity == val;
        if (strcmp(op, "!=") == 0) return r->severity != val;
    }
    else if (strcmp(field, "category") == 0)
    {
        if (strcmp(op, "==") == 0) return strcmp(r->category, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->category, value) != 0;
    }
    else if (strcmp(field, "inspector") == 0)
    {
        if (strcmp(op, "==") == 0) return strcmp(r->inspector_name, value) == 0;
    }
    return 0;
}
```

# AI Usage Documentation — Phase 2

**Course:** Operating Systems / OS1  
**Project:** City Infrastructure Issue Reporting & Management System  
**Environment:** Unix / Linux (C System Interface)

---

## 1. Phase 2 Architecture Context

In Phase 2, the system was expanded from a static command-line database manager into an interactive, multi-process environment utilizing **Process Lifecycles** (`fork`, `execvp`, `waitpid`) and **Asynchronous IPC via Signal Delivery** (`sigaction`, `kill`). 

The Gemini AI Engine was leveraged to develop clean, standards-compliant boilerplate configurations for POSIX signal routing and child process execution structures, which were manually audited, hardened for memory safety, and locked behind existing role-restricted authorization policies.

---

## 2. Prompts Provided to the AI Engine

### For Safe Process Cloning and Execution Flow
> "How do I use `fork()` and `execvp()` to execute an external system utility command like `rm -rf` from inside a parent C runtime context without breaking the primary application flow or creating zombie processes?"

### For Asynchronous Monitor Inode Registration
> "How do I build an asynchronous standalone monitor loop program that outputs its current tracking ID into an external `.monitor_pid` file and registers handlers for `SIGUSR1` and `SIGINT` using `sigaction()`?"

---

## 3. Originally Generated Logic Blueprints

The AI engine delivered procedural code slices establishing the mechanical structure for a stateful signal trapping engine using `struct sigaction` and system macros:

```c
struct sigaction sa_usr1;
sa_usr1.sa_handler = handle_sigusr1;
sigemptyset(&sa_usr1.sa_mask);
sa_usr1.sa_flags = 0;
sigaction(SIGUSR1, &sa_usr1, NULL);
```

# AI Usage Documentation — Phase 3

**Course:** Operating Systems / OS1  
**Project:** City Infrastructure Issue Reporting & Management System  
**Environment:** Unix / Linux (C System Interface)

---

## 1. Phase 3 Architecture Context

Phase 3 completed the software ecosystem by converting individual background files and processes into a coordinated, multi-program environment handled through a centralized shell interface (`city_hub.c`). This phase heavily relies on **Inter-Process Communication (IPC)** via **Unnamed Pipes** (`pipe()`), **File Descriptor Duplication and Redirection** (`dup2()`), and asynchronous background monitoring pipelines.

The Gemini AI Engine was utilized to generate strategic structural frameworks for handling file descriptor redirection and token-matching loops. These templates were then customized to implement clean synchronization constraints, prevent deadlock scenarios, and handle abnormal background process termination cleanly.

---

## 2. Prompts Provided to the AI Engine

### For Monitored Stream Pipeline Routing
> "How can I set up an interactive command-line loop in C that establishes an unnamed tracking pipeline via `pipe()`, forks a parent background monitor coordinator process (`hub_mon`) that handles its child's standard output stream redirection over `dup2()`, and systematically parses operational prefix tokens like `[ERR]` or `[OK]`?"

### For Scoring Engine Redirection Matrix
> "Provide a safe methodology to dynamically split space-separated command-line parameters inside a continuous shell environment, instantiate an autonomous calculations process (`scorer`) for each district parameter via a loop, intercept its plain-text standard output summary over a redirected pipe channel, and cleanly collect child exit statuses using `waitpid`."

---

## 3. Originally Generated Logic Blueprints

The AI tool delivered standard procedural templates highlighting basic structural patterns for unnamed pipe binding and standard stream descriptor replacement using `dup2`:

```c
// AI-Generated Stream Overwriting Blueprint
int p_fds[2];
if (pipe(p_fds) == 0) {
    pid_t pid = fork();
    if (pid == 0) {
        close(p_fds[0]);
        dup2(p_fds[1], STDOUT_FILENO); // Bind standard output to pipe write end
        close(p_fds[1]);
        // ... execvp execution block ...
    }
}