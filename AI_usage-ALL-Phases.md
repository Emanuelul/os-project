# AI Usage Documentation

## Tool Used
[Gemini]

## Prompts Given

### For `parse_condition`
> I am writing a C program for an OS project. I need a function int parse_condition(const char *cond_str, char *field, char *op, char *value) that takes a string like 'severity:>=:2' and splits it into three parts using the colon as a delimiter. How can I do this?

### For `match_condition`
> Help me write a C function int match_condition(REPORT *r, const char *field, const char *op, const char *value) that compares a struct named REPORT (which has fields like int severity, char category[20], and char inspector_name[40]) against a field name, a comparison operator (like ==, >, <=), and a value string. It should return 1 if it matches and 0 otherwise.

## What Was Generated
> The AI provided a logic block using sscanf for parsing and a series of if-else if statements for the matching logic. The initial match_condition only handled basic equality (==) or inequality (!=) for strings and integers
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
        if (strcmp(op, "==") == 0)
            return r->severity == val;
        if (strcmp(op, "!=") == 0)
            return r->severity != val;
    }
    else if (strcmp(field, "category") == 0)
    {
        if (strcmp(op, "==") == 0)
            return strcmp(r->category, value) == 0;
        if (strcmp(op, "!=") == 0)
            return strcmp(r->category, value) != 0;
    }
    else if (strcmp(field, "inspector") == 0)
    {
        if (strcmp(op, "==") == 0)
            return strcmp(r->inspector_name, value) == 0;
    }
    return 0;
}
```

## What I Changed and Why
> I manually added support for advanced comparison operators (>, <, >=, <=) for the severity field.

## What I Learned
> I learned how to use negated scansets in sscanf (like %[^:]) to parse structured strings without needing complex regex or multiple strtok calls.

## Phase 3 Prompts and Logic Contributions

### For Pipeline Setup and Asynchronous Verification Protocol
> "How can I set up a program to create a tracking pipeline via pipe(), fork a child tracking monitor instance that binds its standard output to this channel using dup2(), and evaluate custom tag headers like [ERR] or [OK] from the parent process?"

### For Scoring Engine Framework Integration
> "Provide a safe methodology to dynamically loop through variable command line string parameters inside a management shell, execute an autonomous calculating calculation process for each parameter, read its text metrics summary directly over a redirected pipe interface, and clean up zombie structures safely via waitpid."

---

## What Was Generated vs What Was Custom Modified
The AI tool provided modular architecture setups demonstrating basic `pipe()` structural assignments. 

* **The Protocol Integration**: I added functional stream parsing headers (`[MSG]`, `[ERR]`, `[OK]`) to the monitor module output streams. This allows the hub tool to cleanly isolate raw terminal display strings from functional error signaling traps.
* **Fail-Safe Processing Blocks**: The file verification mechanism (`access` and `open`) inside `scorer.c` was expanded to prevent segmentation faults if a user queries a non-existent or corrupted district path identifier.