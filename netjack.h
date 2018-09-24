#include <netinet/in.h>
#include <string.h>

// a wrapper for arguments to functions that are attacks. defined
// here so that if this signature changes, all the attack
// functions don't have to be redefined.
struct Atksig {
    // attacks may take additional arguments
    int argc;
    char** argv;

    // target machine ipv4 address
    struct in_addr victim;
};

// an array of Haxmap is used to denote which names correspond to which attacks in main()
struct Haxmap {
    const char* name;
    const int (*attack) (const struct Atksig*);
};

// search array of Haxmap by name for attack, return fn ptr if found, NULL otherwise.
int (*get_attack(const struct Haxmap map[], const char* name)) (struct Atksig*) {
    size_t idx = 0;
    struct Haxmap* hack = NULL;

    while ((hack = &map[idx++])->name != NULL)
        if (0 == (strcmp(hack->name, name)))
            return hack->attack;

    return NULL;
}