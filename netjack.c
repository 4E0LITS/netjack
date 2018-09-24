/*
Netjack - a small C tool for net sploit demonstration
*/

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

// sploit h files go here
#include "hax/storm.h"

// available attacks go here, delimited by an entry with name == NULL
const struct Haxmap hax[] = {
    {"icmp_storm", &icmp_storm},

    {NULL, NULL}
};

const char usagestr[] =
    "netjack - a small C tool for demonstrating net sploits\n"
    "usage: netjack <attack> <host> [arguments]\n"
    "\n"
    "Available attacks:";

int main(int argc, char* argv[]) {
    // get desired attack. then, get target info and machine info,
    // and hand off to attack invocation

    int (*attack) (const struct Atksig*);
    struct Atksig attack_sig;

    if (3 > argc) {
        puts(usagestr);

        int idx = 0;
        while(NULL != hax[idx].name)
            printf(" * %s\n", hax[idx++].name);

        return 1;
    }

    // root privileges are required for raw socket creation
    if (0 != geteuid()) {
        puts("netjack requires root privileges to operate.");
        return 1;
    }

    // look up desired attack
    if ((attack = get_attack(hax, argv[1])) == NULL) {
        puts("No such attack found!\nAvailable attacks:");
        
        int idx = 0;
        while(NULL != hax[idx].name)
            printf(" * %s\n", hax[idx++].name);
        
        return 1;
    }

    // parse target ip addr from argv[2]
    if (0 == inet_aton(argv[2], &attack_sig.victim)) {
        printf("failed to parse \"%s\" into an ipv4 address!\n", argv[2]);
        return 1;
    }

    // pass control off to attack invocation and return exit code.
    attack_sig.argc = argc;
    attack_sig.argv = argv;

    return attack(&attack_sig);
}