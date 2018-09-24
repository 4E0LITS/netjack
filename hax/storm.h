// an ICMP storm implementation

#include <time.h>
#include <string.h>

#include "../netjack.h"

void prep_sockaddr_in(struct sockaddr_in*, struct in_addr);

int icmp_storm(struct Atksig* attack_sig) {
    // create socket and ICMP packet, then send packet to socket in delay loop

    int count;
    int delay;
    struct sockaddr_in dest_sockaddr;

    // get des count and delay
    if (5 > attack_sig->argc) {
        puts("ICMP storm attack requires two arguments:\n<count (n)> <delay (milliseconds)>");
        return 1;
    }
    
    if (1 > sscanf(attack_sig->argv[3], "%d", &count) || 0 >= count) {
        printf("<count> expected an integer greater than zero. (received \"%s\")\n", attack_sig->argv[3]);
        return 1;
    }

    if (1 > sscanf(attack_sig->argv[4], "%d", &delay) || 0 > delay) {
        printf("<delay> expected an integer greater than or eq to zero. (received \"%s\")\n", attack_sig->argv[4]);
        return 1;
    }

    // populate dest_sockaddr
    prep_sockaddr_in(&dest_sockaddr, attack_sig->victim);
    
    return 0;
}

void prep_sockaddr_in(struct sockaddr_in* dest, struct in_addr victim) {
    memset(dest, '\0', sizeof(struct sockaddr_in));

    dest->sin_family = AF_INET;
    dest->sin_addr = victim;
    dest->sin_port = 0;
}