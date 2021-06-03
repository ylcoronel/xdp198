#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <stdlib.h> 
#include "libbpf/src/bpf_helpers.h"
# define NO_OF_CHARS 256

FILE *logfile;
int udp=0;
int flag = 0;

void check_pattern(unsigned char *data, int Size);
int max (int a, int b);
void badCharHeuristic( char *str, int size, int badchar[NO_OF_CHARS]);

SEC("xdp_sock")
int xdp_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    //char match_pattern[] = "test";
    unsigned int payload_size, i;
    struct ethhdr *eth = data;
    unsigned char *payload;
    struct udphdr *udp;
    struct iphdr *ip;

    if (( void *) eth + sizeof (* eth) <= data_end ){
        struct iphdr *ip = data + sizeof (* eth);
        if (( void *) ip + sizeof (* ip) <= data_end ){
            if (ip -> protocol == IPPROTO_UDP ){
                udp++;
                udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end){
                    payload_size = ntohs(udp->len) - sizeof(*udp);
                    payload = (unsigned char *)udp + sizeof(*udp); // start of payload
                    if ((void *)payload + payload_size <= data_end){
                        check_pattern(payload, payload_size);
                        if (flag == 0){ printf("No pattern found\n"); }
                        else{ printf("Pattern found\n"); }
                        return XDP_PASS;
                    }
                }         
            }
        }
    }   
    return XDP_PASS;
}


void check_pattern(unsigned char *data, int Size) {
    char *pattern = NULL;
    FILE *fp;
    fp = fopen("pats.txt", "r");
    flag = 0;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&pattern, &len, fp)) != -1) {
    int m = strlen(pattern);
    int n = Size;

    int badchar[NO_OF_CHARS];

    /* Fill the bad character array by calling
        the preprocessing function badCharHeuristic()        
        for given pattern */
    badCharHeuristic(pattern, m, badchar);

    int s = 0;  // s is shift of the pattern with
                    
    // respect to text
    while(s <= (n - m))
    {
        int j = m-1;

        /* Keep reducing index j of pattern while
        characters of pattern and text are
        matching at this shift s */
        while(j >= 0 && pattern[j] == data[s+j])
            j--;

        /* If the pattern is present at current
        shift, then index j will become -1 after
        the above loop */
        if (j < 0)
        {
            flag = 1;
            /* Shift the pattern so that the next
            character in text aligns with the last
            occurrence of it in pattern.
            The condition s+m < n is necessary for
            the case when pattern occurs at the end
            of text */
            s += (s+m < n)? m-badchar[data[s+m]] : 1;

        }                             
        else
            /* Shift the pattern so that the bad character
            in text aligns with the last occurrence of
            it in pattern. The max function is used to
            make sure that we get a positive shift.
            We may get a negative shift if the last
            occurrence  of bad character in pattern
            is on the right side of the current
            character. */
            s += max(1, j - badchar[data[s+j]]);
    }
}
}

// A utility function to get maximum of two integers
int max (int a, int b) { return (a > b)? a: b; }

// The preprocessing function for Boyer Moore's
// bad character heuristic
void badCharHeuristic( char *str, int size, int badchar[NO_OF_CHARS])
{
    int i;

    // Initialize all occurrences as -1
    for (i = 0; i < NO_OF_CHARS; i++)
        badchar[i] = -1;

    // Fill the actual value of last occurrence
    // of a character
    for (i = 0; i < size; i++)
        badchar[(int) str[i]] = i;
}                                    