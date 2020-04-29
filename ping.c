#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

// author = Daniel Fan (danielfan@berkeley.edu)
// disclaimer: this minimum viable implementation (0 error handling)
// is mostly inspired from ping's actual source code as although i am familiar
// with low level C coding (sockets and such), i don't know all the specifics like ICMP
// and the way i would actually approach a similar task irl is to learn how existing code works
// and adapt it for my specific use case

char in_packet[1024]; 
struct sockaddr to;
struct sockaddr from;
int sock;
int numsent = 0;
int numrec = 0;
double totaltime = 0;
double mintime = 1000000000;
double maxtime = 0;
pid_t pid;
struct timezone notused;
char *USAGE =
    "Usage: sudo ./ping hostname\n"
    "       sudo ./ping IP-address\n";

void exit_with_usage();
void ping();
void done();
u_short in_cksum(u_short *addr, int len);

void exit_with_usage() {
    fprintf(stderr, "%s", USAGE);
    exit(0);
}

// SIGALRM handler - send ping and set alarm for 1s
void ping() {
    // repeat in 1s
    alarm(1);

    // make packet 
    char out_packet[64];
    struct icmp *icp = (struct icmp *) out_packet;
    icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
    icp->icmp_id = pid;
    icp->icmp_cksum = 0; // initially 0 for checksum calc
	icp->icmp_seq = numsent++;
    gettimeofday((struct timeval *) (out_packet + 8), &notused);
    icp->icmp_cksum = in_cksum((u_short *) out_packet, 64);
    
    // send packet
    int bytes_sent = sendto(sock, out_packet, 64, 0, &to, sizeof(struct sockaddr));
}

// SIGINT handler - print exit stats
void done() {
    printf("\n");
    printf("--- %s ping statistics ---\n", inet_ntoa(((struct sockaddr_in *) &from)->sin_addr));
    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n", numsent, 
        numrec, 1 - (double) numrec / numsent);
    printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n", mintime, totaltime / numrec, maxtime);
    exit(0);
}

// copy pasted generic internet checksum routine
u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while( nleft > 1 )  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if( nleft == 1 ) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add possible carry */
	answer = ~sum;		/* ones complement & truncate to 16 bits */
	return answer;
}

int main(int argc, char **argv) {
    pid = getpid();
    if (argc != 2)
        exit_with_usage();

    // config
    setlinebuf(stdout);
    signal(SIGINT, &done);
    signal(SIGALRM, &ping);
    
    // name resolution
    struct sockaddr_in *dest_in = (struct sockaddr_in *) &to;
    dest_in->sin_family = AF_INET;
	dest_in->sin_addr.s_addr = inet_addr(argv[1]);
    if (dest_in->sin_addr.s_addr == (in_addr_t) -1) {
        struct hostent *hp = gethostbyname(argv[1]);
        if (hp) {
            dest_in->sin_family = hp->h_addrtype;
            strncpy((caddr_t) &dest_in->sin_addr, hp->h_addr, hp->h_length);
        } else 
            exit_with_usage();
    }

    // get socket
    struct protoent *proto = getprotobyname("icmp");
    sock = socket(AF_INET, SOCK_RAW, proto->p_proto);
        
    // starting
    printf("PING (%s): 56 data bytes\n", inet_ntoa(dest_in->sin_addr));
    ping();

    // receive packets
    while (1) {
        socklen_t fromlen = sizeof(from);
        int bytes_read = recvfrom(sock, in_packet, 1024, 0, &from, &fromlen);

        // check if recvfrom was interrupted
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            perror("recvfrom");
            exit(1);
        }

        struct sockaddr_in *from_in = (struct sockaddr_in *) &from;
        struct timeval tv;
        struct ip *ip = (struct ip *) &in_packet;
        int headerlen = ip->ip_hl << 2;
        gettimeofday(&tv, &notused);

        // check if packet too short
        if (bytes_read < headerlen + ICMP_MINLEN) {
            printf("packet too short (%d bytes) from %s\n", bytes_read, inet_ntoa(from_in->sin_addr));
            continue;
        } 

        bytes_read -= headerlen;
        struct icmp *icp = (struct icmp *)(in_packet + headerlen);

        if (icp->icmp_type == ICMP_ECHOREPLY && icp->icmp_id == pid) {
            // timing
            struct timeval *tp = (struct timeval *) &(icp->icmp_data[0]);
            if((tv.tv_usec -= tp->tv_usec) < 0 )   {
                tv.tv_sec--;
                tv.tv_usec += 1000000;
            }
            tv.tv_sec -= tp->tv_sec;
            double triptime = tv.tv_sec * 1000 + (tv.tv_usec / 1000);
            totaltime += triptime;
            if (triptime < mintime)
                mintime = triptime;
            if (triptime > maxtime)
                maxtime = triptime;
            printf("%d bytes from %s: icmp_seq=%d time=%.3f ms\n", bytes_read, 
                inet_ntoa(from_in->sin_addr), icp->icmp_seq, triptime);
            numrec++;
        }
    }

    // never reached
    return 0;
}
