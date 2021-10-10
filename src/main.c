#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>
#include <netdb.h>

char isRandInitialized = 0;
void logg(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
	printf("\n");
}

void isValidSocketGuard(int* sock_id) {
	if (*sock_id < 0){
        logg("Creating ICMP Socket failed. Try to run again with su privileges.");
        exit(1);
    }
}

void displayUsageInfo(const char * firstArg) {
	logg("Usage: %s [ip]", firstArg);
    exit(1);
}

// one of the cheksum functions, discovered from the internet
unsigned short checksum(unsigned short *addr, int len){

	unsigned short result;
	unsigned int sum = 0;
	
	/* Adds all double-byte words */
	while(len > 1){
		sum += *addr++;
		len -= 2;
	}
	
	/* If the left byte, we add it to the sum */
	if(len == 1) sum += *(unsigned char*) addr;
	sum = (sum >> 16) + (sum & 0xFFFF);
	
	/* Adds an Transfer */
	sum += (sum >> 16);
	/* again */
	result = ~sum;
	/* Invert the result */
	return result;
}

#define MAX_PACKET_SIZE 65535
#define MAX_PINGS 3

struct ping_packet
{
    struct icmp icmp_header;
    char payload[52];
};

char generateRandomByte() {
	if(!isRandInitialized) {
		srand(time(NULL));
		isRandInitialized = 1;
	}
	char randomByte = rand();
	return randomByte;
}

double getElapsedTime(struct timeval start, struct timeval end) {
	return (double)(end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_usec - start.tv_usec) / 1000;
}
int main(int argc, char *argv[])
{
     // default start variables
	 int maxHops = 30;
	 int TTL = 0;

	 // State
	 char packetBlock = 0;

	 if(argc > 1 ) {

		// Buffer for incoming ICMP Packets
		char buffer[MAX_PACKET_SIZE];

		// Destination sockeet address
		struct sockaddr_in destination_ip;
		destination_ip.sin_family = AF_INET;
		in_addr_t destinationIP = inet_addr(argv[1]);
		if(destinationIP == -1) {
			logg("Niepoprawny adres IP.");
			exit(1);
		}
		destination_ip.sin_addr.s_addr = destinationIP;

		int icmp_endpoint = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	    isValidSocketGuard(&icmp_endpoint);

		// Set socket default timeout to 1 second
		struct timeval tv_out;
    	tv_out.tv_sec = 1;
    	tv_out.tv_usec = 0;
		setsockopt(icmp_endpoint, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

		struct in_addr paddr;
		paddr.s_addr = destinationIP;
		logg("Traceroute to (%s), max hops %d, bytes %d", inet_ntoa(paddr), maxHops, sizeof((struct ping_packet *)0)->payload);
        for(;;) {
			if (TTL >= maxHops) exit(0);
			struct ping_packet packet;
			struct timeval ping_timer_start;
			struct timeval ping_timer_end;

			// send packet
			if (packetBlock == 0) {
				TTL++;
				setsockopt(icmp_endpoint, IPPROTO_IP, IP_TTL, &TTL, sizeof(TTL));

				packet.icmp_header.icmp_type = ICMP_ECHO;
				packet.icmp_header.icmp_code = 0;
				packet.icmp_header.icmp_hun.ih_idseq.icd_id = 999;
				packet.icmp_header.icmp_hun.ih_idseq.icd_seq = 0;

				for (int i = 0; i < sizeof(packet.payload); i++ )
				{
					packet.payload[i] = 0x6a;
				}
				packet.icmp_header.icmp_cksum = checksum(&packet, sizeof(packet));
				sendto(icmp_endpoint, &packet, sizeof(packet), 0, &destination_ip, sizeof(destination_ip));
				clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ping_timer_start);
				packetBlock = 1;
			} else {
				// receive packet
				memset(&buffer, 0, sizeof(buffer));
        		int receiveReturnVal = recvfrom(icmp_endpoint, &buffer, MAX_PACKET_SIZE, 0, NULL, NULL);
				struct ip *ip_header = (struct ip *)buffer;
				struct icmp *icmp_header = (struct icmp *)((char *)ip_header + (4 * ip_header->ip_hl)); // ip_hl - ilosc 32-bitowych pol do ominiecia, bo czasami pakiet moze miec options

				if (receiveReturnVal > 0) {
					// pointer for received payload from other host
					// unsigned char* p = (unsigned char*)(icmp_header) + 2 * sizeof(struct icmp);

					//if (memcmp(packet.payload, p, 52) == 0 ) {
					
					if (icmp_header->icmp_hun.ih_idseq.icd_id == 999)
					{
						clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ping_timer_end);				
						double elapsed_time = getElapsedTime(ping_timer_start, ping_timer_end);
						logg("%d: received the echo reply from %s , %.2f ms", TTL, inet_ntoa(ip_header->ip_src), elapsed_time);
						if (ip_header->ip_src.s_addr == destination_ip.sin_addr.s_addr) 
						{
							logg("Traceroute ended.");
							exit(0);
						}
						packetBlock = 0;
					} else {
						if(icmp_header->icmp_type == ICMP_TIMXCEED && icmp_header->icmp_code == ICMP_TIMXCEED_INTRANS)
						{
							struct icmp *icmp_header2 = (struct icmp *)((char*)icmp_header + sizeof(struct icmp));
							if(icmp_header2->icmp_hun.ih_idseq.icd_id == 999)
							{
								clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ping_timer_end);				
								double elapsed_time = getElapsedTime(ping_timer_start, ping_timer_end);
								logg("%d: received the ttl response from %s , %.2fms", TTL, inet_ntoa(ip_header->ip_src), elapsed_time);
								if (ip_header->ip_src.s_addr == destination_ip.sin_addr.s_addr) 
								{
									logg("Traceroute ended.");
									exit(0);
								}
								packetBlock = 0;
							}
						}
					}

				} else {
					logg("%d: *", TTL);
					packetBlock = 0;
				}
			}      
     	}
	} else if (argc == 1) {
		displayUsageInfo(argv[0]);
	}
     

}