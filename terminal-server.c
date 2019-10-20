/*
 * terminal server proof of concept - (c) 2019 by Marius Petrescu, YO2LOJ <marius@yo2loj.ro>
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>


#ifndef FALSE
    #define FALSEE	0
#endif

#ifndef TRUE
    #define TRUE	1
#endif

#define DEVICE_NUMBER_MAX	10

#define MYIP		"0.0.0.0"

#pragma pack(push, 1)

typedef struct terminal_request {
	short int streamid;
	char flags[2];
	unsigned int pad; /* x00 x00 x00 x00 */
	char station[8];
	char call[8];
	char terminal[8];
	unsigned int ip_address;
} terminal_request;

typedef struct connect_request {
	short int streamid;
	char flags[2];
	unsigned int pad; /* x00 x00 x00 x00 */
	char call[8];
} connect_request;

typedef struct connect_response {
	short int streamid;
	char flags[2];
	unsigned int pad; /* x00 x00 x00 x00 */
	char ur[8];
	char rpt1[8];
	char rpt2[8];
	unsigned int ip_address;
} connect_response;

typedef struct dv_header {
	char sig[4];            /* DSVT */
	unsigned char type;     /* 0x10 - configuration frame */
	char pad1[3];           /* 0x00, 0x00, 0x00 */
	unsigned stream;        /* 0x20 - voice stream */
	char pad2[3];           /* 0x00, 0x01, 0x01 */
	short int streamid;     /* random */
	char pad3;              /* 0x80 */

	unsigned char flags[3]; /* flag1 ... flag3 */
	char destination[8];    /* repeater + dest module */
	char departure[8];      /* repeater + 'G' */
        char companion[8];      /* "CQCQCQ  " */
        char own1[8];           /* own call */
        char own2[4];           /* ext, 'RPTR' */
        short int fcs;
} dv_header;

typedef struct ping_packet {
	char data[4];
} ping_packet;


#pragma pack(pop)

int debug = 0;
char *address = "0.0.0.0";
char *usage_string = "Usage: terminal-server [-d] [-a bind_address]";

char *devices[DEVICE_NUMBER_MAX];

char gateway[8] = "YO2LOJ B";

int main(int argc, char **argv)
{
	int p;

	while ((p = getopt(argc, argv, "dh?a:")) != -1)
	{
		switch (p)
		{
			case 'd':
			case 'h':
			case '?':
				break;
			default:
				if (optarg && optarg[0] == '-')
				{
					fprintf(stderr, "terminal-server: option -%c needs an argument.\n", p);
					return 1;
				}
				break;
		}

		switch (p)
		{
		case 'd':
			debug = 1;
			break;
		case 'a':
			address = optarg;
			break;
		case 'h':
		case '?':
			fprintf(stderr, "%s\n", usage_string);
			return 1;
		}
	}


	if (strcmp(address, "0.0.0.0")) printf("Binding to address: %s\n", address);


	int st = socket(AF_INET, SOCK_DGRAM, 0);
	if (st < 0)
	{
		fprintf(stderr, "terminal-server: Error opening 12346 socket\n");
		exit(1);
	}

	int reuse = 1;
	setsockopt(st, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
	setsockopt(st, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse));

	struct sockaddr_in sin;
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(MYIP);
	sin.sin_port = htons(12346);

	if (bind(st, (struct sockaddr *)&sin, sizeof(sin)))
	{
		fprintf(stderr, "terminal-server: Error binding 12346 socket\n");
		close(st);
		exit(1);
	}

	int sc = socket(AF_INET, SOCK_DGRAM, 0);
	if (sc < 0)
	{
		fprintf(stderr, "terminal-server: Error opening 12345 socket\n");
		close(st);
		exit(1);
	}

	setsockopt(sc, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
	setsockopt(sc, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse));
	setsockopt(sc, IPPROTO_IP, IP_PKTINFO, (char *)&reuse, sizeof(reuse));

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(MYIP);
	sin.sin_port = htons(12345);

	if (bind(sc, (struct sockaddr *)&sin, sizeof(sin)))
	{
		fprintf(stderr, "terminal-server: Error binding 12345 socket\n");
		close(st);
		close(sc);
		exit(1);
	}

	int dv = socket(AF_INET, SOCK_DGRAM, 0);
	if (dv < 0)
	{
		fprintf(stderr, "terminal-server: Error opening 40000 socket\n");
		close(st);
		close(sc);
		exit(1);
	}

	setsockopt(dv, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
	setsockopt(dv, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse));

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(MYIP);
	sin.sin_port = htons(40000);

	if (bind(dv, (struct sockaddr *)&sin, sizeof(sin)))
	{
		fprintf(stderr, "terminal-server: Error binding 40000 socket\n");
		close(st);
		close(sc);
		close(dv);
		exit(1);
	}

	int icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (icmp < 0)
	{
		fprintf(stderr, "terminal-server: Error opening icmp socket\n");
		close(st);
		close(sc);
		close(dv);
		exit(1);
	}


	struct pollfd pollfd[4];

	pollfd[0].fd = st;
	pollfd[0].events = POLLIN;
	pollfd[0].revents = 0;

	pollfd[1].fd = sc;
	pollfd[1].events = POLLIN;
	pollfd[1].revents = 0;

	pollfd[2].fd = dv;
	pollfd[2].events = POLLIN;
	pollfd[2].revents = 0;

	pollfd[3].fd = icmp;
	pollfd[3].events = POLLIN;
	pollfd[3].revents = 0;

	printf("Ready\n\n");

	unsigned char buffer[256];
	int len;

	struct sockaddr_in sa;
	unsigned int sasize = sizeof(sa);

	unsigned short int hseq = 0;
	unsigned short int dvseq = 0;

	time_t timer = 0;

	unsigned int client_addr = 0u;
	unsigned int local_addr = 0u;

	union {
		struct cmsghdr cm;
		unsigned char pktinfo_sizer[sizeof(struct cmsghdr) + sizeof(struct in_pktinfo)];
	} control_un;


	while(poll(pollfd, 4, 100) >= 0)
	{

		if (pollfd[0].revents)
		{
			len = recvfrom(st, buffer, 255, 0, (struct sockaddr *)&sa, &sasize);

			if (len == 32)
			{
				terminal_request *req = (terminal_request *)buffer;
				printf("Request:  %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
				printf("Seq:      0x%04x\n", ntohs(req->streamid));
				printf("Flags:    0x%02x 0x%02x\n", req->flags[0], req->flags[1]);
				printf("Station:  %8.8s\n", req->station);
				printf("Owner:    %8.8s\n", req->call);
				printf("Terminal: %8.8s\n\n", req->terminal);

				client_addr = sa.sin_addr.s_addr;

				req->flags[0] = 0x80; // 0x80 = response
				req->flags[1] = 0x00; // x00 = ok, x01 = no access
				req->ip_address = inet_addr(MYIP);

				sendto(st, (char *)req, sizeof(terminal_request), 0, (struct sockaddr *)&sa, sasize);

				printf("> ACK/Authorized\n\n");
				if (debug)
				{
					printf("Sent %lu bytes:\n", sizeof(terminal_request));
					for (int i = 0; i < sizeof(terminal_request); i++)
					{
						printf("%c", buffer[i]);
					}
					printf("\n\n");
				}
			}
		}

		if (pollfd[1].revents)
		{

			struct msghdr msg;
			struct iovec iov[1];
			struct in_addr local_ip;
			local_ip.s_addr = 0u;

			bzero(&msg, sizeof(msg));
			iov[0].iov_base = buffer;
			iov[0].iov_len = 255;

			bzero(&sa, sizeof(sa));
			msg.msg_name = &sa;
			msg.msg_namelen = sasize;
			msg.msg_iov = iov;
			msg.msg_iovlen = 1;
			msg.msg_control = &control_un;
			msg.msg_controllen = sizeof(control_un);

			len = recvmsg(sc, &msg, 0);

			if (len == 16)
			{

				struct cmsghdr *cmsg;
				for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))
				{
				    struct in_pktinfo *pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
				    local_ip.s_addr = pkt->ipi_spec_dst.s_addr;
				    printf("Local IP: %s\n", inet_ntoa(local_ip));
				}

				connect_request *req = (connect_request *)buffer;
				printf("Request:  %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
				printf("Seq:      0x%04x\n", ntohs(req->streamid));
				printf("Flags:    0x%02x 0x%02x (%s call)\n", req->flags[0], req->flags[1], (req->flags[0] & 0x10)?"repeater":"direct");
				/*
				    flag[0]: 0x00 = user call, 0x10 = repeater call
				*/
				printf("Callsign: %8.8s\n\n", req->call);

				connect_response resp;
				bzero(&resp, sizeof(resp));

				resp.streamid = req->streamid;
				resp.flags[0] = req->flags[0] | 0x80;

				// accept
				resp.flags[1] = 0x00;

				memcpy(resp.ur, req->call, 8);

				if ((req->flags[0] & 0x10) == 0x00) // routed call
				{
					// direct call
					memcpy(resp.rpt1, gateway, 7);
					resp.rpt1[7] = 'G';
					memcpy(resp.rpt2, gateway, 8);
				}
				else // routed repeater call
				{
					// repeater call
					memcpy(resp.rpt1, req->call, 7);
					resp.rpt1[7] = 'G';
					memcpy(resp.rpt2, req->call, 8);
				}

				if (resp.flags[1])
				{
					printf("> Rejected\n\n");
					client_addr = 0u;
				}
				else
				{
					printf("> Accepted\n\n");
					client_addr = sa.sin_addr.s_addr;
					// gateway address
					local_addr = local_ip.s_addr;
				}

				resp.ip_address = local_addr;
				sendto(sc, (char *)&resp, sizeof(resp), 0, (struct sockaddr *)&sa, sasize);
				if (debug)
				{
					printf("Sent %lu bytes:\n", sizeof(resp));
					for (int i = 0; i < sizeof(resp); i++)
					{
						printf("%c", ((unsigned char *)&resp)[i]);
					}
					printf("\n\n");
				}
			}
		}

		if (pollfd[2].revents)
		{
			len = recvfrom(dv, buffer, 255, 0, (struct sockaddr *)&sa, &sasize);
			if (((len == 56) || (len == 27)) &&
			    (memcmp(buffer, "DSVT", 4) == 0) &&
			    ((buffer[4] == 0x10) ||   // header
			     (buffer[4] == 0x20)) &&  // details
			    (buffer[8] == 0x20))      // voice
			{
				client_addr = sa.sin_addr.s_addr;

				int lseq = (buffer[12] << 8) + buffer[13];
				if (len == 56)
				{
					if (hseq != lseq)
					{
						printf("DV Headers:  %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
						printf("MY: %8.8s/%4.4s UR: %8.8s RPT1: %8.8s RPT2: %8.8s\n", buffer +42, buffer + 50, buffer + 34, buffer + 26, buffer + 18);
						hseq = lseq;
					}
				}
				else
				{
					if ((buffer[14] & 0x40) == 0)
					{
						if (dvseq != lseq)
						{
							printf("DV Frames:  %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
							dvseq = lseq;
						}
					}
					else
					{
						printf("DV Last Frame:  %s:%d\n\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
						hseq = 0;
						dvseq = 0;
					}
				}
			}
			else
			{
				printf("Unknown:  %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
				for (int i = 0; i < len; i++)
				{
					printf("%02x ", buffer[i]);
				}
				printf("\n\n");

			}
		}

		if (pollfd[3].revents)
		{
			len = recvfrom(icmp, buffer, 255, 0, (struct sockaddr *)&sa, &sasize);
			if (len > 28) 
			{

				struct ip *iph = (struct ip *)buffer;
				int iphdrlen = iph->ip_hl*4;
				struct icmp *icmph = (struct icmp *)(buffer + iphdrlen);

				if (icmph->icmp_type == 3)
				{
					struct ip *rip = (struct ip *)(buffer + iphdrlen + 8);
					if (rip->ip_dst.s_addr == client_addr)
					{
					    printf("ICMP unreachable for %s - disconnected\n\n", inet_ntoa(rip->ip_dst));
					    client_addr = 0u;
					}
				}
			}
		}

		if ((time(NULL) - timer) > 5) // each 5 seconds
		{
			timer = time(NULL);

			if (client_addr)
			{
				ping_packet ping;
				bzero(&ping, sizeof(ping));
				memcpy(ping.data, "PING", 4);

				struct sockaddr_in sap;
				bzero((char *)&sa, sizeof(sa));
				sap.sin_family = AF_INET;
				sap.sin_addr.s_addr = client_addr;
				sap.sin_port = htons(40000);

				if (sendto(dv, (char *)&ping, sizeof(ping), 0, (struct sockaddr *)&sap, sizeof(sap)) < 0)
				{
				    printf("Ping error\n");
				}

				if (debug)
				{
					printf("Sent %lu bytes:\n", sizeof(ping));
					for (int i = 0; i < sizeof(ping); i++)
					{
						printf("%c", ((unsigned char *)&ping)[i]);
					}
					printf("\n\n");
				}
			}

		}
	}

	return 0; 
}


