
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <usrsctp.h>
#include "programs_helper.h"
#include <sys/resource.h>


#define PORT 9
#define BUFFER_SIZE 10240
#define SLEEP 1
#define LOCAL_ENCAPS_PORT 11111
#define REMOTE_ENCAPS_PORT 22222


const int use_udpencaps = 0;

void print_memory_usage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    printf("Memory usage: %ld KB\n", usage.ru_maxrss); // Memory in kilobytes
}

static int receive_cb(struct socket *sock, union sctp_sockstore addr, void *data,
           size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
	
	char namebuf[INET6_ADDRSTRLEN];
	const char *name;
	uint16_t port;

	if (data) 
	{
		if (flags & MSG_NOTIFICATION) 
		{
			printf("Notification of length %d received.\n", (int)datalen);
		} 
		else 
		{
			switch (addr.sa.sa_family) 
			{

			case AF_INET:
				name = inet_ntop(AF_INET, &addr.sin.sin_addr, namebuf, INET_ADDRSTRLEN);
				port = ntohs(addr.sin.sin_port);
				break;
			case AF_INET6:
				name = inet_ntop(AF_INET6, &addr.sin6.sin6_addr, namebuf, INET6_ADDRSTRLEN),
				port = ntohs(addr.sin6.sin6_port);
				break;
			case AF_CONN:

				if (snprintf(namebuf, INET6_ADDRSTRLEN, "%p", addr.sconn.sconn_addr) < 0) 
				{
					namebuf[0] = '\0';
				}
				name = namebuf;
				port = ntohs(addr.sconn.sconn_port);
				break;
			default:
				name = "???";
				port = 0;
				break;
			}
			printf("Msg of length %d received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u.\n",
			       (int)datalen,
			       name,
			       port,
			       rcv.rcv_sid,
			       rcv.rcv_ssn,
			       rcv.rcv_tsn,
			       (uint32_t)ntohl(rcv.rcv_ppid),
			       rcv.rcv_context);
		
		}
		
		free(data);
		
	}
	return (1);
}


int main()
{

	struct socket *sock;
	struct sockaddr_in6 addr;
	struct sctp_udpencaps encaps;
	struct sctp_event event;
	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
	                          SCTP_PEER_ADDR_CHANGE,
	                          SCTP_REMOTE_ERROR,
	                          SCTP_SHUTDOWN_EVENT,
	                          SCTP_ADAPTATION_INDICATION,
	                          SCTP_PARTIAL_DELIVERY_EVENT};
	unsigned int i;
	struct sctp_assoc_value av;
	const int on = 1;
	ssize_t n;
	int flags;
	socklen_t from_len;
	char buffer[BUFFER_SIZE];
	char name[INET6_ADDRSTRLEN];
	socklen_t infolen;
	struct sctp_rcvinfo rcv_info;
	unsigned int infotype;

	
	if (use_udpencaps) 
	{
		usrsctp_init((uint16_t)LOCAL_ENCAPS_PORT, NULL, debug_printf_stack);
		printf("Init usrsctp with port: %d\n", (uint16_t)LOCAL_ENCAPS_PORT);
	} 
	else 
	{
		usrsctp_init(9899, NULL, debug_printf_stack);
		printf("Init usrsctp with port: 9899\n");
	}

	usrsctp_sysctl_set_sctp_blackhole(2);
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0);


	if ((sock = usrsctp_socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP, receive_cb, NULL, 0, NULL)) == NULL) 
	{
		perror("usrsctp_socket");
	}


	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, (const void*)&on, (socklen_t)sizeof(int)) < 0) 
	{
		perror("usrsctp_setsockopt SCTP_I_WANT_MAPPED_V4_ADDR");
	}


	memset(&av, 0, sizeof(struct sctp_assoc_value));
	av.assoc_id = SCTP_ALL_ASSOC;
	av.assoc_value = 47;

	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_CONTEXT, (const void*)&av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) 
	{
		perror("usrsctp_setsockopt SCTP_CONTEXT");
	}
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(int)) < 0)
	{
		perror("usrsctp_setsockopt SCTP_RECVRCVINFO");
	}

	if (use_udpencaps) 
	{
		memset(&encaps, 0, sizeof(struct sctp_udpencaps));
		encaps.sue_address.ss_family = AF_INET6;
		encaps.sue_port = htons((uint16_t)REMOTE_ENCAPS_PORT);
		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) 
		{
			perror("usrsctp_setsockopt SCTP_REMOTE_UDP_ENCAPS_PORT");
		}
	}

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_FUTURE_ASSOC;
	event.se_on = 1;
	for (i = 0; i < (unsigned int)(sizeof(event_types)/sizeof(uint16_t)); i++) 
	{
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(struct sctp_event)) < 0) 
		{
			perror("usrsctp_setsockopt SCTP_EVENT");
		}
	}


	memset((void *)&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(PORT);
	addr.sin6_addr = in6addr_any;
	if (usrsctp_bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) < 0) 
	{
		perror("usrsctp_bind");
	}
	if (usrsctp_listen(sock, 1) < 0) 
	{
		perror("usrsctp_listen");
	}
	while (1) 
	{
		sleep(SLEEP);	
	}
	usrsctp_close(sock);
	while (usrsctp_finish() != 0) 
	{

		sleep(SLEEP);

	}
	return (0);
}