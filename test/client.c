#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <io.h>
#endif
#include <usrsctp.h>
#include "programs_helper.h"
#include <time.h>

int done = 0;
const char *REMOTE_ADDR = "127.0.0.1";
#define REMOTE_PORT 9
#define LOCAL_PORT 0
#define LOCAL_ENCAPS_PORT 22222
#define REMOTE_ENCAPS_PORT 11111
#define BUFFER_SIZE 1024

const int use_udpencaps = 0;

static int receive_cb(struct socket *sock, union sctp_sockstore addr, void *data,
           size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
	if (data == NULL) 
	{
		done = 1;
		usrsctp_close(sock);
	} 
	else 
	{
		if (flags & MSG_NOTIFICATION) 
		{
			handle_notification((union sctp_notification *)data, datalen);
		} 
		else 
		{
			if (write(fileno(stdout), data, datalen) < 0) 
			{
				perror("write");
			}
		}
		free(data);
	}
	return (1);
}

int main()
{
	struct socket *sock;
	struct sockaddr *addr, *addrs;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sctp_udpencaps encaps;
	struct sctpstat stat;
	struct sctp_event event;
	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
	                          SCTP_PEER_ADDR_CHANGE,
	                          SCTP_SEND_FAILED_EVENT};
	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];

	unsigned int i;
	int n;

	struct timespec start, end;
	double latency;


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


	if ((sock = usrsctp_socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, NULL)) == NULL) 
	{
		perror("usrsctp_socket");
	}

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) 
	{
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) 
		{
			perror("setsockopt SCTP_EVENT");
		}
	}

	if (use_udpencaps) {
		memset((void *)&addr6, 0, sizeof(struct sockaddr_in6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons((uint16_t)LOCAL_PORT);
		addr6.sin6_addr = in6addr_any;
		if (usrsctp_bind(sock, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6)) < 0) 
		{
			perror("bind");
		}

		memset(&encaps, 0, sizeof(struct sctp_udpencaps));
		encaps.sue_address.ss_family = AF_INET6;
		encaps.sue_port = htons((uint16_t)REMOTE_ENCAPS_PORT);
		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
			perror("setsockopt");
		}
	}

	memset((void *)&addr4, 0, sizeof(struct sockaddr_in));
	memset((void *)&addr6, 0, sizeof(struct sockaddr_in6));

	addr4.sin_family = AF_INET;
	addr6.sin6_family = AF_INET6;
	addr4.sin_port = htons((uint16_t)REMOTE_PORT);
	addr6.sin6_port = htons((uint16_t)REMOTE_PORT);

	if (inet_pton(AF_INET6, REMOTE_ADDR, &addr6.sin6_addr) == 1) 
	{
		if (usrsctp_connect(sock, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6)) < 0) 
		{
			perror("usrsctp_connect");
		}
	} 
	else if (inet_pton(AF_INET, REMOTE_ADDR, &addr4.sin_addr) == 1) 
	{
		if (usrsctp_connect(sock, (struct sockaddr *)&addr4, sizeof(struct sockaddr_in)) < 0) 
		{
			perror("usrsctp_connect");
		}
	} 
	else 
	{
		printf("Illegal destination address.\n");
	}

	if ((n = usrsctp_getladdrs(sock, 0, &addrs)) < 0) 
	{
		perror("usrsctp_getladdrs");
	} 
	else 
	{
		addr = addrs;
		printf("Local addresses: ");
		for (i = 0; i < (unsigned int)n; i++) 
		{
			if (i > 0) 
			{
				printf("%s", ", ");
			}
			switch (addr->sa_family) 
			{
			case AF_INET:
			{
				struct sockaddr_in *sin;
				char buf[INET_ADDRSTRLEN];
				const char *name;

				sin = (struct sockaddr_in *)addr;
				name = inet_ntop(AF_INET, &sin->sin_addr, buf, INET_ADDRSTRLEN);
				printf("%s", name);
				break;
			}
			case AF_INET6:
			{
				struct sockaddr_in6 *sin6;
				char buf[INET6_ADDRSTRLEN];
				const char *name;

				sin6 = (struct sockaddr_in6 *)addr;
				name = inet_ntop(AF_INET6, &sin6->sin6_addr, buf, INET6_ADDRSTRLEN);
				printf("%s", name);
				break;
			}
			default:
				break;
			}
		}
		printf(".\n");
		usrsctp_freeladdrs(addrs);
	}


	if ((n = usrsctp_getpaddrs(sock, 0, &addrs)) < 0) 
	{
		perror("usrsctp_getpaddrs");
	} 
	else 
	{
		addr = addrs;
		printf("Peer addresses: ");
		for (i = 0; i < (unsigned int)n; i++) 
		{
			if (i > 0) 
			{
				printf("%s", ", ");
			}
			switch (addr->sa_family) 
			{
			case AF_INET:
			{
				struct sockaddr_in *sin;
				char buf[INET_ADDRSTRLEN];
				const char *name;

				sin = (struct sockaddr_in *)addr;
				name = inet_ntop(AF_INET, &sin->sin_addr, buf, INET_ADDRSTRLEN);
				printf("%s", name);
				break;
			}
			case AF_INET6:
			{
				struct sockaddr_in6 *sin6;
				char buf[INET6_ADDRSTRLEN];
				const char *name;

				sin6 = (struct sockaddr_in6 *)addr;
				name = inet_ntop(AF_INET6, &sin6->sin6_addr, buf, INET6_ADDRSTRLEN);
				printf("%s", name);
				break;
			}
			default:
				break;
			}
		}
		printf(".\n");
		usrsctp_freepaddrs(addrs);
	}

	// while ((fgets(send_buffer, sizeof(send_buffer), stdin) != NULL) && !done)
	// {
	// 	usrsctp_sendv(sock, send_buffer, strlen(send_buffer), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
	// }

	for (int i = 1; i <= 50; i++) 
	{
		snprintf(send_buffer, sizeof(send_buffer), "hello, how are you %d", i);
		if (usrsctp_sendv(sock, send_buffer, strlen(send_buffer), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0) < 0) 
		{
			perror("usrsctp_sendv");
			break; 
		}
		printf("Sent: %s\n", send_buffer); 
		sleep(1); 

	}

	if (!done) 
	{
		if (usrsctp_shutdown(sock, SHUT_WR) < 0) 
		{
			perror("usrsctp_shutdown");
		}
	}
	while (!done) 
	{
		sleep(1);
	}

	usrsctp_get_stat(&stat);
	printf("Number of packets (sent/received): (%u/%u).\n",
	       stat.sctps_outpackets, stat.sctps_inpackets);

	while (usrsctp_finish() != 0) 
	{
		sleep(1);
	}
	return(0);
}