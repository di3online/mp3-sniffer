/*
 * v0.1 2011-11-18
 *
 * gcc -o mp3-sniffer mp3-sniffer.c -lpcap
 *
 */

#include "mp3-sniffer.h"

#define MAX_DUMPS 50
struct dump **dumps;



int contain_mp3(char *payload, int len)
{
	char *p;
	int mp3_found = 0;
	int len_found = 0;
	u_int content_len = 0;
	for (p=(char *)payload; (int)p < ((int)payload)+len; p++) {
		if ( !mp3_found && memcmp(p, "Content-Type: audio/mpeg", 24) == 0) {
			mp3_found = 1;
			p += 24;
		}
		else if (!len_found && memcmp(p, "Content-Length: ", 16) == 0) {
			char *l;
			p += 16;
			len_found = 1;
			l = strndup(p, strchr(p, '\r') - p);
			content_len = atoi(l);
			free(l);
		}
		if (mp3_found && len_found) {
			return content_len;
		}
	}
	return 0;
}

struct dump* create_dump_stream(u_short port, u_int seq, u_int file_size, char *payload, u_int payload_size, char* mp3) {
	int i;
	struct dump *dp;
	char f[32];

	dp = malloc(sizeof(struct dump));
	dp->payload_count = 0;
	dp->head = NULL;
	dp->tail = NULL;
	dp->fail_count = 0;
	dp->port = port;
	dp->current_size = 0;
	dp->expected_size = file_size;
	dp->timestamp = time(NULL);
	dp->next_seq = seq;
	sprintf(f, "%d.mp3", dp->timestamp);
	dp->filename = strdup(f);
	printf("Saving: %s\n", dp->filename);
	dp->file = fopen(dp->filename, "w");
	for (i=0; i<MAX_DUMPS; i++) {
		if (dumps[i] == NULL) {
			dumps[i] = dp;
			break;
		}
	}
	if (i == MAX_DUMPS) {
		fprintf(stderr, "Too many concurrent dumps");
		free(dp);
		dp = NULL;
	}

	return dp;
}

struct dump* get_dump_stream(u_short port) {
	struct dump *dp = NULL;
	int i;

	for (i = 0; i<MAX_DUMPS; i++) {
		if ((dp = dumps[i]) != NULL) {
			 if (dp->port == port) {
				 return dp;
			 }
		}

	}
	return dp;
}

void close_dump_stream(struct dump* dp, int error) {
	int i;
	struct payload *p;
	if (error) {
		printf("Finished receiving \"%s\" with errors\n", dp->filename);
	}
	else {
		printf("Finished receiving \"%s\"", dp->filename);
		printf(" [size: %.1fM]\n", (float)dp->expected_size/(1024*1024));
	}
	fclose(dp->file);
	for (i = 0; i < MAX_DUMPS; ++i) {
		if (dumps[i] == dp) {
			dumps[i] = NULL;
		}
	}
	free(dp->filename);
	for (p = dp->head; p != NULL; ) {
		struct payload *p2;
		free(p->data);
		p2 = p;
		p = p->next;
		free(p2);
	}
	free(dp);
}


void write_dump(struct dump* dp, char *data, u_int len) {
	fwrite(data, 1, len, dp->file);
	dp->next_seq += len;
	dp->current_size += len;

	if (dp->current_size >= dp->expected_size) {
		close_dump_stream(dp, 0);
	}
}

void store_packet(struct dump *dp, u_int seq, char *payload, int size) {
	struct payload *p;

	p = malloc(sizeof(struct payload));
	p->data = malloc(size);
	memcpy(p->data, payload, size);
	p->length = size;
	p->next = NULL;
	p->seq = seq;

	dp->payload_count++;

	if (dp->tail == NULL) {
		dp->head = dp->tail = p;
	}
	else {
		dp->tail->next = p;
		dp->tail = p;
	}

	if (dp->payload_count > 20) {
		dp->payload_count--;
		free(dp->head->data);
		p = dp->head;
		dp->head = dp->head->next;
		free(p);
	}
}


struct payload *find_valid_seq(struct dump *dp, u_int seq) {
	struct payload *p;

	for (p = dp->head; p != NULL; p = p->next) {
		if (p->seq == seq) {

			return p;
		}
	}
	return NULL;
}


void process_packet(struct pcap_pkthdr* pkthdr, u_char* packet) {
	struct eth_hdr *eth;
	struct ip_hdr *ip;
	struct tcp_hdr *tcp;
	char *payload;
	int size_ip, size_tcp, payload_size;
	u_int mp3_len;
	struct dump *dp;

	// --------------------------------------------------------

	eth = (struct eth_hdr *) packet;
	if (ntohs (eth->ether_type) != 0x0800)
	{
		return;
	}
	ip = (struct ip_hdr*)(packet + SIZE_ETHERNET);
	if (ip->ip_p != IPPROTO_TCP) {
		return;
	}
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	payload_size = ntohs(ip->ip_len) - (size_ip + size_tcp);

	// --------------------------------------------------------

	//check_old_streams();

	if ((dp = get_dump_stream(ntohs(tcp->th_dport))) != NULL) {
		if (dp->next_seq != ntohl(tcp->th_seq)) {
			struct payload *old;

			//printf("invalid seq number got: %u  expected: %u\n", ntohl(tcp->th_seq), dp->next_seq);

			store_packet(dp, ntohl(tcp->th_seq), payload, payload_size);

			/* try to find the valid packet */
			old = find_valid_seq(dp, ntohl(tcp->th_seq));
			if (old) {
				write_dump(dp, old->data, old->length);
				return;
			}

			if (++dp->fail_count > 5) {
				close_dump_stream(dp, 1);
			}

			return;

		}
		write_dump(dp, payload, payload_size);
	}
	else if ((mp3_len = contain_mp3(payload, payload_size)) > 0) {
		char *start;
		start = strstr(payload, "\r\n\r\n") + 4;
		dp = create_dump_stream(ntohs(tcp->th_dport), ntohl(tcp->th_seq), mp3_len, payload, payload_size, start);
		dp->current_size += payload_size - (start - payload);
		fwrite(start, 1, dp->current_size, dp->file);
		dp->next_seq += payload_size;
	}
}


static void pcap_callback(u_char *useless, struct pcap_pkthdr* pkthdr,u_char* packet)
{
	process_packet(pkthdr, packet);
}

int main ()
{
	char errbuf[256];
	char *dev;
	pcap_t* pcap_descr;
	int i;

	dumps = calloc(MAX_DUMPS, sizeof(struct dump*));

	dev = pcap_lookupdev(errbuf);
	pcap_descr= pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(pcap_descr == NULL) {
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);
	}

	pcap_loop(pcap_descr, -1, (pcap_handler)pcap_callback, NULL);

	printf("\nDone processing packets...\n");
	return 0;
}

