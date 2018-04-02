/*pc_sniff.c*/
#include <pcap.h>
void dump(const u_char *packet,int len);
int main(){
  struct pcap_pkthdr header;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;
  int i;
  device = pcap_lookupdev(errbuf);
  if(device == 0){ printf("fail lookupdev...%s\n",errbuf); }
  printf("start device: %s sniffing\n",device);

  pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
  if(pcap_handle == 0){ printf("fail pcap_open_live...%s\n",errbuf); }
  
  for(i=0; i<3; i++){
    packet = pcap_next(pcap_handle, &header);    
    dump(packet, header.len);
  }//for
  pcap_close(pcap_handle);
  return 0;
}
void dump(const u_char *packet,int len){
  int i = 0;
  printf("--------capture %d byte--------\n",len);
  for(i=0; i<len; ++i){
    printf("%.2x ",*packet);
    packet++;
    if(i%25 == 24){ printf("\n"); }
  }//for
  printf("\n-----------------\n");
}
