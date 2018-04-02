#include <pcap.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Grab a packet */
	packet = pcap_next(handle, &header);

	/*print*/
 	int i = 0;

	printf("---------- ALL -----------\n");
 	for(i=0; i<34; ++i){
 	printf("%.2x ",*packet);
 	packet++;
	}

	packet = pcap_next(handle, &header);
	printf("\n");
 	printf("-------- ethernet --------\n");
 	printf("Destination : \t\t");
 	for(i=0; i<6; ++i){
 	printf("%.2x ",*packet);
 	packet++;
	}
	printf("\n");

	printf("Source : \t\t");
 	for(i; i<12; ++i){
 	printf("%.2x ",*packet);
 	packet++;
	}
	printf("\n");

	printf("type : \t\t");
 	for(i; i<14; ++i){
 	printf("%d ",*packet);
 	packet++;
	}
	printf("\n");

 	printf("----------- IP -----------\n");
	printf("HeaderLength : \t\t");
 	for(i; i<15; ++i){
 	printf("%d ",*packet);
 	packet++;
	}
	printf("\n");

	printf("TotalLength : \t\t");
 	for(i=16; i<18; ++i){
 	printf("%d ",*packet);
 	packet++;
	}
	printf("\n");

	printf("Protocol : \t\t");
 	for(i=23; i<24; ++i){
 	printf("%d ",*packet);
 	packet++;
	}
	printf("\n");

	printf("IP Source : \t\t");
 	for(i=26; i<30; ++i){
 	printf("%d.",*packet);
 	packet++;
	}
	printf("\n");

	printf("IP Destination : \t");
 	for(i; i<34; ++i){
 	printf("%d.",*packet);
 	packet++;
	}
	printf("\n");

 	//for
	printf("\n-----------------\n");

	/* And close the session */
	pcap_close(handle);
	return(0);
}
