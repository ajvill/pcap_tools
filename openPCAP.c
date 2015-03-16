#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

typedef struct flow_table__t {
    unsigned int sip;
    unsigned int tip;
    unsigned short sport;
    unsigned short tport;
    unsigned int found;
    //size_t   length; 
} flow_table_t;

int main(int argc, char *argv[])
{
  flow_table_t *flowTable = NULL;
  unsigned int flowTableCount = 0;
  unsigned int foundFlows = 0;
  unsigned int flowTableSize = 10000000;

  if ( argc < 3 ) {
    printf("%s: (file)\n", argv[0]);
    exit(1);
  }

  flowTable = (flow_table_t*) malloc(flowTableSize * sizeof(flow_table_t));
  if ( flowTable == NULL ) {
      perror("FlowTable is null\n");
      exit(1);
  }

  struct pcap_pkthdr *h = malloc (sizeof(struct pcap_pkthdr));
  if ( !h ) {
    perror("MALLOC: pcap pkthdr");
    exit(1);
  }

  char ERRBUF[PCAP_ERRBUF_SIZE];
  
  pcap_t *p  = pcap_open_offline(argv[1], ERRBUF);  //sessions pointer
  if ( !p ) {
    perror("Sessions pcap_open_offline:");
    exit(1);
  }

  printf("The flowtable contains %i flows\n", flowTableCount);
  unsigned int pc = 0;  //packet counter
  unsigned char *packet = NULL;
  //Make FlowTable 
  while ( (packet = (unsigned char*)pcap_next(p, h)) ) {
    // Filter on SYN Packets 
    if ( packet[0x2f] == 0x02 ) {
        unsigned char sip[4] = { packet[0x1a], packet[0x1b], packet[0x1c], packet[0x1d] };
        unsigned char tip[4] = { packet[0x1e], packet[0x1f], packet[0x20], packet[0x21] };
        unsigned char sport[2] = { packet[0x22], packet[0x23] };
        unsigned char tport[2] = { packet[0x24], packet[0x25] };
        unsigned int sipv = 0; unsigned int tipv = 0;
        unsigned short sportv = 0; unsigned short tportv = 0;
        unsigned char *sipv_p = (unsigned char*)&sipv;
        unsigned char *tipv_p = (unsigned char*)&tipv;
        unsigned char *sportv_p = (unsigned char*)&sportv;
        unsigned char *tportv_p = (unsigned char*)&tportv;
        sipv_p[0] = sip[3]; sipv_p[1] = sip[2]; sipv_p[2] = sip[1]; sipv_p[3] = sip[0];
        tipv_p[0] = tip[3]; tipv_p[1] = tip[2]; tipv_p[2] = tip[1]; tipv_p[3] = tip[0];
        sportv_p[0] = sport[1]; sportv_p[1] = sport[0];
        tportv_p[0] = tport[1]; tportv_p[1] = tport[0];

         if ( flowTable ) {
              flowTable[flowTableCount].sip = sipv; 
			  flowTable[flowTableCount].tip =  tipv;
              flowTable[flowTableCount].sport = sportv; 
			  flowTable[flowTableCount].tport = tportv;
              flowTable[flowTableCount].found = 0;
              flowTableCount++;
         } else {
              printf("MALLOC ERROR !!!\n");
              exit(1);
         }
    }
    pc++;
  }
  pcap_close(p);  //Releasing resources closing sessions pcap handler

  pcap_t *p_keepAlive = pcap_open_offline(argv[2], ERRBUF);  //Create handler to keepalive handler
  if ( !p_keepAlive ) {
    perror("KeepAlive pcap_open_offline:");
    exit(1);
  }

 //Go through next pcap here and start comparing against FlowTable
  while ( (packet = (unsigned char*)pcap_next(p_keepAlive, h)) ) {
    // Filter on ACK Packets 
    if ( packet[0x2f] == 0x10 ) {
        unsigned char sip[4] = { packet[0x1a], packet[0x1b], packet[0x1c], packet[0x1d] };
        unsigned char tip[4] = { packet[0x1e], packet[0x1f], packet[0x20], packet[0x21] };
        unsigned char sport[2] = { packet[0x22], packet[0x23] };
        unsigned char tport[2] = { packet[0x24], packet[0x25] };
        unsigned int sipv = 0; unsigned int tipv = 0;
        unsigned short sportv = 0; unsigned short tportv = 0;
        unsigned char *sipv_p = (unsigned char*)&sipv;
        unsigned char *tipv_p = (unsigned char*)&tipv;
        unsigned char *sportv_p = (unsigned char*)&sportv;
        unsigned char *tportv_p = (unsigned char*)&tportv;
        sipv_p[0] = sip[3]; sipv_p[1] = sip[2]; sipv_p[2] = sip[1]; sipv_p[3] = sip[0];
        tipv_p[0] = tip[3]; tipv_p[1] = tip[2]; tipv_p[2] = tip[1]; tipv_p[3] = tip[0];
        sportv_p[0] = sport[1]; sportv_p[1] = sport[0];
        tportv_p[0] = tport[1]; tportv_p[1] = tport[0];
		
		unsigned int sip_i;
		unsigned int tip_i;
		unsigned short sport_i;
		unsigned short tport_i;

		sip_i = sipv;
		tip_i = tipv;
		sport_i = sportv;
		tport_i = tportv;
	
        
		//Look for 4-tuple flow to complete match
	    unsigned int loop;
		for (loop  = 0; loop < flowTableCount; loop++) {
            if ( flowTable[loop].found == 0   &&
                 flowTable[loop].sip == sip_i &&
                 flowTable[loop].tip == tip_i )
                // flowTable[loop].sport == sport_i &&
                 //flowTable[loop].tport == tport_i ) {

                    flowTable[loop].found = 1;
                    foundFlows++;
                }
         }
         
    } //end of IF
  }  //end of While   
  pcap_close(p_keepAlive);
  free(flowTable);
  free(h);

  printf("The flowtable contains %i flows\n", flowTableCount);
  printf("I found %i flows\n", foundFlows);
  return 0;
}



