/*
 *
 *  This code is Copyright (C) 2001, 2018, David Hoelzer
 *  Please feel free to make modifications to this code, however,
 *  license is -not- granted for redistribution of modifications
 *  or of modified code.  License is granted for all non-commercial
 *  use, meaning, you may not use this code or portions thereof
 *  to create some other commercial product.
 *
 */

/*
 *  This code takes a libpcap compatible file and allows you to
 *  perform some statistical analysis against the packets.
 *  The idea is that "interesting" communication channels
 *  may be revealed by identifying portions of packets that
 *  repeat with some frequency.  This should allow us to
 *  identify potential covert channels (or communications
 *  over well known ports that does not conform to the
 *  expected behaviour of the protocol for that port) in
 *  the vast sea of network traffic that passes by our sensors.
 *
 *  libpcap 0.4 (or higher) is required.
 */

#define VERSION "0.6"
// Rev 0.1 - Initial Release
// Rev 0.5 - Added checksum support
//    We have developed a suspicion that there are checksums that will almost never appear
//    and others that will be quite common.  Thought we'd add something to test this out.
// Rev 0.6 - Added more detailed help as requested.


#include<stdio.h>
#include<unistd.h>
#include<pcap.h>
#include<stdlib.h>
#include<time.h>
#include<math.h>

#define GOT_SOURCE 1
#define SRC_PORTS  2
#define DST_PORTS  4
#define GOT_BPF    8
#define IPIDS      16
#define SEQ_NUMS   32
#define QUIET      64
#define SRC_HOSTS  128
#define CHECKSUM 256
#define KEYLENGTH  32

struct root_struct
{
  unsigned char key[KEYLENGTH];
  unsigned int count;
  int hash_value;
  struct root_struct *next_root, *prev_root;
} ;

void DEBUG(char *debug_string);
float standard_deviation(struct root_struct *ptr);
unsigned int hash(char *key);
void print_results(struct root_struct *ptr);
struct root_struct *find_root(unsigned char key[KEYLENGTH],
			      struct root_struct *master_root);
void insert(struct root_struct *insertme);
struct root_struct *new_root();
pcap_handler analyze_packets(unsigned char *p, struct pcap_pkthdr *h, unsigned char *packet);
void usage();
int get_header_length(unsigned char *packet);
float average(struct root_struct *ptr);

int significant_bytes;
unsigned int node_struct_size, root_struct_size;
int hash_hits, hash_misses, sigs;
unsigned long int packets;
char source_file[512], dest_file[512], the_filter[4096];
char ebuff[4096];
pcap_t *input;
pcap_dumper_t *output;
struct bpf_program program;
struct root_struct *root, *last;
struct root_struct *hash_table[1048576];
unsigned int flags;
int _debug = 0;
float anomalosity = 1;
float median = 0;

void DEBUG(char *debug_string)
{
  if(_debug) { printf("DBG: %s\n",debug_string); }
}

unsigned int hash(char *key)
{
  unsigned char chars[KEYLENGTH];
  unsigned int hashval;
  int x;

  if(flags & (SRC_PORTS | DST_PORTS | IPIDS | CHECKSUM))
    {
      hashval = *((unsigned short int *)key);
      return (hashval);
    }
  if(flags & (SEQ_NUMS | SRC_HOSTS))
    {
      hashval = *((unsigned short int *)key);
      return (hashval);
    }
  for(x=0;x!=significant_bytes;x++) chars[x] = key[x];
  hashval = 0;
  for(x=0;x!=significant_bytes;x++) hashval ^= (chars[x] << x);
  //  hashval = ((char1 ^ char2<<3 ^ char3<<6 ^ char4 << 9 ^
  //     char5<<12 ^ char6<<14 ^ char7<<17 ^ char8 << 19)) & 0xfffff;
  hashval &= 0xfffff;
  return(hashval);
}

int main(int argc, char **argv)
{
  char option;
  u_char buffer[4096];
  unsigned int modify_significant_bytes = 0;

  // Clear our vars
  strcpy(source_file, "");
  strcpy(dest_file, "");
  flags = 0;
  root_struct_size = sizeof(struct root_struct);
  root = NULL;
  last = root;
  packets = hash_hits = hash_misses = sigs = 0;
  bzero(hash_table, sizeof(struct root_struct *) * 65536);
  significant_bytes = 32;

  // Get command line args
  for(option = getopt(argc, argv, "qscdSihr:a:b:");
      option != -1;
      option = getopt(argc, argv, "qscdSihr:a:b:"))
    {
      switch(option)
	{
  case 'c':
    flags |= CHECKSUM;
    significant_bytes = 2;
    break;
	case 'h' :
	  flags |= SRC_HOSTS;
	  significant_bytes = 4;
	  break;
	case 'q' :
	  flags |= QUIET;
	  break;
	case 'r' : 
	  strncpy(source_file, optarg, 511);
	  flags |= GOT_SOURCE;
	  break;
	case 'a' :
	  sscanf(optarg, "%f", &anomalosity);
	  break;
  case 'b':
    sscanf(optarg, "%d", &modify_significant_bytes);
    break;
	case 's' :
	  flags |= SRC_PORTS;
	  significant_bytes = 2;
	  break;
	case 'd' :
	  flags |= DST_PORTS;
	  significant_bytes = 2;
	  break;
	case 'S' :
	  flags |= SEQ_NUMS;
	  significant_bytes = 4;
	  break;
	case 'i' :
	  flags |= IPIDS;
	  significant_bytes = 2;
	  break;
	default : usage();
	}
    }
  // Added logic to allow you to limit or expand the size of the hashed value/unique payload length.
  if(significant_bytes == 32 && modify_significant_bytes > 0 && modify_significant_bytes < 64){
    significant_bytes = modify_significant_bytes;
  }
  if(!(flags & QUIET)) 
    printf("Packet Analysis Engine Version %s\nCopyright 2001, 2018, David Hoelzer\n",
	 VERSION);
  // Check for required args:
  if(!flags || !(flags & GOT_SOURCE)) { usage(); }

  if(!(flags & QUIET)) printf("Reading from %s\n", source_file);

  input = pcap_open_offline(source_file, ebuff);
  if(!input)
    {
      printf("Could not open dump file for reading!\n");
      exit(1);
    }  
  strcpy(the_filter, (flags & SEQ_NUMS ? "tcp and tcp[4:4] != 0" : 
		      (flags & (SRC_HOSTS | CHECKSUM) ? 
		       "ip " :
		       (flags & (SRC_PORTS | DST_PORTS) ?
			"(tcp or udp)" : 
			(flags & IPIDS ? "ip and not ip[4:2]=0" :
			 "tcp or udp")))));
  if(pcap_compile(input, &program, the_filter, 1, 24) < 0)
    {
      printf("BPF Filter error.\n");
      exit(3);
    }

  pcap_setfilter(input, &program);
  if(!(flags & QUIET))
    {
      /*      printf("%x %x %x %x %x\n",flags, flags & SRC_PORTS,
	      flags & DST_PORTS, flags & IPIDS, flags & SEQ_NUMS);*/
      printf("Producing analysis of %s.\n",
	     (flags & SRC_PORTS ? "Source Ports" :
	      (flags & DST_PORTS ? "Destination Ports" :
	       (flags & IPIDS ? "IP ID Numbers" :
      		(flags & SEQ_NUMS ? "Sequence Numbers" : 
            (flags & CHECKSUM ? "Checksums" : 
      		    (flags & SRC_HOSTS ? "Source Hosts" : "Payloads")))))));
      printf("Processing...\n");
    }
  /* I can't find any documentation in the man page for libpcap explaining
     what exactly this last argument (buffer) is for, but there it is...
  */
  DEBUG("Entering pcap loop");
  pcap_loop(input, 0, (pcap_handler)analyze_packets, buffer);
  if(!(flags & QUIET)) printf("Cleaning up.\n");
  pcap_close(input);
  print_results(root);
}

pcap_handler analyze_packets(unsigned char *p, struct pcap_pkthdr *h, unsigned char *packet)
{
  /*
    Assumption:  We are only worried about Ethernet
    Process:  Grab the packet headers, identify protocol
              and attach pointers to the headers.  Key the
	      packets using a hash of the IP port pairs.
	      Build a tree according to packet contents.
	      Nodes will hold value and count.  Top level
	      counts can be used to deduce frequency.
  */

  unsigned char *ip_header, *saddr, *daddr, *checksum, *chkptr, *data;
  unsigned int ip_words[64];
  unsigned int i, header_length, num_words, chksum;
  unsigned char chkflag;
  unsigned int hash_value;
  struct root_struct *ptr;

  packets++;
  DEBUG("Handling packet");
  ip_header = (packet + 14);
  header_length = get_header_length(ip_header);
  switch(ip_header[9])
    {
    case 0x01 : //ICMP
      data = ip_header + header_length + 4;
      break;
    case 0x06 : //TCP
      data = ip_header + header_length + 20;
      break;
    case 0x11: //UDP
      data = ip_header + header_length + 8;
      break;
    case 0x32: //ESP
      data = ip_header + header_length + 8;
      break;
    case 0x02: //IGMP
      data = ip_header + header_length + 8;
      break;
    default : 
      if(!(flags & QUIET))
	printf("\tUnknown: %x\n", (unsigned char)ip_header[9] );
      data = ip_header + header_length;
      break;
    }
  data = (flags & SRC_PORTS ? ip_header + header_length :
	  (flags & DST_PORTS ? ip_header + header_length + 2 :
	   (flags & IPIDS ? ip_header + 4 :
	    (flags & SEQ_NUMS ? ip_header + header_length + 4 :
	     (flags & SRC_HOSTS ? ip_header + 12 :
        (flags & CHECKSUM ? ip_header + 10 :
	     data))))));
  if((data + significant_bytes) > 
     (ip_header + ntohs(*((unsigned short int *)ip_header+1))))
    {
      // TODO: This should be modified, especially for Payload options, to pad the payload out.
      // Still, we shouldn't pad a packet that has zero data.
      if(!(flags & QUIET)) printf("Not enough data!\n");
      return 0;
    }
  ptr = find_root(data, root);
  DEBUG("Root found");
  if(ptr == NULL)
    {
      DEBUG("New root needed");
      ptr = new_root();
      DEBUG("New root allocated");
      sigs++;
      memcpy(ptr->key, data, significant_bytes);
      DEBUG("Completed memcpy");
      hash_value = hash(data);
      ptr -> hash_value = hash_value;
      if(root == NULL)
	{ 
	  hash_table[hash_value] = ptr;
	  root = ptr;
	  last = root;
	}
      else 
	{
	  insert(ptr);
	}
    }
  ptr->count ++;
  bzero(data, significant_bytes + 1);
}
 
void insert(struct root_struct *insertme)
{
  unsigned int hash_value;
  struct root_struct *ptr1, *ptr2;
  int comparison;
  int element = 0;

  DEBUG("Inserting");
  hash_value = insertme -> hash_value;
  // Check hash table first
  if(hash_table[hash_value] != NULL)
    {
      ptr1 = hash_table[hash_value];
      ptr2 = ptr1 -> next_root;
      insertme -> prev_root = ptr1;
      insertme -> next_root = ptr2;
      ptr1 -> next_root = insertme;
      if(ptr2 != NULL) ptr2 -> prev_root = insertme;
      return;
    }

  ptr1 = root;
  ptr2 = ptr1 -> next_root;
  insertme -> prev_root = ptr1;
  insertme -> next_root = ptr2;
  ptr1 -> next_root = insertme;
  if(ptr2) ptr2 -> prev_root = insertme;
  hash_table[hash_value] = insertme;
  /*
  while(ptr1 != NULL)
  {
  element ++;
  comparison = (ptr1 -> hash_value < insertme -> hash_value ? 0 : 1);
  if(comparison == 0) 
  {
  ptr2 = ptr1 -> next_root;
  if(ptr2) ptr2 -> prev_root = insertme;
  insertme -> next_root = ptr2;
  insertme -> prev_root = ptr1;
  ptr1 -> next_root = insertme;
  return;
  }
  ptr2 = ptr1;
  ptr1 = ptr1->next_root;
  }
  ptr2 -> next_root = insertme;
  insertme -> prev_root = ptr2;
  hash_table[hash_value] = insertme;
  last = insertme;
  */
}

int get_header_length(unsigned char *packet)
{
  unsigned char x, y;

  x = (unsigned char)(*packet);
  //  y = x / 256; /* Shift right 8 bits */
  x = x & 0x0f; /* Mask off high nibble */
  return ((int)(x * 4)); /* Multiply by 4 */
}

void usage()
{
  printf("Usage:\n\tpae -r source_file [-h|i|s|c|d|S] [-q] [-a <anomalosity value>]\n\n");
  printf("\t-h\tThis help\n");
  printf("\t-i\tExtract and count occurrences of discrete IP ID values.\n");
  printf("\t-s\tExtract and count occurrences of discrete source port numbers.\n");
  printf("\t-c\tExtract and count occurrences of discrete IP checksum values.\n");
  printf("\t-d\tExtract and count occurrences of discrete destination port numbers.\n");
  printf("\t-S\tExtract and count occurrences of discrete TCP sequence numbers\n");
  printf("\t-q\tSuppress internal hash table statistics information\n");
  printf("\t-a\tConfigure an 'Anomalosity' value (how anomalous is this?) as a filter for values displayed.\n");
  printf("\t\tIf given no extraction options, PAE will extract and count discrete occurrences of the first 32 bytes of data\n");
  exit(3);
}

struct root_struct *new_root()
{
  struct root_struct *node;

  DEBUG("New root"); 
  node = (struct root_struct *)malloc(root_struct_size);
  if(node == NULL)
    {
      printf("Error in Malloc (root).\n");
      exit(3);
    }
  node -> count = 0;
  node -> next_root = NULL;
  node -> prev_root = NULL;
  return node;
}

struct root_struct *find_root(unsigned char key[KEYLENGTH],
			      struct root_struct *master_root)
{
  struct root_struct *ptr;
  unsigned int hash_value;
  int comparison;

  ptr = master_root;
 
  DEBUG("Find root"); 
  hash_value = hash(key);
  if(hash_table[hash_value] == NULL)
    {
      hash_misses ++;
      return(NULL);
    }
  hash_hits ++;
  ptr = hash_table[hash_value];
  while(ptr != NULL)
    {
      comparison = strncmp(ptr->key, key, significant_bytes);
      if(comparison == 0) {return(ptr);}
      ptr = ptr -> next_root;
      if(ptr != NULL && ptr->hash_value != hash_value) return(NULL);
    }
  return(NULL);
}

float standard_deviation(struct root_struct *ptr)
{
  double avg, total, n, x, y;
  int greatest, least, ones;
  struct root_struct *this;

  DEBUG("Standard Deviation");
  greatest = 0;
  ones = 0;
  least = 99999;
  this = ptr;
  if(this == NULL) return 0;
  x=n=total=0;
  avg = 0;
  while(this)
    {
      if(this->count == 1) ones++;
      if(this->count > greatest) greatest = this->count;
      if(this->count < least) least = this->count;
      total += this->count;
      n++;
      this = this->next_root;
    }
  avg = average(ptr);

  total = 0;
  this = ptr;

  while(this)
    {
      y = this->count - avg;
      total = total + (y * y);
      this = this->next_root;
    }
  x = sqrt(((double)total / (double)n));
  /*  if(!(flags & QUIET))  printf("%f %f %f %f\n%d %d %d\n",
      total, average(ptr), n, x, greatest, least, ones);*/
  return (int)x;
}

float average(struct root_struct *ptr)
{
  unsigned long int total;
  int count;
  struct root_struct *this;

  DEBUG("Average");
  this = ptr;
  total = count = 0;
  if(!this) return 0;
  while(this)
    {
      count ++;
      total += this->count;
      this = this->next_root;
    }
  return((float)((float)total / (float)count));
}

float get_median(struct root_struct *ptr)
{
	unsigned long int min,max;
	struct root_struct *this;

	this = ptr;
	min = max = ptr -> count;
	while(this)
	{
		if(this -> count < min) { min = this -> count; }
		if(this -> count > max) { max = this -> count; }
		this = this -> next_root;
	}
	return((float)((float)min + (float)max)/2.0);
}

void print_results(struct root_struct *ptr)
{
  int x, hashes, gt100, bucket_reuse, bmax, bmin, average_count;
  float std_dev;
  unsigned int lasthash;

  DEBUG("Print results");
  hashes = gt100 = bucket_reuse = bmax = 0;
  bmin = 999999;

  if(ptr == NULL)
    {
      printf("No packets!\n");
      return;
    }
    average_count = average(ptr);
    median = get_median(ptr);
    /*
    if(!(flags & (SEQ_NUMS | IPIDS | SRC_PORTS | DST_PORTS | SRC_HOSTS)))
    {
      average_count = (average_count + 2) * 100; 
    }
  if(flags & (SRC_HOSTS | SRC_PORTS | DST_PORTS))
    {
      average_count = (average_count + 2) * 50;
    }
  if(flags & SEQ_NUMS) 
    {
      average_count = (average_count * 1000);
    }
  if(flags & IPIDS)
    {
      average_count = average_count * 2;
    }
  */
    std_dev=standard_deviation(root);
  lasthash = ptr -> hash_value;
  hashes ++;
  while(ptr)
    {
      bucket_reuse++;
      if(lasthash != ptr -> hash_value)
    	{
    	  hashes ++;
    	  lasthash = ptr -> hash_value;
    	  if(bmax < bucket_reuse) bmax = bucket_reuse;
    	  if(bmin > bucket_reuse) bmin = bucket_reuse;
    	  bucket_reuse = 0;
    	}
//      if(abs(ptr -> count - median) > ((std_dev * anomalosity) ))
    	{
    	  gt100 ++;
    	  if(!(flags & (SEQ_NUMS | IPIDS | SRC_PORTS | DST_PORTS | SRC_HOSTS | CHECKSUM)))
    	 {
    	      if(ptr->count > anomalosity){
      	      printf("+-------------------------------------------"\
      		     "--------------------------------------------+\n");
      	      for(x=0;x!=significant_bytes;x++)
          		{
          		  printf("%s%x ", (ptr->key[x] < 16 ? "0" : ""),
          			 (unsigned char)(ptr->key[x]));
          		}
      	      printf("\n");
      	      for(x=0;x!=significant_bytes;x++)
          		{
          		  printf("%c  ",(isprint(ptr->key[x])? ptr->key[x] : '.'));
          		}	
      	      printf(" -#: %d\n", ptr->count);
    	      }
    	 } else {
    	  printf("%d ", 
    		ptr->count);
    	 }
      
	  if((flags & DST_PORTS) | (flags & SRC_PORTS) | (flags &IPIDS) | (flags & CHECKSUM))
	    {
	      unsigned short int port;
	      port = ntohs(((unsigned short int *)ptr->key)[0]);
	      printf("%u\n",port);
	    }
	  if(flags & SEQ_NUMS)
	    {
	      unsigned long int seq;
	      seq = ntohl(((unsigned long int *)ptr->key)[0]);
	      printf("%u\n",seq);
	    }
	  if(flags & SRC_HOSTS)
	    {
	      unsigned char octet;
	      int x;
	      for (x=0; x!= 4; x++)
		{
		  octet = *((unsigned char *)(ptr->key)+x);
		  printf("%u%c", octet, (x == 3 ? ' ' : '.'));
		}
    printf("\n");
	    }
	}
      ptr = ptr->next_root;
    }
  if(!(flags & QUIET))
    {
      printf("Hashes: %d\nHits: %d\nMisses: %d\nSignatures: "\
	     "%d\nHits > 100: %d\nPackets: %u\n"\
	     "Efficiency: Max Reuse: %d  Min Reuse: %d\n",
	     hashes, hash_hits, hash_misses, sigs, gt100, packets, bmax, bmin);
      printf("Standard Deviation: %f Average: %f Median: %f\n",standard_deviation(root),average(root),get_median(root));
    }
}
