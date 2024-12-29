/*
 * David Hoelzer/Enclave Forensics, Inc. 2020
 * Conversion and unification of internal "analyze" tool.  Converted
 * to a compiled native application to allow handling of packet repositories
 * of any size and number of files without kernel modification.
 */
#include <pcap/pcap.h>
#include <stdio.h>
#include <dirent.h>
#include <malloc.h>

#define INFINITE    -1      /* pcap functions use -1 as infinity */
#define VERSION     "0.1"
#define REPO_DIR    "/data/packets"

/*
 * Globals:
 */
pcap_dumper_t *outputDump;      /* Required since this is opened separately from callback */

void usage()
{
    printf("'analyze' version %s, Enclave Forensics, Inc., 2020\n", VERSION);
    printf("Usage: analyze [<sensor>] [-s '<starting date/time>'] [-e '<ending date/time>\n\n");
    printf("Reads raw packets from a packet repository and streams them in pcap format to\n");
    printf("standard output.\n\n");
    printf("If no sensor is specified and more than one sensor directory then using analyze\n");
    printf("with no arguments will print a list of sensors that are available.  If there is \n");
    printf("only one sensor, analyze will select this sensor by default even if no sensor is\n");
    printf("specified.\n\n");
    printf(" -s  Specify starting date and time; if only a starting date/time is specified,\n");
    printf("     all packets from that date and time onward will be streamed.")
    printf(" -e  Specify ending date and time; if only an ending date/time is specified,\n");
    printf("     all packets in the repository up to that date/time will be streamed.\n\n");
    printf("If no date or time are specified, all packets in the repository will be streamed.\n");
}

/*
 * Callback function for pcap reader.  Streams packets to standard output via the
 * outputDump handle.
 */
pcap_handler callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  pcap_dump(outputDump, h, bytes);
}

char **get_sensor_list()
{
  struct dirent *de;
  char **list_of_names;

  DIR *dr = opendir(REPO_DIR);
  if(dr == NULL){
    usage();
    printf("\nError: The %s packet repository is missing or inaccessible!\n", REPO_DIR);
    exit(1);
  }
  while((de = readdir(dr)) != NULL)
  {
    if(de->d_name[0] != '.')
    {
      /* Allocate memory and store name in list */
      printf("%s\n", de->d_name);
    }
  }
  closedir(dr);
}

int main(int argc, char **argv)
{
  pcap_t *outputHandle, *inputHandle;;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_char *nothing;
  char **sensor_list;


  
  inputHandle = pcap_open_offline("1.pcap", errbuf);
  outputHandle = pcap_open_dead(pcap_datalink(inputHandle), -1);
  outputDump = pcap_dump_open(outputHandle, "-");
  pcap_loop(inputHandle, -1, (pcap_handler) &callback, nothing);
  inputHandle = pcap_open_offline("2.pcap", errbuf);
  pcap_loop(inputHandle, -1, &callback, nothing);


}
