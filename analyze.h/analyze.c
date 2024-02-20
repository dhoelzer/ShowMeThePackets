/*
 *
 *  This code is Copyright (C) 2022, David Hoelzer
 *  Please feel free to make modifications to this code, however,
 *  license is -not- granted for redistribution of modifications
 *  or of modified code.  License is granted for all non-commercial
 *  use, meaning, you may not use this code or portions thereof
 *  to create some other commercial product.
 *
 */

#define VERSION "0.1"
// Rev 0.1 - Initial Release

// The following is required for strptime() to be defined.
#define __USE_XOPEN
#define _GNU_SOURCE

#include<stdio.h>
#include<unistd.h>
#include<pcap.h>
#include<stdlib.h>
#include<time.h>
#include<ctype.h>
#include<strings.h>
#include<string.h>
#include<dirent.h>

// Defines
#define     MAX_FILEPATH_LENGTH         512
#define     MAX_SENSORNAME_LENGTH       512

// Function Defs
void DEBUG(char *debug_string);

// Global vars
char packet_path[MAX_FILEPATH_LENGTH];  // Arbitrarily limited

void DEBUG(char *debug_string)
{
#ifdef _debug
  printf("DBG: %s\n",debug_string);
#endif
}

int load_config(char *config_file)
{
    char conf_file[MAX_FILEPATH_LENGTH];

    if(config_file != NULL && strlen(config_file) > 0){
        strncpy(conf_file, config_file, MAX_FILEPATH_LENGTH-1);    
    }
}

void usage(char *command)
{
    printf("Usage: %s [-s <starting time>] [-e <ending time>] <sensor>\n", command);
    printf("Extract packets from a packet repository.\n\n");
    printf("\t-s\tSpecify a starting timestamp.  The timestamp can be specified\n");
    printf("\t\tusing the month/day/year convention or the year/month/day convention.\n\n");
    printf("\t\tYou may specify only the date, which is equivalent to 00:00:00 on the \n");
    printf("\t\tdate specified, or you may specify a more specific time by including either\n");
    printf("\t\thours and minutes or hours, minutes, and seconds.  The starting time is inclusive.\n\n");
    printf("\t-e\tSpecify an ending timestamp.  The timestamp can be specified\n");
    printf("\t\tusing the month/day/year convention or the year/month/day convention.\n\n");
    printf("\t\tYou may specify only the date, which is equivalent to 00:00:00 on the \n");
    printf("\t\tdate specified, or you may specify a more specific time by including either\n");
    printf("\t\thours and minutes or hours, minutes, and seconds.  The ending time is exclusive.\n\n");
    printf("\t\tIf the starting time is not specified, all packets up to the ending time will be returned.\n");
    printf("\t\tIf the ending time is not specified, all packets from the starting time will be returned.\n");
    printf("\t\tIf both the starting and ending times are not specified, all packets from the specified\n");
    printf("\t\tsensor will be returned.\n\n");
    printf("\tExamples:\n");
    printf("\t---------\n");
    printf("\t%s -s '5/1/19' sensor\n", command);
    printf("\t%s -s '05/01/19' sensor\n", command);
    printf("\t%s -e '05/01/2019' sensor\n", command);
    printf("\t%s -s '19/05/01' -e '2019/05/01' sensor\n", command);
    printf("\t%s -s '5/1/19 13:15' -e '2019/05/02 23:50:15' sensor\n", command);
    printf("\n");
}
int main(int argc, char **argv)
{
    char path[512], source_file[512], dest_file[512], the_filter[4096];
    char ebuff[4096];
    pcap_t *input;
    pcap_t *out;
    pcap_dumper_t *output;
    struct pcap_pkthdr *pkt;
    const u_char *data;
    struct timeval last_time;
    int start_spooling = 0;
    int status = 1;
    int sensor_index = -1;
    char start_time[] = "1970/01/01 00:00:00";
    char end_time[] = "12/30/2199 23:59:59";
    struct tm *time_temp;
    long int start, end;
    struct bpf_program program;
    struct dirent **dir;

    /* Getopt stuff */
    int c;

    while((c = getopt(argc, argv, "hs:e:")) != -1)
        switch(c)
        {
            case 's':
                strncpy(start_time, optarg, 19);
                break;
            case 'e':
                strncpy(end_time, optarg, 19);
                break;
            case '?':
                printf("Unknown argument '-%c'.\n", optopt);
                return 1;
            case 'h':
                usage(argv[0]);
                return 1;
        }
    if(optind == argc){
        printf("You must specify a sensor.  Sensors available are: [ ");
        strcpy(path, "/data/packets");
        int entries = scandir(path, &dir, 0, alphasort);
        if(entries < 0){
            printf("The base path for the packet repository is missing!\n");
            return 1;
        }
        for(int i = 0; i != entries; i++){
            if(dir[i]->d_name[0] != '.') printf("%s ", dir[i]->d_name);
        }
        printf(" ]\n");
        return 1;
    }
    if(strlen(start_time) < 11){
        strcat(start_time, " 00:00:00");
    }
    time_temp = getdate(start_time);
    if(getdate_err){
        printf("The starting timestamp must be of the format '2019/05/01 00:00:00'.\n");
        return 1;
    }
    start = mktime(time_temp);
    if(strlen(end_time) < 11){
        strcat(end_time, " 00:00:00");
    }    
    time_temp = getdate(end_time);
    if(getdate_err){
        printf("The ending timestamp must be of the format '2019/05/01 00:00:00'.\n");
        return 1;
    }
    end = mktime(time_temp);
    if(end <= start){
        printf("The start time must be earlier than the end time.\n");
        return 1;
    }
    strcpy(path, "/data/packets/");
    strncat(path, argv[optind], 100); // Arbitrarily limited to 100 character sensor name
    strcat(path, "/dailylogs/");
    int entries = scandir(path, &dir, 0, alphasort);
    if(entries < 0){
        printf("No files?\n");
        return 1;
    }
    for(int i=0; i != entries; i++){
        if(dir[i]->d_name[0] != '.'){
            strcpy(start_time, dir[i]->d_name);
            strcat(start_time, " 00:00:00");
            time_temp = getdate(start_time);
            if(getdate_err){
                printf("Your packet repository seems to be corrupt?  %s", dir[i]->d_name);
                return 1;
            }
            long int this_dir_start_time = mktime(time_temp);
            int difference = start - this_dir_start_time;
            if(difference >= 0 && difference < 86400) start_spooling = 1;
            if(start_spooling)
                {
                    char packet_path[1024];
                    struct dirent **packet_files;
                    sprintf(packet_path, "%s%s", path, dir[i]->d_name);
                    int num_files = scandir(packet_path, &packet_files, 0, alphasort);
                    if(num_files < 0){
                        printf("Repository corrupt?\n");
                        return 1;
                    }
                    for(int file_num=0; file_num != num_files; file_num++){
                        char pcap_path[2048];
                        if(packet_files[file_num]->d_name[0] != '.'){
                            status = 1;
                            sprintf(pcap_path, "%s/%s", packet_path, packet_files[file_num]->d_name);
                            input = pcap_open_offline_with_tstamp_precision(pcap_path, PCAP_TSTAMP_PRECISION_NANO, ebuff);
                            if(!output) output = pcap_dump_open(input, "-");
                            while(status > 0){
                                status = pcap_next_ex(input, &pkt, &data);
                                last_time = pkt->ts;
                                if(status > 0 && pkt->ts.tv_sec < end && pkt->ts.tv_sec > start) pcap_dump((u_char *)output, pkt, data);
                            }
                            pcap_close(input);
                            if(pkt->ts.tv_sec > end){
                                pcap_dump_close(output);
                                return 0;
                            }
                        }
                    }
                }
        }
    }
    return 0;
}
