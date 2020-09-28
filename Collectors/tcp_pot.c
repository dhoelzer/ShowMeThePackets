#include <stdio.h> 
#include <ctype.h>
#include <unistd.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <signal.h>
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#define MAX 5000 
#define SA struct sockaddr 

void sig_urg(int sig)
{
    signal (SIGURG, SIG_DFL);
    printf("Signal fired\n");
}

void print_hex(char *data, int bytes)
{
    int i;
    for(i = 0; i != bytes; i++)
    {
        if(i%16 == 0){
            if(i > 0) {
                printf(" ::");
                for(int j = i-16; j != i; j++){
                    printf(" %c", (isprint(data[j]) ? (data[j] == ' ' ? '.' : data[j]) : '.'));
                }
            }
            printf("\n0x%.4x:", i);
        }
        if(i%8 == 0) printf(" ");
        printf(" %.2x", (unsigned char)data[i]);
    }
    if((i % 16) != 0)
    {
        for(int j = (16 - (i % 16)) ; j != 0; j--) {
            printf("   ");
        }
        if((i % 16) < 8) printf(" ");
    }
    printf(" ::");
    for(int j = ((i % 16) == 0 ? bytes - 16 : bytes - (i % 16)); j != i; j++){
        printf(" %c", (isprint(data[j]) ? (data[j] == ' ' ? '.' : data[j]) : '.'));
    }
    printf("\n");
}

// Function designed for chat between client and server. 
void func(int sockfd) 
{ 
	char buff[MAX]; 
    int n = 0;
	// infinite loop for chat 
    bzero(buff, MAX); 
	while ((n = read(sockfd, buff, sizeof(buff))) ) { 


		// read the message from client and copy it in buffer 
		
		// print buffer which contains the client contents 
		print_hex(buff, n);
		bzero(buff, MAX); 
	} 
} 

// Driver function 
int main(int argc, char **argv) 
{ 
    int port, pid;
	unsigned int sockfd, connfd, len; 
	struct sockaddr_in servaddr, cli; 

    if(argc == 1) {
        port = 80;  /* Default */
    } else {
        port = atoi(argv[1]);
    }

    signal (SIGURG, sig_urg);
	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		exit(0); 
	} 
	bzero(&servaddr, sizeof(servaddr)); 

	// assign IP, PORT 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(port); 

	// Binding newly created socket to given IP and verification 
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
		printf("socket bind failed...\n"); 
		exit(0); 
	} 
	else
		printf("Listening on %d...\n", port); 

	// Now server is ready to listen and verification 
	if ((listen(sockfd, 5)) != 0) { 
		printf("Listen failed...\n"); 
		exit(0); 
	} 
	len = sizeof(cli); 

	// Accept the data packet from client and verification 
    while(1)
    {
        connfd = accept(sockfd, (SA*)&cli, &len); 
        if ((pid = fork()) == -1)
        {
            close(connfd);
            printf("Failed to accept new connection.\n");
        }
        else if(pid > 0)
        {
            close(connfd);
        }
        else if(pid == 0)
        {
            printf("New connection...\n"); 

            // Function for chatting between client and server 
            func(connfd); 
        }
    }
	// After chatting close the socket 
	close(sockfd); 
} 
