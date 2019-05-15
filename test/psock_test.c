/**
 * @file psock_test.c
 * @brief Small test for testing the custom psock socket
 * @author Jeroen
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PF_PSOCK PF_NFC

const char *msg = "Hello World\n";
char buffer[255];
int main()
{
	int psock = socket( PF_PSOCK, SOCK_RAW, 0 );
	printf( "psock creation : %d\n" , psock );

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = 1;

	int cfd = connect( psock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	printf( "Connecting result : %d\n" , cfd );

	// Lets try and write something to the socket
	int res = write( psock, msg, strlen(msg ) );
	printf( "Msg written result : %d\n" , res );

	// Reading from socket
	int rres = read( psock, buffer, 255 );
	printf( "Reading from socket result : %d\n", rres );
	
}


