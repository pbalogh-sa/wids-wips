#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>

#include "main.h"

int
send_parameters(int sockfd, char *text)
{
	if (write(sockfd, text, strlen(text)) < 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}	
	return 0;
}

int
read_sources(int sockfd, regex_t source_reg)
{
	char recvBuff[4096];
	int n;
	
	memset(recvBuff, '0', sizeof(recvBuff));
	n = read(sockfd, recvBuff, sizeof(recvBuff) - 1);
	recvBuff[n] = 0;
	parse_source(recvBuff, sizeof(recvBuff), source_reg);

	printf("%s %s\n", sourceuid[0].name, sourceuid[0].uuid);
	printf("%s %s\n", sourceuid[1].name, sourceuid[1].uuid);
	printf("%s %s\n", sourceuid[2].name, sourceuid[2].uuid);
	printf("%s %s\n", sourceuid[3].name, sourceuid[3].uuid);
	return 0;
}

int
configure_kismet_server(int sockfd, regex_t source_reg)
{
	char text[1024];

	strcpy(text, "!1 capability source\n");
	send_parameters(sockfd,text);
	strcpy(text, "!1 enable source username,uuid\n");
	send_parameters(sockfd,text);
	read_sources(sockfd, source_reg);
	
	strcpy(text, "!3 enable client bssid,mac,type,channel\n");
	send_parameters(sockfd, text);
	strcpy(text, "!4 enable clisrc signal_dbm,uuid\n");
	send_parameters(sockfd, text);
	strcpy(text, "!5 enable bssid bssid,type\n");
	send_parameters(sockfd,text);
	strcpy(text, "!6 enable bssidsrc signal_dbm,uuid\n");
	send_parameters(sockfd,text);

	return 0;
}
