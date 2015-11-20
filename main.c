/*
 * main.c
 * Copyright (C) 2014 <p.balogh.sa@gmail.com>
 * 
 * wids-wips is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * uniband-monitor is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <regex.h>

#include "main.h"

int
main(int argc, char *argv[])
{
	int sockfd = 0, n = 0;
	char recvBuff[4096];
	struct sockaddr_in serv_addr;
	regex_t bssid_reg, bssidsrc_reg, cli_reg, clisrc_reg, source_reg;
	char *access_filename, *blackhole_filename;
	FILE *acclist, *blackfile;
	int i, j;
	
	acclines = 0;
	blacklines = 0;
	
	if (argc != 2) {
		printf("\n Usage: %s <ip of server> \n", argv[0]);
		return 1;
	}

	access_filename = (char *)malloc(64 * sizeof(char));
	strcpy(access_filename, "/usr/local/etc/access.conf");
	acclist = fopen(access_filename, "r");
	if (acclist == NULL) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}
	memset(&accmac, '0', sizeof(accmac));
	while ((fgets(accmac[acclines], MAC_SIZE, acclist)) != NULL) {
		acclines++;
	}
	fclose(acclist);

	blackhole_filename = (char *)malloc(64 * sizeof(char));
	strcpy(blackhole_filename, "/usr/local/etc/blackhole.conf");
	blackfile = fopen(blackhole_filename, "r");
	if (blackfile == NULL) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}
	memset(&blackholes, 0, sizeof(blackholes));
	while ((fgets(blackholes[blacklines], 18, blackfile)) != NULL) {
		blacklines++;
	}
	fclose(blackfile);

	if (regcomp(&source_reg, SOURCE_REGEX, REG_EXTENDED) != 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	if (regcomp(&bssid_reg, BSSID_REGEX, REG_EXTENDED) != 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	if (regcomp(&bssidsrc_reg, BSSIDSRC_REGEX, REG_EXTENDED) != 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	if (regcomp(&cli_reg, CLI_REGEX, REG_EXTENDED) != 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	if (regcomp(&clisrc_reg, CLISRC_REGEX, REG_EXTENDED) != 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	memset(recvBuff, '0', sizeof(recvBuff));
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(2501);

	if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof (serv_addr))
	    < 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
		return 1;
	}

	if (configure_kismet_server(sockfd, source_reg) == 1) {
		return 1;
	}
	while ((n = read(sockfd, recvBuff, sizeof(recvBuff) - 1)) > 0) {
		recvBuff[n] = 0;
#ifdef _DEBUG_RAW
		fprintf(stderr, "<------ DEBUG RAW STREAMS BEGIN \n");
		if (fputs(recvBuff, stderr) == EOF) {
			fprintf(stderr, "%s: File: %s Function: %s\n",
				strerror(errno), __FILE__, __FUNCTION__);
		}
		fprintf(stderr, "<------ DEBUG RAW STREAMS END \n");
#endif
#ifdef _DEBUG_PARSER
			printf("============================= DEBUG PARSER ==============================\n");
#endif		
		if (parse_srv_message(recvBuff, sizeof(recvBuff), bssid_reg, bssidsrc_reg, cli_reg, clisrc_reg) == 1) {
			return 1;
		}
	}
	if (n < 0) {
		fprintf(stderr, "%s: File: %s Function: %s\n",
			strerror(errno), __FILE__, __FUNCTION__);
	}

	return 0;
}
