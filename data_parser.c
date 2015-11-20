#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "main.h"

int
print_vars(char *str, int first, int last, int num)
{
	int n;
	int i = 0;
	char *vars;

	if (first == -1)
		return 1;
	vars = malloc((last-first)*sizeof(char)+1);
	for (n = first; n < last; n++)
		vars[i++] = str[n];
	vars[i] = '\0';
	if ((num == 2) && (atoi(vars) == 2)) {
		printf("2 ------------> NETWORK TYPE PROBE!\n");
	} else {
		printf("%s\n", vars);
	}
	free(vars);
	return 0;
}

int
parse_srv_message(char *recvBuff, size_t recvSize, regex_t bssid_reg, regex_t bssidsrc_reg, regex_t cli_reg, regex_t clisrc_reg)
{
	char *token;
	int i = 0;
	regmatch_t line_element[5];

	token = strtok(recvBuff, "\n");

	do {
		if (regexec(&bssid_reg, token, 5, line_element, 0) == 0) {
#ifdef _DEBUG_PARSER
			printf("---------------------------> ");
			print_vars(token, line_element[1].rm_so, line_element[1].rm_eo, 100);
			printf("MAC:\t");
			print_vars(token, line_element[2].rm_so, line_element[2].rm_eo, 2);
			printf("Type:\t");
			print_vars(token, line_element[3].rm_so, line_element[3].rm_eo, 3);
#endif
		} else if (regexec(&bssidsrc_reg, token, 5, line_element, 0) == 0) {
#ifdef _DEBUG_PARSER
			printf("---------------------------> ");
			print_vars(token, line_element[1].rm_so, line_element[1].rm_eo, 100);
			printf("Signal:\t");
			print_vars(token, line_element[2].rm_so, line_element[2].rm_eo, 4);
			printf("Card:\t");
			print_vars(token, line_element[3].rm_so, line_element[3].rm_eo, 5);
#endif
		} else if (regexec(&cli_reg, token, 7, line_element, 0) == 0) {
			process_client(token, line_element[2].rm_so, line_element[2].rm_eo, 7);
			process_client(token, line_element[3].rm_so, line_element[3].rm_eo, 8);
			process_client(token, line_element[4].rm_so, line_element[4].rm_eo, 9);
			process_client(token, line_element[5].rm_so, line_element[5].rm_eo, 10);
			new_cli = 1;
#ifdef _DEBUG_PARSER
			printf("---------------------------> ");
			print_vars(token, line_element[1].rm_so, line_element[1].rm_eo, 100);
			printf("BSSID:\t");
			print_vars(token, line_element[2].rm_so, line_element[2].rm_eo, 7);
			printf("MAC:\t");
			print_vars(token, line_element[3].rm_so, line_element[3].rm_eo, 8);
			printf("Type:\t");
			print_vars(token, line_element[4].rm_so, line_element[4].rm_eo, 9);
			printf("Channel:\t");
			print_vars(token, line_element[5].rm_so, line_element[5].rm_eo, 10);
#endif
		} else if (regexec(&clisrc_reg, token, 5, line_element, 0) == 0) {
			process_src(token, line_element[2].rm_so, line_element[2].rm_eo, 12);
			process_src(token, line_element[3].rm_so, line_element[3].rm_eo, 13);
#ifdef _DEBUG_PARSER
			printf("---------------------------> ");
			print_vars(token, line_element[1].rm_so, line_element[1].rm_eo, 100);
			printf("Signal:\t");
			print_vars(token, line_element[2].rm_so, line_element[2].rm_eo, 12);
			printf("Card:\t");
			print_vars(token, line_element[3].rm_so, line_element[3].rm_eo, 13);
#endif
		} else {
#ifdef _DEBUG_PARSER
			printf("%s\n", token);
#endif
		}
	} while ((token = strtok(NULL, "\n")) != NULL);
#ifdef _DEBUG_PARSER
	printf("\n");
#endif
	
	return 0;
}

int
parse_source(char *recvBuff, size_t recvSize, regex_t source_reg)
{
	char *token;
	int i = 0;
	regmatch_t line_element[5];
	
	token = strtok(recvBuff, "\n");
	db = 0;
	do {
		if (regexec(&source_reg, token, 5, line_element, 0) == 0) {
			process_client(token, line_element[2].rm_so, line_element[2].rm_eo, 0);
			process_client(token, line_element[3].rm_so, line_element[3].rm_eo, 1);
			db++;
#ifdef _DEBUG_PARSER
			printf("---------------------------> ");
			print_vars(token, line_element[1].rm_so, line_element[1].rm_eo, 100);
			printf("SRC Name:\t");
			print_vars(token, line_element[2].rm_so, line_element[2].rm_eo, 0);
			printf("UUID:\t");
			print_vars(token, line_element[3].rm_so, line_element[3].rm_eo, 1);
#endif
		} else {
#ifdef _DEBUG_PARSER
			printf("%s\n", token);
#endif
		}
	} while ((token = strtok(NULL, "\n")) != NULL);
#ifdef _DEBUG_PARSER
	printf("\n");
#endif
	
	return 0;
}
