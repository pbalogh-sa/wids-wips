#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "main.h"

int
process_client(char *str, int first, int last, int num)
{
	int n;
	int i = 0;
	char *vars;
	
	if (first == -1)
		return 1;
	vars = malloc((last-first)*sizeof(char)+1);
	for (n = first; n < last; n++) {
		vars[i++] = str[n];
	}
	vars[i] = '\0';
	
	switch (num) {
	case 7:
		strcpy(bssid, vars);
#ifdef _DEBUG_PROCESS
		printf("%s ", bssid);
#endif
		break;
	case 8:
		strcpy(macaddr, vars);
#ifdef _DEBUG_PROCESS
		printf("%s ", macaddr);
#endif
		break;
	case 9:
		cltp = atoi(vars);
#ifdef _DEBUG_PROCESS
		printf("%d ", cltp);
#endif
		break;
	case 10:
		strcpy(channel, vars);
#ifdef _DEBUG_PROCESS
		printf("%s\n", channel);
#endif
		break;
	case 0:
		strcpy(sourceuid[db].name, vars);
#ifdef _DEBUG_PROCESS
		printf("NAME %s ", sourceuid[db].name);
#endif
		break;
	case 1:
		strcpy(sourceuid[db].uuid, vars);
#ifdef _DEBUG_PROCESS
		printf("UUID %s %d\n", sourceuid[db].uuid, db);
#endif
		break;
	default: printf("%s\n", vars);
	}

	free(vars);
	return 0;
}


int
process_src(char *str, int first, int last, int num)
{
	int n, chanint, known_src = 1;
	int i = 0;
	char *vars;
	char ap_chan[4];
	struct ap_struct *ap_tmp;

	if ((strcmp(bssid, macaddr) == 0)) {
		if ((chanint = atoi(channel)) != 0) {
#ifdef _DEBUG_PROCESS
			printf("ACCESS POINT %s %s\n", bssid, channel);
#endif
			if (search_in_list(bssid, NULL) == NULL) {
				add_to_list(bssid, chanint, 1);
			}
		}
//		print_list();
		return 0;
	}
	for (n = 0; n < acclines; n++) {
		if (strncmp(macaddr, accmac[n], strlen(macaddr)) == 0) {
#ifdef _DEBUG_PROCESS
			printf ("ENABLED MAC ------ %s\n", macaddr);
#endif
			return 0;
		}
	}
	
	if (first == -1)
		return 1;
	vars = malloc((last-first)*sizeof(char)+1);
	for (n = first; n < last; n++) {
		vars[i++] = str[n];
	}
	vars[i] = '\0';
	
	switch (num) {
	case 12:
		signal_db = atoi(vars);
#ifdef _DEBUG_PROCESS
		printf("%d ", signal_db);
#endif
		break;
	case 13:
		for (i = 0; i < 4; i++) {
			if (strcmp(vars, sourceuid[i].uuid) == 0) {
				if(ap_tmp = search_in_list(bssid, NULL)) {
#ifdef _DEBUG_ACT
					printf("%s %d (%d) %d %d %s %s\n", sourceuid[i].name, i, signal_db, ap_tmp->channel, cltp, macaddr, bssid);		
#endif
					mesarray[i].interface = i;
					mesarray[i].signal = signal_db;
					mesarray[i].channel = ap_tmp->channel;
					strcpy(mesarray[i].bssid, bssid);
					strcpy(mesarray[i].mac, macaddr);
					strcpy(mesarray[i].srcname, sourceuid[i].name);
					mesarray[i].cltp = cltp;
				} else {
#ifdef _DEBUG_ACT
					printf("JUST PROBE to a non seen AP %s %d (%d) %d %s %s\n", sourceuid[i].name, i, signal_db, cltp, macaddr, bssid);
#endif
					mesarray[i].interface = i;
					mesarray[i].signal = signal_db;
					strcpy(mesarray[i].bssid, bssid);
					strcpy(mesarray[i].mac, macaddr);
					strcpy(mesarray[i].srcname, sourceuid[i].name);
					mesarray[i].cltp = cltp;
				}
				known_src = 0;
			}
		}
#ifdef _DEBUG_ACT
		if (known_src) {
			if(ap_tmp = search_in_list(bssid, NULL))
				printf("unknown source (%d) %d %s %s %s %d\n", signal_db, ap_tmp->channel, cltp, macaddr, bssid);
			else
				printf("unknown source JUST PROBE to a non seen AP (%d) %s %s %s %s\n", signal_db, cltp, macaddr, bssid, vars);
		}
#endif
		break;
	default: printf("%s\n", vars);
	}
	if (new_cli) {
		deauth_thread(mesarray);
		memset(mesarray, 0, sizeof(mesarray));
	}
	new_cli = 0;

	free(vars);
	return 0;
}

