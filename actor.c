#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>

#include "main.h"

int
deauth_thread(measure *mesarray)
{
	int i, dth;
	pid_t pid;
	char *deauth[6];
	char channel_str[4];
	measure selected;
	int disable_deauth = 1;
	char source[60];
	char timetxt[32];
	struct tm time_format;
	time_t timestamp;
	
	memset(&selected, 0, sizeof(measure));
	memset(&source, 0, sizeof(source));
	selected.signal = -105;

#ifdef _DEBUG_MEASURE
	printf("------------ MEASURE DEBUG BEGIN\n");
#endif
	for (i = 0; i < 4; i++) {
		if (mesarray[i].channel == 0) {
			continue;
		}
		if (selected.signal < mesarray[i].signal) {
			memcpy(&selected, &mesarray[i], sizeof(measure));
		}
#ifdef _DEBUG_MEASURE
		printf("int: %d ", mesarray[i].interface);
		printf("signal: %d ", mesarray[i].signal);
		printf("channel: %d ", mesarray[i].channel);
		printf("bssid: %s ", mesarray[i].bssid);
		printf("mac: %s ", mesarray[i].mac);
		printf("source: %s \n", mesarray[i].srcname);
#endif
	}
#ifdef _DEBUG_MEASURE
	printf("------------ MEASURE DEBUG END\n");
#endif

	if ((selected.channel == 0) || (selected.cltp == 0)) {
		memset(prev_mac, 0, sizeof(prev_mac));
		return 0;
	}
	if (strncmp(prev_mac, selected.mac, strlen(selected.mac)) == 0) {
		memset(prev_mac, 0, sizeof(prev_mac));
//		return 0;
	}
	for (i = 0; i < blacklines; i++) {
		if (strncmp(blackholes[i], selected.srcname, strlen(selected.srcname)) == 0)
			disable_deauth = 0;
	}
	if (disable_deauth)
		return 0;

	strcat(source, "root@");
	strcat(source, selected.srcname);
	strcpy(prev_mac, selected.mac);
	sprintf(channel_str, "%d", selected.channel);
	deauth[0] = strdup("ssh");
	deauth[1] = strdup(source);
	deauth[2] = strdup("deauth.sh");
	deauth[3] = strdup(channel_str);
	deauth[4] = strdup(selected.bssid);
	deauth[5] = strdup(selected.mac);
#ifdef _DEBUG_DEAUTH
	time(&timestamp);
	printf(asctime_r(localtime_r(&timestamp, &time_format), timetxt));
#endif
	if (fork() == 0) {
		pid = fork();
		if (pid == 0) {
			execlp(deauth[0], deauth[0], deauth[1], deauth[2], deauth[3], deauth[4], deauth[5], "&", NULL);
#ifdef _DEBUG_DEAUTH
			for (i = 0; i < 6; i++) {
				printf("%s ", deauth[i]);
			}
			printf("\n");
			printf("CHILD: my pid = %d\n", getpid());
			printf("CHILD: my parent's pid = %d\n",getppid());
#endif
		} else {
			deauth_pid = pid;
#ifdef _DEBUG_DEAUTH
			printf("PARENT: my pid = %d\n", getpid());
			printf("PARENT: my child's pid = %d\n", pid);
#endif
		}
		exit(EXIT_SUCCESS);
	} else if (pid == -1) {
		fprintf(stderr, "Fork failed\n");
		fprintf(stderr, "%s: File: %s Function: %s\n", strerror(errno), __FILE__, __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	wait(NULL);
	
	return 0;
}
