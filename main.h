#ifndef _MAIN_H
#define _MAIN_H

#include <regex.h>

//#define _DEBUG_RAW
//#define _DEBUG_PARSER
//#define _DEBUG_PROCESS
//#define _DEBUG_APLIST
//#define _DEBUG_ACT
#define _DEBUG_MEASURE
#define _DEBUG_DEAUTH


#define MAC_SIZE 19
#define SOURCE_REGEX "(\\*SOURCE:)[ ]+([a-z0-9.]+)[ ]+([0-9a-f]{8}-[0-90-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
#define BSSID_REGEX "(\\*BSSID:)[ ]+([0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2})[ ]+([0-9]+)"
#define BSSIDSRC_REGEX "(\\*BSSIDSRC:)[ ]+(-[0-9]{2})[ ]+([0-9a-f]{8}-[0-90-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
#define CLI_REGEX "(\\*CLIENT:)[ ]+([0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2})[ ]+([0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2}[:][0-9A-F]{2})[ ]+([0-9])[ ]+([0-9]+)"
#define CLISRC_REGEX "(\\*CLISRC:)[ ]+(-[0-9]{2})[ ]+([0-9a-f]{8}-[0-90-f]{4}-[0-9a-f]{4}-[0-9Aa-f]{4}-[0-9a-f]{12})"

int acclines;
char accmac[40][18];
char blackholes[4][18];
int blacklines;
char macaddr[19];
char prev_mac[19];
char bssid[18];
int cltp;
char channel[4];
int signal_db;
int db, new_cli, probeonly;
pid_t deauth_pid;

typedef struct {
	char name[18];
	char uuid[37];
} mes_source;

mes_source sourceuid[4];

typedef struct {
	char srcname[18];
	char bssid[18];
	char mac[18];
	int channel;
	int signal;
	int interface;
	int cltp;
}measure;

measure mesarray[4];

struct ap_struct {
	char bssid[18];
	int channel;
	struct ap_struct *next;
};

int send_parameters(int sockfd, char *text);
int configure_kismet_server(int sockfd, regex_t source_reg);
int read_sources(int sockfd, regex_t source_reg);
int print_vars(char *str, int first, int last, int num);
int parse_source(char *recvBuff, size_t recvSize, regex_t source_reg);
int parse_srv_message(char *recvBuff, size_t recvSize, regex_t bssid_reg, regex_t bssidsrc_reg, regex_t cli_reg, regex_t clisrc_reg);
int process_client(char *str, int first, int last, int num);
int process_src(char *str, int first, int last, int num);

struct ap_struct* add_to_list(char *bssid, int channel, int add_to_end);
struct ap_struct* create_list(char *bssid, int channel);
struct ap_struct* search_in_list(char *bssid, struct ap_struct **prev);
int delete_from_list(char *bssid);
void print_list(void);
int deauth_thread(measure *mesarray);

#endif
