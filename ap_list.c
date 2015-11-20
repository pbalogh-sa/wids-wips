#include<stdio.h>
#include<stdlib.h>

#include "main.h"

struct ap_struct *head = NULL;
struct ap_struct *curr = NULL;

struct ap_struct*
create_list(char *bssid, int channel)
{
#ifdef _DEBUG_APLIST
    printf("\n creating list as [%s]\n", bssid);
#endif
    struct ap_struct *ptr = (struct test_struct *) malloc(sizeof(struct ap_struct));
    if (NULL == ptr) {
		printf("\n creation failed \n");
	return NULL;
    }
	strcpy(ptr->bssid, bssid);
    ptr->channel = channel;
    ptr->next = NULL;

    head = curr = ptr;
    return ptr;
}

struct ap_struct*
add_to_list(char *bssid, int channel, int add_to_end)
{
    if (NULL == head) {
	return (create_list(bssid, channel));
    }
#ifdef _DEBUG_APLIST
    if (add_to_end)
	printf("\n Adding bssid to end of list with value [%s] [%d]\n", bssid, channel);
    else
		printf("\n Adding bssid to beginning of list with value [%s] [%d]\n",
	     bssid, channel);
#endif

    struct ap_struct *ptr =
	(struct test_struct *) malloc(sizeof(struct ap_struct));
    if (NULL == ptr) {
		printf("\n ad_to_list failed \n");
		return NULL;
    }
    strcpy(ptr->bssid, bssid);
    ptr->channel = channel;
    ptr->next = NULL;

    if (add_to_end) {
		curr->next = ptr;
		curr = ptr;
    } else {
		ptr->next = head;
		head = ptr;
    }
    return ptr;
}

struct ap_struct*
search_in_list(char *bssid, struct ap_struct **prev)
{
    struct ap_struct *ptr = head;
    struct ap_struct *tmp = NULL;
    int found = 0;

#ifdef _DEBUG_APLIST
    printf("\n Searching the list for value [%s] \n", bssid);
#endif
    while (ptr != NULL) {
		if (strcmp(ptr->bssid, bssid) == 0) {
			found = 1;
#ifdef _DEBUG_APLIST
			printf("Found channel [%d]\n", ptr->channel);
#endif
			break;
		} else {
			tmp = ptr;
			ptr = ptr->next;
		}
    }

    if (1 == found) {
		if (prev)
			*prev = tmp;
		return ptr;
	} else {
		return NULL;
	}
}

int
delete_from_list(char *bssid)
{
    struct ap_struct *prev = NULL;
    struct ap_struct *del = NULL;

#ifdef _DEBUG_APLIST
    printf("\n Deleting value [%s] from list\n", bssid);
#endif
    del = search_in_list(bssid, &prev);
    if (del == NULL) {
		return -1;
    } else {
		if (prev != NULL)
			prev->next = del->next;
		if (del == curr) {
			curr = prev;
		} else if (del == head) {
			head = del->next;
		}
    }

    free(del);
    del = NULL;

    return 0;
}

void
print_list(void)
{
    struct ap_struct *ptr = head;

    printf("\n -------Printing list Start------- \n");
    while (ptr != NULL) {
		printf(" [%s] [%d]\n", ptr->bssid, ptr->channel);
		ptr = ptr->next;
    }
    printf(" -------Printing list End------- \n");

    return;
}
