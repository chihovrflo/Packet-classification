#include<stdlib.h>
#include<stdio.h>
#include<string.h>
////////////////////////////////////////////////////////////////////////////////////
struct ENTRY{
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned char src_len;
	unsigned char dst_len;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int nexthop;
	unsigned short protocol;
};
////////////////////////////////////////////////////////////////////////////////////
static __inline__ unsigned long long rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}
////////////////////////////////////////////////////////////////////////////////////
int num_chunk = 0, num_ruleleaf = 0, num_rulenode = 0, num_rulenodearray = 0;
struct rule_leaf{
	int rule_index;
	struct rule_leaf *down_link;
};
struct rule_leaf *create_rule_leaf(){
	struct rule_leaf *tmp = (struct rule_leaf *)malloc(sizeof(struct rule_leaf));
	num_ruleleaf++;
	tmp->down_link = NULL;
	tmp->rule_index = -1;
	return tmp;
}
struct rule_node{
	struct rule_node *node_link;
	struct rule_leaf *leaf_link;
};
struct rule_node *create_rule_node(){
	struct rule_node *tmp = (struct rule_node *)malloc(sizeof(struct rule_node));
	num_rulenode++;
	tmp->node_link = NULL;
	tmp->leaf_link = NULL;
	return tmp;
}
struct chunk{
	int eqid;
	struct rule_leaf *leaf_link;
};
struct rule_node_array{
	struct rule_leaf *leaf_link;
};
struct rule_node_array *array_p1_srcip_up = NULL, *array_p1_srcip_down = NULL, *array_p1_dstip_up = NULL, *array_p1_dstip_down = NULL, *array_p1_srcport = NULL, *array_p1_dstport = NULL, *array_p1_protocol = NULL;
struct rule_node_array *array_p2_srcip = NULL, *array_p2_dstip = NULL, *array_p2_port_protocol = NULL;
struct rule_node_array *array_p3 = NULL;
struct rule_node *p1_srcip_up = NULL, *p1_srcip_down = NULL, *p1_dstip_up = NULL, *p1_dstip_down = NULL, *p1_srcport = NULL, *p1_dstport = NULL, *p1_protocol = NULL;
struct rule_node *p2_srcip = NULL, *p2_dstip = NULL, *p2_port_protocol = NULL;
struct rule_node *p3_all = NULL;
int p1_srcip_up_eqid = 0, p1_srcip_down_eqid = 0, p1_dstip_up_eqid = 0, p1_dstip_down_eqid = 0, p1_srcport_eqid = 0, p1_dstport_eqid = 0, p1_protocol_eqid = 0;
int p2_srcip_eqid = 0, p2_dstip_eqid = 0, p2_port_protocol_eqid = 0;
int p3_eqid = 0;
struct chunk chunk_p1_srcip_up[65536], chunk_p1_srcip_down[65536], chunk_p1_dstip_up[65536], chunk_p1_dstip_down[65536], chunk_p1_srcport[65536], chunk_p1_dstport[65536], chunk_p1_protocol[256];
struct chunk *chunk_p2_srcip, *chunk_p2_dstip, *chunk_p2_port_protocol;
struct chunk *chunk_p3;
////////////////////////////////////////////////////////////////////////////////////
/*global variables*/
struct ENTRY *query;
struct ENTRY *table;
int num_entry=0;
int num_query=0;
int N=0;//number of nodes
unsigned long long int begin,end,total=0;
unsigned long long int *clock;
int num_node=0;//total number of nodes in the binary trie
int match_case = 0, loss_case = 0;
////////////////////////////////////////////////////////////////////////////////////
void read_table(char *str, struct ENTRY *node){
	int i;
	char tok[]="./\t:";
	char buf[100],*str1;
	unsigned int n[4];
	sprintf(buf,"%s\0",strtok(++str, tok));//指標右移跳過@
	//source ip
	n[0]=atoi(buf);
	for(i=1; i<4; i++){
        sprintf(buf, "%s", strtok(NULL, tok));
        n[i] = atoi(buf);
    }
	node->nexthop = n[2];
	str1=(char *)strtok(NULL,tok);
	sprintf(buf, "%s", str1);
	node->src_len = atoi(buf);
	node->src_ip = (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];
	//destination ip
	for(i=0; i<4; i++){
        sprintf(buf, "%s", strtok(NULL, tok));
        n[i] = atoi(buf);
    }
	node->dst_ip = (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];
    str1 = (char *)strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->dst_len = atoi(buf);
	//source port
	str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->src_port = atoi(buf) << 16;
	str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->dst_port += atoi(buf);
	//destination port
	str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->dst_port = atoi(buf) << 16;
    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->dst_port += atoi(buf);
	//protocol
	str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->protocol = strtoul(buf, NULL, 0) << 8;
    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->protocol += strtoul(buf, NULL, 0);
}
////////////////////////////////////////////////////////////////////////////////////
void set_table(char *file_name){
	FILE *fp;
	char string[200];
	fp=fopen(file_name,"r");
	while(fgets(string,200,fp)!=NULL){
		num_entry++;
	}
	rewind(fp);
	table=(struct ENTRY *)malloc(num_entry*sizeof(struct ENTRY ));
	num_entry=0;
	while(fgets(string,200,fp)!=NULL){
		read_table(string, &table[num_entry]);
		num_entry++;
	}
	fclose(fp);
}
////////////////////////////////////////////////////////////////////////////////////
void set_query(char *file_name){
	FILE *fp;
	char string[100];
	fp=fopen(file_name,"r");
	while(fgets(string,50,fp)!=NULL){
		num_query++;
	}
	rewind(fp);
	query=(struct ENTRY *)malloc(num_query*sizeof(struct ENTRY ));
	clock=(unsigned long long int *)malloc(num_query*sizeof(unsigned long long int));
	num_query=0;
	while(fgets(string,50,fp)!=NULL){
		read_table(string,&query[num_query]);
		clock[num_query++]=10000000;
	}
	fclose(fp);
}
////////////////////////////////////////////////////////////////////////////////////
void CountClock()
{
	unsigned int i;
	unsigned int* NumCntClock = (unsigned int* )malloc(50 * sizeof(unsigned int ));
	for(i = 0; i < 50; i++) NumCntClock[i] = 0;
	unsigned long long MinClock = 10000000, MaxClock = 0;
	for(i = 0; i < num_query; i++)
	{
		if(clock[i] > MaxClock) MaxClock = clock[i];
		if(clock[i] < MinClock) MinClock = clock[i];
		if(clock[i] / 100 < 50) NumCntClock[clock[i] / 100]++;
		else NumCntClock[49]++;
	}
	printf("(MaxClock, MinClock) = (%5llu, %5llu)\n", MaxClock, MinClock);
	return;
}
void shuffle(struct ENTRY *array, int n) {
    srand((unsigned)time(NULL));
    struct ENTRY *temp=(struct ENTRY *)malloc(sizeof(struct ENTRY));
    for (int i = 0; i < n - 1; i++) {
        size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
        temp->src_ip=array[j].src_ip;
		temp->dst_ip=array[j].dst_ip;
        temp->src_len=array[j].src_len;
		temp->dst_len=array[j].dst_len;
        temp->src_port=array[j].src_port;
		temp->dst_port=array[j].dst_port;
		temp->protocol=array[j].protocol;
        array[j].src_ip = array[i].src_ip;
		array[j].dst_ip = array[i].dst_ip;
        array[j].src_len = array[i].src_len;
		array[j].dst_len = array[i].dst_len;
        array[j].src_port = array[i].src_port;
		array[j].dst_port = array[i].dst_port;
		array[j].protocol = array[i].protocol;
        array[i].src_ip = temp->src_ip;
		array[i].dst_ip = temp->dst_ip;
        array[i].src_len = temp->src_len;
		array[i].dst_len = temp->dst_len;
        array[i].src_port = temp->src_port;
		array[i].dst_port = temp->dst_port;
		array[i].protocol = temp->protocol;
    }
	free(temp);
}
////////////////////////////////////////////////////////////////////////////////////
void free_leaf_link(struct rule_leaf *leaf_node){
	struct rule_leaf *tmp_free, *tmp = leaf_node;
	while(tmp != NULL){
		tmp_free = tmp;
		tmp = tmp->down_link;
		num_ruleleaf--;
		free(tmp_free);
	}
}
////////////////////////////////////////////////////////////////////////////////////
void create_RFC(){
	//create chunk of phase 1
	int i;
	int num_entry_size = num_entry/10*9;
	unsigned int input_srcip_up, input_srcip_down, input_dstip_up, input_dstip_down, input_srcport_s, input_srcport_e, input_dstport_s, input_dstport_e, input_protocol;
	//srcip_up
	for(i=0; i<num_entry_size; i++){
		input_srcip_up = table[i].src_ip >> 16;
		if(table[i].src_len < 16){
			unsigned int down = input_srcip_up >> (16 - table[i].src_len) << (16 - table[i].src_len);
			unsigned int up = input_srcip_up >> (16 - table[i].src_len);
			for(unsigned int j=0; j<(16 - table[i].src_len); j++){
				up = up << 1;
				up +=1;
			}
			for(int j=down; j<=up; j++){
				struct rule_leaf *tmp = create_rule_leaf();
				tmp->rule_index = i;
				tmp->down_link = chunk_p1_srcip_up[j].leaf_link;
				chunk_p1_srcip_up[j].leaf_link = tmp;
			}
		}
		else{
			struct rule_leaf *tmp = create_rule_leaf();
			tmp->rule_index = i;
			tmp->down_link = chunk_p1_srcip_up[input_srcip_up].leaf_link;
			chunk_p1_srcip_up[input_srcip_up].leaf_link = tmp;
		}
	}
	struct rule_leaf *tmp_leaf = NULL;
	for(i=0; i<65536; i++){
		struct rule_node *tmp_phase_node = p1_srcip_up;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p1_srcip_up[i].leaf_link == NULL){
			chunk_p1_srcip_up[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p1_srcip_up[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node -> leaf_link;

			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p1_srcip_up[i].eqid = quid_num;
				free_leaf_link(chunk_p1_srcip_up[i].leaf_link);
				chunk_p1_srcip_up[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p1_srcip_up;
			if(p1_srcip_up == NULL){
				p1_srcip_up = create_rule_node();
				tmp_phase_node = p1_srcip_up;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p1_srcip_up[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p1_srcip_up[i].eqid = quid_num;
		}
	}
	struct rule_node *count_eqid = p1_srcip_up;
	int num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p1_srcip_up_eqid = num_eqid;
	//srcip_down
	for(i=0; i<num_entry_size; i++){
		input_srcip_down = table[i].src_ip & 0xFFFF;
		if(table[i].src_len > 16){
			unsigned int down = input_srcip_down >> (32 - table[i].src_len) << (32 - table[i].src_len);
			unsigned int up = input_srcip_down >> (32 - table[i].src_len);
			for(unsigned int j=0; j<(32 - table[i].src_len); j++){
				up = up << 1;
				up +=1;
			}
			for(unsigned int j=down; j<=up; j++){
				struct rule_leaf *tmp = create_rule_leaf();
				tmp->rule_index = i;
				tmp->down_link = chunk_p1_srcip_down[j].leaf_link;
				chunk_p1_srcip_down[j].leaf_link = tmp;
			}
		}
		else{
			for(unsigned int j=0; j<65536; j++){
				struct rule_leaf *tmp = create_rule_leaf();
				tmp->rule_index = i;
				tmp->down_link = chunk_p1_srcip_down[j].leaf_link;
				chunk_p1_srcip_up[j].leaf_link = tmp;
			}
		}
	}
	tmp_leaf = NULL;
	for(i=0; i<65536; i++){
		struct rule_node *tmp_phase_node = p1_srcip_down;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p1_srcip_down[i].leaf_link == NULL){
			chunk_p1_srcip_down[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p1_srcip_down[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node -> leaf_link;

			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p1_srcip_down[i].eqid = quid_num;
				free_leaf_link(chunk_p1_srcip_down[i].leaf_link);
				chunk_p1_srcip_down[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p1_srcip_down;
			if(p1_srcip_down == NULL){
				p1_srcip_down = create_rule_node();
				tmp_phase_node = p1_srcip_down;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p1_srcip_down[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p1_srcip_down[i].eqid = quid_num;
		}
	}
	count_eqid = p1_srcip_down;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p1_srcip_down_eqid = num_eqid;
	//dstip_up
	for(i=0; i<num_entry_size; i++){
		input_dstip_up = table[i].dst_ip >> 16;
		if(table[i].dst_len < 16){
			unsigned int down = input_dstip_up >> (16 - table[i].dst_len) << (16 - table[i].dst_len);
			unsigned int up = input_dstip_up >> (16 - table[i].dst_len);
			for(unsigned int j=0; j<(16 - table[i].dst_len); j++){
				up = up << 1;
				up +=1;
			}
			for(int j=down; j<=up; j++){
				struct rule_leaf *tmp = create_rule_leaf();
				tmp->rule_index = i;
				tmp->down_link = chunk_p1_dstip_up[j].leaf_link;
				chunk_p1_dstip_up[j].leaf_link = tmp;
			}
		}
		else{
			struct rule_leaf *tmp = create_rule_leaf();
			tmp->rule_index = i;
			tmp->down_link = chunk_p1_dstip_up[input_dstip_up].leaf_link;
			chunk_p1_dstip_up[input_dstip_up].leaf_link = tmp;
		}
	}
	tmp_leaf = NULL;
	for(i=0; i<65536; i++){
		struct rule_node *tmp_phase_node = p1_dstip_up;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p1_dstip_up[i].leaf_link == NULL){
			chunk_p1_dstip_up[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p1_dstip_up[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node -> leaf_link;

			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p1_dstip_up[i].eqid = quid_num;
				free_leaf_link(chunk_p1_dstip_up[i].leaf_link);
				chunk_p1_dstip_up[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p1_dstip_up;
			if(p1_dstip_up == NULL){
				p1_dstip_up = create_rule_node();
				tmp_phase_node = p1_dstip_up;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p1_dstip_up[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p1_dstip_up[i].eqid = quid_num;
		}
	}
	count_eqid = p1_dstip_up;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p1_dstip_up_eqid = num_eqid;
	//dstip_down
	for(i=0; i<num_entry_size; i++){
		input_dstip_down = table[i].dst_ip & 0xFFFF;
		if(table[i].dst_len > 16){
			unsigned int down = input_dstip_down >> (32 - table[i].dst_len) << (32 - table[i].dst_len);
			unsigned int up = input_dstip_down >> (32 - table[i].dst_len);
			for(unsigned int j=0; j<(32 - table[i].dst_len); j++){
				up = up << 1;
				up +=1;
			}
			for(unsigned int j=down; j<=up; j++){
				struct rule_leaf *tmp = create_rule_leaf();
				tmp->rule_index = i;
				tmp->down_link = chunk_p1_dstip_down[j].leaf_link;
				chunk_p1_dstip_down[j].leaf_link = tmp;
			}
		}
		else{
			for(unsigned int j=0; j<65536; j++){
				struct rule_leaf *tmp = create_rule_leaf();
				tmp->rule_index = i;
				tmp->down_link = chunk_p1_dstip_down[j].leaf_link;
				chunk_p1_dstip_up[j].leaf_link = tmp;
			}
		}
	}
	tmp_leaf = NULL;
	for(i=0; i<65536; i++){
		struct rule_node *tmp_phase_node = p1_dstip_down;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p1_dstip_down[i].leaf_link == NULL){
			chunk_p1_dstip_down[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p1_dstip_down[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node -> leaf_link;

			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p1_dstip_down[i].eqid = quid_num;
				free_leaf_link(chunk_p1_dstip_down[i].leaf_link);
				chunk_p1_dstip_down[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p1_dstip_down;
			if(p1_dstip_down == NULL){
				p1_dstip_down = create_rule_node();
				tmp_phase_node = p1_dstip_down;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p1_dstip_down[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p1_dstip_down[i].eqid = quid_num;
		}
	}
	count_eqid = p1_dstip_down;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p1_dstip_down_eqid = num_eqid;
	//srcport
	for(i=0; i<num_entry_size; i++){
		input_srcport_s = table[i].src_port >> 16;
		input_srcport_e = table[i].src_port & 0xFFFF;

		for(unsigned int j=input_srcport_s; j<=input_srcport_e; j++){
			struct rule_leaf * tmp = create_rule_leaf();
			tmp->rule_index = i;
			tmp->down_link = chunk_p1_srcport[j].leaf_link;
			chunk_p1_srcport[j].leaf_link = tmp;
		}
	}
	tmp_leaf = NULL;
	for(i=0; i<65536; i++){
		struct rule_node *tmp_phase_node = p1_srcport;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p1_srcport[i].leaf_link == NULL){
			chunk_p1_srcport[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p1_srcport[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node->leaf_link;
			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p1_srcport[i].eqid = quid_num;
				free_leaf_link(chunk_p1_srcport[i].leaf_link);
				chunk_p1_srcport[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p1_srcport;
			if(p1_srcport == NULL){
				p1_srcport = create_rule_node();
				tmp_phase_node = p1_srcport;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p1_srcport[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p1_srcport[i].eqid = quid_num;
		}
	}
	count_eqid = p1_srcport;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p1_srcport_eqid = num_eqid;
	//dstport
	for(i=0; i<num_entry_size; i++){
		input_dstport_s = table[i].dst_port >> 16;
		input_dstport_e = table[i].dst_port & 0xFFFF;

		for(unsigned int j=input_dstport_s; j<=input_dstport_e; j++){
			struct rule_leaf * tmp = create_rule_leaf();
			tmp->rule_index = i;
			tmp->down_link = chunk_p1_dstport[j].leaf_link;
			chunk_p1_dstport[j].leaf_link = tmp;
		}
	}
	tmp_leaf = NULL;
	for(i=0; i<65536; i++){
		struct rule_node *tmp_phase_node = p1_dstport;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p1_dstport[i].leaf_link == NULL){
			chunk_p1_dstport[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p1_dstport[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node->leaf_link;
			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p1_dstport[i].eqid = quid_num;
				free_leaf_link(chunk_p1_dstport[i].leaf_link);
				chunk_p1_dstport[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p1_dstport;
			if(p1_dstport == NULL){
				p1_dstport = create_rule_node();
				tmp_phase_node = p1_dstport;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p1_dstport[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p1_dstport[i].eqid = quid_num;
		}
	}
	count_eqid = p1_dstport;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p1_dstport_eqid = num_eqid;
	//protocol
	for(i=0; i<num_entry_size; i++){
		input_protocol = table[i].protocol;
		struct rule_leaf *tmp = create_rule_leaf();
		tmp->rule_index = i;
		tmp->down_link = chunk_p1_protocol[input_protocol].leaf_link;
		chunk_p1_protocol[input_protocol].leaf_link = tmp;
	}
	tmp_leaf = NULL;
	for(i=0; i<256; i++){
		struct rule_node * tmp_phase_node = p1_protocol;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p1_protocol[i].leaf_link == NULL){
			chunk_p1_protocol[i].eqid = -1;
			continue;
		}

		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p1_protocol[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node->leaf_link;
			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p1_protocol[i].eqid = quid_num;
				free_leaf_link(chunk_p1_protocol[i].leaf_link);
				chunk_p1_protocol[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p1_protocol;
			if(p1_protocol == NULL){
				p1_protocol = create_rule_node();
				tmp_phase_node = p1_protocol;
			}
			else
			{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p1_protocol[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p1_protocol[i].eqid = quid_num;
		}
	}
	count_eqid = p1_protocol;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p1_protocol_eqid = num_eqid;
	
	array_p1_srcip_up = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p1_srcip_up_eqid);
	array_p1_srcip_down = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p1_srcip_down_eqid);
	array_p1_dstip_up = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p1_dstip_up_eqid);
	array_p1_dstip_down = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p1_dstip_down_eqid);
	array_p1_srcport = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p1_srcport_eqid);
	array_p1_dstport = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p1_dstport_eqid);
	array_p1_protocol = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p1_protocol_eqid);
	
	num_rulenodearray += (p1_srcip_up_eqid + p1_srcip_down_eqid + p1_dstip_up_eqid + p1_dstip_down_eqid + p1_srcport_eqid + p1_dstport_eqid + p1_protocol_eqid);
	//set array
	for(i=0; i<p1_srcip_up_eqid; i++){
		array_p1_srcip_up[i].leaf_link = p1_srcip_up->leaf_link;
		struct rule_node *tmp = p1_srcip_up;
		p1_srcip_up = p1_srcip_up->node_link;
		num_rulenode--;
		free(tmp);
	}
	for(i=0; i<p1_srcip_down_eqid; i++){
		array_p1_srcip_down[i].leaf_link = p1_srcip_down->leaf_link;
		struct rule_node *tmp = p1_srcip_down;
		p1_srcip_down = p1_srcip_down->node_link;
		num_rulenode--;
		free(tmp);
	}
	for(i=0; i<p1_dstip_up_eqid; i++){
		array_p1_dstip_up[i].leaf_link = p1_dstip_up->leaf_link;
		struct rule_node *tmp = p1_dstip_up;
		p1_dstip_up = p1_dstip_up->node_link;
		num_rulenode--;
		free(tmp);
	}
	for(i=0; i<p1_dstip_down_eqid; i++){
		array_p1_dstip_down[i].leaf_link = p1_dstip_down->leaf_link;
		struct rule_node *tmp = p1_dstip_down;
		p1_dstip_down = p1_dstip_down->node_link;
		num_rulenode--;
		free(tmp);
	}
	for(i=0; i<p1_srcport_eqid; i++){
		array_p1_srcport[i].leaf_link = p1_srcport -> leaf_link;
		struct rule_node *tmp = p1_srcport;
		p1_srcport = p1_srcport->node_link;
		num_rulenode--;
		free(tmp);
	}
	for(i=0; i<p1_dstport_eqid; i++){
		array_p1_dstport[i].leaf_link = p1_dstport -> leaf_link;
		struct rule_node *tmp = p1_dstport;
		p1_dstport = p1_dstport->node_link;
		num_rulenode--;
		free(tmp);
	}
	for(i=0; i<p1_protocol_eqid; i++){
		array_p1_protocol[i].leaf_link = p1_protocol -> leaf_link;
		struct rule_node *tmp = p1_protocol;
		p1_protocol = p1_protocol->node_link;
		num_rulenode--;
		free(tmp);
	}
	printf("phase1 over\n");
}
////////////////////////////////////////////////////////////////////////////////////
void create_RFC_p2(){
	int i, j;
	chunk_p2_srcip = (struct chunk *)malloc(sizeof(struct chunk) * p1_srcip_up_eqid * p1_srcip_down_eqid);
	chunk_p2_dstip = (struct chunk *)malloc(sizeof(struct chunk) * p1_dstip_up_eqid * p1_dstip_down_eqid);
	chunk_p2_port_protocol = (struct chunk *)malloc(sizeof(struct chunk) * p1_srcport_eqid * p1_dstport_eqid * p1_protocol_eqid);
	num_chunk += (p1_srcip_up_eqid * p1_srcip_down_eqid + p1_dstip_up_eqid * p1_dstip_down_eqid + p1_srcport_eqid * p1_dstport_eqid * p1_protocol_eqid);
	//initialize
	for(i=0; i<p1_srcip_up_eqid; i++){
		for(j=0; j<p1_srcip_down_eqid; j++){
			chunk_p2_srcip[i * p1_srcip_down_eqid + j].eqid = -1;
			chunk_p2_srcip[i * p1_srcip_down_eqid + j].leaf_link = NULL;
		}
	}
	for(i=0; i<p1_dstip_up_eqid; i++){
		for(j=0; j<p1_dstip_down_eqid; j++){
			chunk_p2_dstip[i * p1_dstip_down_eqid + j].eqid = -1;
			chunk_p2_dstip[i * p1_dstip_down_eqid + j].leaf_link = NULL;
		}
	}
	for(i=0; i<p1_srcport_eqid; i++){
		for(j=0; j<p1_dstport_eqid; j++){
			for(int k=0; k<p1_protocol_eqid; k++){
				chunk_p2_port_protocol[i * p1_dstport_eqid * p1_protocol_eqid + j * p1_protocol_eqid + k].eqid = -1;
				chunk_p2_port_protocol[i * p1_dstport_eqid * p1_protocol_eqid + j * p1_protocol_eqid + k].leaf_link = NULL;
			}
		}
	}
	//srcip
	for(i=0; i<p1_srcip_up_eqid; i++){
		for(j=0; j<p1_srcip_down_eqid; j++){
			struct rule_leaf *tmp_leaf_1 = array_p1_srcip_up[i].leaf_link;
			struct rule_leaf *tmp_leaf_2 = array_p1_srcip_down[j].leaf_link;

			while(tmp_leaf_1 != NULL && tmp_leaf_2 != NULL){
				if(tmp_leaf_1->rule_index == tmp_leaf_2->rule_index){
					struct rule_leaf *tmp = create_rule_leaf();
					tmp->rule_index = tmp_leaf_1->rule_index;
					tmp->down_link = chunk_p2_srcip[i * p1_srcip_down_eqid + j].leaf_link;
					chunk_p2_srcip[i * p1_srcip_down_eqid + j].leaf_link = tmp;
					tmp_leaf_1 = tmp_leaf_1->down_link;
					tmp_leaf_2 = tmp_leaf_2->down_link;
				}
				else if(tmp_leaf_1->rule_index > tmp_leaf_2->rule_index){
					tmp_leaf_1 = tmp_leaf_1->down_link;
				}
				else if(tmp_leaf_1->rule_index < tmp_leaf_2->rule_index){
					tmp_leaf_2 = tmp_leaf_2 -> down_link;
				}
			}
		}
	}
	struct rule_leaf *tmp_leaf = NULL;
	for(i=0; i<p1_srcip_up_eqid * p1_srcip_down_eqid; i++){
		struct rule_node *tmp_phase_node = p2_srcip;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p2_srcip[i].leaf_link == NULL){
			chunk_p2_srcip[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p2_srcip[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node->leaf_link;
			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p2_srcip[i].eqid = quid_num;
				free_leaf_link(chunk_p2_srcip[i].leaf_link);
				chunk_p2_srcip[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p2_srcip;
			if(p2_srcip == NULL){
				p2_srcip = create_rule_node();
				tmp_phase_node = p2_srcip;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p2_srcip[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p2_srcip[i].eqid = quid_num;
		}
	}
	struct rule_node *count_eqid = p2_srcip;
	int num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p2_srcip_eqid = num_eqid;
	//dstip
	for(i=0; i<p1_dstip_up_eqid; i++){
		for(j=0; j<p1_dstip_down_eqid; j++){
			struct rule_leaf *tmp_leaf_1 = array_p1_dstip_up[i].leaf_link;
			struct rule_leaf *tmp_leaf_2 = array_p1_dstip_down[j].leaf_link;

			while(tmp_leaf_1 != NULL && tmp_leaf_2 != NULL){
				if(tmp_leaf_1->rule_index == tmp_leaf_2->rule_index){
					struct rule_leaf *tmp = create_rule_leaf();
					tmp->rule_index = tmp_leaf_1->rule_index;
					tmp->down_link = chunk_p2_dstip[i * p1_dstip_down_eqid + j].leaf_link;
					chunk_p2_dstip[i * p1_dstip_down_eqid + j].leaf_link = tmp;
					tmp_leaf_1 = tmp_leaf_1->down_link;
					tmp_leaf_2 = tmp_leaf_2->down_link;
				}
				else if(tmp_leaf_1->rule_index > tmp_leaf_2->rule_index){
					tmp_leaf_1 = tmp_leaf_1->down_link;
				}
				else if(tmp_leaf_1->rule_index < tmp_leaf_2->rule_index){
					tmp_leaf_2 = tmp_leaf_2 -> down_link;
				}
			}
		}
	}
	tmp_leaf = NULL;
	for(i=0; i<p1_dstip_up_eqid * p1_dstip_down_eqid; i++){
		struct rule_node *tmp_phase_node = p2_dstip;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p2_dstip[i].leaf_link == NULL){
			chunk_p2_dstip[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p2_dstip[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node->leaf_link;
			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p2_dstip[i].eqid = quid_num;
				free_leaf_link(chunk_p2_dstip[i].leaf_link);
				chunk_p2_dstip[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p2_dstip;
			if(p2_dstip == NULL){
				p2_dstip = create_rule_node();
				tmp_phase_node = p2_dstip;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p2_dstip[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p2_dstip[i].eqid = quid_num;
		}
	}
	count_eqid = p2_dstip;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p2_dstip_eqid = num_eqid;
	//port&protocol
	for(i=0; i<p1_srcport_eqid; i++){
		for(j=0; j<p1_dstport_eqid; j++){
			for(int k=0; k<p1_protocol_eqid; k++){
				struct rule_leaf *tmp_leaf_1 = array_p1_srcport[i].leaf_link;
				struct rule_leaf *tmp_leaf_2 = array_p1_dstport[j].leaf_link;
				struct rule_leaf *tmp_leaf_3 = array_p1_protocol[k].leaf_link;

				while(tmp_leaf_1 != NULL && tmp_leaf_2 != NULL && tmp_leaf_3 != NULL){
					if(tmp_leaf_1->rule_index == tmp_leaf_2->rule_index && tmp_leaf_1->rule_index == tmp_leaf_3->rule_index ){
						struct rule_leaf *tmp = create_rule_leaf();
						tmp->rule_index = tmp_leaf_1->rule_index;
						tmp->down_link = chunk_p2_port_protocol[i * p1_dstport_eqid * p1_protocol_eqid + j * p1_protocol_eqid + k].leaf_link;
						chunk_p2_port_protocol[i * p1_dstport_eqid * p1_protocol_eqid + j * p1_protocol_eqid + k].leaf_link = tmp;
						tmp_leaf_1 = tmp_leaf_1->down_link;
						tmp_leaf_2 = tmp_leaf_2->down_link;
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else if(tmp_leaf_1->rule_index > tmp_leaf_2->rule_index && tmp_leaf_1->rule_index > tmp_leaf_3->rule_index){
						tmp_leaf_1 = tmp_leaf_1->down_link;
					}
					else if(tmp_leaf_2->rule_index > tmp_leaf_1->rule_index && tmp_leaf_2->rule_index > tmp_leaf_3->rule_index){
						tmp_leaf_2 = tmp_leaf_2->down_link;
					}
					else if(tmp_leaf_3->rule_index > tmp_leaf_1->rule_index && tmp_leaf_3->rule_index > tmp_leaf_2->rule_index){
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else if(tmp_leaf_1->rule_index == tmp_leaf_2->rule_index && tmp_leaf_1->rule_index > tmp_leaf_3->rule_index){
						tmp_leaf_1 = tmp_leaf_1->down_link;
						tmp_leaf_2 = tmp_leaf_2->down_link;
					}
					else if(tmp_leaf_1->rule_index == tmp_leaf_3->rule_index && tmp_leaf_1->rule_index > tmp_leaf_2->rule_index){
						tmp_leaf_1 = tmp_leaf_1->down_link;
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else if(tmp_leaf_2->rule_index == tmp_leaf_3->rule_index && tmp_leaf_2->rule_index > tmp_leaf_1->rule_index){
						tmp_leaf_2 = tmp_leaf_2->down_link;
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else{
						printf("phase2 error\n");
					}
				}
			}
		}
	}
	tmp_leaf = NULL;
	for(i=0; i<p1_srcport_eqid * p1_dstport_eqid * p1_protocol_eqid; i++){
		struct rule_node *tmp_phase_node = p2_port_protocol;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p2_port_protocol[i].leaf_link == NULL){
			chunk_p2_port_protocol[i].eqid = -1;
			//printf("i : %d, eqid : %d\n", i, chunk_port_type_phase2[i].eqid);
			continue;
		}

		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p2_port_protocol[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node->leaf_link;
	
			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p2_port_protocol[i].eqid = quid_num;
				free_leaf_link(chunk_p2_port_protocol[i].leaf_link);
				chunk_p2_port_protocol[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p2_port_protocol;
			if(p2_port_protocol == NULL){
				p2_port_protocol = create_rule_node();
				tmp_phase_node = p2_port_protocol;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p2_port_protocol[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p2_port_protocol[i].eqid = quid_num;
		}
	}
	count_eqid = p2_port_protocol;
	num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p2_port_protocol_eqid = num_eqid;

	array_p2_srcip = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p2_srcip_eqid);
	array_p2_dstip = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p2_dstip_eqid);
	array_p2_port_protocol = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p2_port_protocol_eqid);
	num_rulenodearray += (p2_srcip_eqid + p2_dstip_eqid + p2_port_protocol_eqid);
	//srcip
	for(i=0; i<p2_srcip_eqid; i++){
		array_p2_srcip[i].leaf_link = p2_srcip->leaf_link;
		struct rule_node *tmp = p2_srcip;
		p2_srcip = p2_srcip->node_link;
		num_rulenode--;
		free(tmp);
	}
	//dstip
	for(i=0; i<p2_dstip_eqid; i++){
		array_p2_dstip[i].leaf_link = p2_dstip->leaf_link;
		struct rule_node *tmp = p2_dstip;
		p2_dstip = p2_dstip->node_link;
		num_rulenode--;
		free(tmp);
	}
	//port&protocol
	for(i=0; i<p2_port_protocol_eqid; i++){
		array_p2_port_protocol[i].leaf_link = p2_port_protocol->leaf_link;
		struct rule_node *tmp = p2_port_protocol;
		p2_port_protocol = p2_port_protocol->node_link;
		num_rulenode--;
		free(tmp);
	}
	printf("phase2 over\n");
}
////////////////////////////////////////////////////////////////////////////////////
void create_RFC_p3(){
	int i, j;
	chunk_p3 = (struct chunk *)malloc(sizeof(struct chunk) * p2_srcip_eqid * p2_dstip_eqid * p2_port_protocol_eqid);
	num_chunk += (p2_srcip_eqid * p2_dstip_eqid * p2_port_protocol_eqid);
	for(i=0; i<p2_srcip_eqid; i++){
		for(j=0; j<p2_dstip_eqid; j++){
			for(int k=0; k<p2_port_protocol_eqid; k++){
				chunk_p3[i * p2_dstip_eqid * p2_port_protocol_eqid + j * p2_port_protocol_eqid + k].eqid = -1;
				chunk_p3[i * p2_dstip_eqid * p2_port_protocol_eqid + j * p2_port_protocol_eqid + k].leaf_link = NULL;
			}
		}
	}
	for(i=0; i<p2_srcip_eqid; i++){
		for(j=0; j<p2_dstip_eqid; j++){
			for(int k=0; k<p2_port_protocol_eqid; k++){
				struct rule_leaf *tmp_leaf_1 = array_p2_srcip[i].leaf_link;
				struct rule_leaf *tmp_leaf_2 = array_p2_dstip[j].leaf_link;
				struct rule_leaf *tmp_leaf_3 = array_p2_port_protocol[k].leaf_link;

				while(tmp_leaf_1 != NULL && tmp_leaf_2 != NULL && tmp_leaf_3 != NULL){
					if(tmp_leaf_1->rule_index == tmp_leaf_2->rule_index && tmp_leaf_1->rule_index == tmp_leaf_3->rule_index){
						struct rule_leaf *tmp = create_rule_leaf();
						tmp->rule_index = tmp_leaf_1->rule_index;
						tmp->down_link = chunk_p3[i * p2_dstip_eqid * p2_port_protocol_eqid + j * p2_port_protocol_eqid + k].leaf_link;
						chunk_p3[i * p2_dstip_eqid * p2_port_protocol_eqid + j * p2_port_protocol_eqid + k].leaf_link = tmp;
						tmp_leaf_1 = tmp_leaf_1->down_link;
						tmp_leaf_2 = tmp_leaf_2->down_link;
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else if(tmp_leaf_1->rule_index < tmp_leaf_2->rule_index && tmp_leaf_1->rule_index < tmp_leaf_3->rule_index){
						tmp_leaf_1 = tmp_leaf_1->down_link;
					}
					else if(tmp_leaf_2->rule_index < tmp_leaf_1->rule_index && tmp_leaf_2->rule_index < tmp_leaf_3->rule_index){
						tmp_leaf_2 = tmp_leaf_2->down_link;
					}
					else if(tmp_leaf_3->rule_index < tmp_leaf_1->rule_index && tmp_leaf_3->rule_index < tmp_leaf_2->rule_index){
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else if(tmp_leaf_1->rule_index == tmp_leaf_2->rule_index && tmp_leaf_1->rule_index < tmp_leaf_3->rule_index){
						tmp_leaf_1 = tmp_leaf_1->down_link;
						tmp_leaf_2 = tmp_leaf_2->down_link;
					}
					else if(tmp_leaf_1->rule_index == tmp_leaf_3->rule_index && tmp_leaf_1->rule_index < tmp_leaf_2->rule_index){
						tmp_leaf_1 = tmp_leaf_1->down_link;
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else if(tmp_leaf_2->rule_index == tmp_leaf_3->rule_index && tmp_leaf_2->rule_index < tmp_leaf_1->rule_index){
						tmp_leaf_2 = tmp_leaf_2->down_link;
						tmp_leaf_3 = tmp_leaf_3->down_link;
					}
					else{
						printf("error at phase3\n");
					}
				}
			}
		}
	}
	struct rule_leaf *tmp_leaf = NULL;
	for(i=0; i<p2_srcip_eqid * p2_dstip_eqid * p2_port_protocol_eqid; i++){
		struct rule_node *tmp_phase_node = p3_all;
		int quid_num = 0;
		int same_flag = 0;

		if(chunk_p3[i].leaf_link == NULL){
			chunk_p3[i].eqid = -1;
			continue;
		}
		while(tmp_phase_node != NULL){
			tmp_leaf = chunk_p3[i].leaf_link;
			struct rule_leaf *tmp = tmp_phase_node->leaf_link;
	
			while(tmp != NULL && tmp_leaf != NULL){
				if(tmp->rule_index == tmp_leaf->rule_index){
					tmp = tmp->down_link;
					tmp_leaf = tmp_leaf->down_link;
					same_flag = 1;
				}
				else{
					same_flag = 0;
					break;
				}
				if((tmp == NULL && tmp_leaf != NULL) || (tmp != NULL && tmp_leaf == NULL)){
					same_flag = 0;
					break;
				}
			}
			if(same_flag == 1){
				chunk_p3[i].eqid = quid_num;
				free_leaf_link(chunk_p3[i].leaf_link);
				chunk_p3[i].leaf_link = tmp_phase_node->leaf_link;
				break;
			}
			quid_num++;
			tmp_phase_node = tmp_phase_node->node_link;
		}
		if(same_flag == 0){
			tmp_phase_node = p3_all;
			if(p3_all == NULL){
				p3_all = create_rule_node();
				tmp_phase_node = p3_all;
			}
			else{
				while(tmp_phase_node->node_link != NULL){
					tmp_phase_node = tmp_phase_node->node_link;
				}
				tmp_phase_node->node_link = create_rule_node();
				tmp_phase_node = tmp_phase_node->node_link;
			}
			tmp_leaf = chunk_p3[i].leaf_link;
			tmp_phase_node->leaf_link = tmp_leaf;
			chunk_p3[i].eqid = quid_num;
		}
	}
	struct rule_node *count_eqid = p3_all;
	int num_eqid = 0;
	while(count_eqid != NULL){
		num_eqid++;
		count_eqid = count_eqid->node_link;
	}
	p3_eqid = num_eqid;

	array_p3 = (struct rule_node_array *)malloc(sizeof(struct rule_node_array) * p3_eqid);
	num_rulenodearray += p3_eqid;
	for(i=0; i<p3_eqid; i++){
		array_p3[i].leaf_link = p3_all->leaf_link;
		struct rule_node *tmp = p3_all;
		p3_all = p3_all->node_link;
		num_rulenode--;
		free(tmp);
	}
	printf("phase3 over\n");
}
////////////////////////////////////////////////////////////////////////////////////
void RFC_search(unsigned int input_srcip, unsigned int input_dstip, unsigned int input_srcport, unsigned int input_dstport, unsigned int input_protocol){
	unsigned int input_srcip_up, input_srcip_down, input_dstip_up, input_dstip_down;

	input_srcip_up = input_srcip >> 16;
	input_srcip_down = input_srcip & 0xFFFF;
	input_dstip_up = input_dstip >> 16;
	input_dstip_down = input_dstip & 0xFFFF;
	input_srcport = input_srcport >> 16;
	input_dstport = input_dstport >> 16;

	int search_srcup_eqid = chunk_p1_srcip_up[input_srcip_up].eqid;
	int search_srcdown_eqid = chunk_p1_srcip_down[input_srcip_down].eqid;
	int search_dstup_eqid = chunk_p1_dstip_up[input_dstip_up].eqid;
	int search_dstdown_eqid = chunk_p1_dstip_down[input_dstip_down].eqid;
	int search_srcport_eqid = chunk_p1_srcport[input_srcport].eqid;
	int search_dstport_eqid = chunk_p1_dstport[input_dstport].eqid;
	int search_protocol_eqid = chunk_p1_protocol[input_protocol].eqid;

	if(search_srcup_eqid == -1 || search_srcdown_eqid == -1 || search_dstup_eqid == -1 || search_dstdown_eqid == -1 || search_srcport_eqid == -1 || search_dstport_eqid == -1 || search_protocol_eqid == -1){
		loss_case++;
		return;
		printf("-1 occur at phase1\n");
		printf("search: s_up_eqid : %d, s_down_eqid : %d, d_up_eqid : %d, d_down_eqid : %d, port_s eqid : %d,  port_d eqid : %d,  protocol eqid : %d\n", search_srcup_eqid, search_srcdown_eqid, search_dstup_eqid, search_dstdown_eqid, search_srcport_eqid, search_dstport_eqid, search_protocol_eqid);
	}
	int search_src_eqid = chunk_p2_srcip[search_srcup_eqid * p1_srcip_down_eqid + search_srcdown_eqid].eqid;
	int search_dst_eqid = chunk_p2_dstip[search_dstup_eqid * p1_dstip_down_eqid + search_dstdown_eqid].eqid;
	int search_port_protocol_eqid = chunk_p2_port_protocol[search_srcport_eqid * p1_dstport_eqid * p1_protocol_eqid + search_dstport_eqid * p1_protocol_eqid + search_protocol_eqid].eqid;

	if(search_src_eqid == -1 || search_dst_eqid == -1 || search_port_protocol_eqid == -1){
		loss_case++;
		return;
		printf("----------------------------------------------------------------------\n");
		printf("-1 occur at phase2\n");
		printf("search: s_eqid : %d, d_eqid : %d, port_protocol_eqid : %d\n", search_src_eqid, search_dst_eqid, search_port_protocol_eqid);
		printf("search: s_up_eqid : %d, s_down_eqid : %d, d_up_eqid : %d, d_down_eqid : %d, port_s eqid : %d,  port_d eqid : %d,  protocol eqid : %d\n", search_srcup_eqid, search_srcdown_eqid, search_dstup_eqid, search_dstdown_eqid, search_srcport_eqid, search_dstport_eqid, search_protocol_eqid);
		printf("ip s : %u, ip d : %u, port s : %u, port d : %u, protocol : %u\n", input_srcip, input_dstip, input_srcport, input_dstport, input_protocol);
	}

	int search_all = chunk_p3[search_src_eqid * p2_dstip_eqid * p2_port_protocol_eqid + search_dst_eqid * p2_port_protocol_eqid + search_port_protocol_eqid].eqid;

	if(search_all == -1){
		loss_case++;
		return;
		printf("----------------------------------------------------------------------\n");
	}
	if(array_p3[search_all].leaf_link != NULL)
		match_case++;
	else
		loss_case++;
}
////////////////////////////////////////////////////////////////////////////////////
int main(int argc,char *argv[]){
	/*if(argc!=3){
		printf("Please execute the file as the following way:\n");
		printf("%s  routing_table_file_name  query_table_file_name\n",argv[0]);
		exit(1);
	}*/
	int i,j;
	//set_query(argv[2]);
	//set_table(argv[1]);
	set_query(argv[1]);
	set_table(argv[1]);
	begin = rdtsc();
	create_RFC();
	create_RFC_p2();
	create_RFC_p3();
	end = rdtsc();
	printf("Avg. Insert: %llu\n", (end - begin) / num_entry);
	printf("Number of entry : %d\n", num_entry);
	printf("Total memory requirement: %d KB\n",((sizeof(struct chunk) * (65536 * 6 + 256 + num_chunk) + sizeof(struct rule_node) * num_rulenode + sizeof(struct rule_leaf) * num_ruleleaf + sizeof(struct rule_node_array) * num_rulenodearray)/1024));
	shuffle(query, num_query);
	////////////////////////////////////////////////////////////////////////////
	for(j=0;j<100;j++){
		for(i=0;i<num_query;i++){
			begin=rdtsc();
			RFC_search(query[i].src_ip, query[i].dst_ip, query[i].src_port, query[i].dst_port, query[i].protocol);
			end=rdtsc();
			if(clock[i]>(end-begin))
				clock[i]=(end-begin);
		}
	}
	total=0;
	for(j=0;j<num_query;j++)
		total+=clock[j];
	printf("Avg. Search: %llu\n",total/num_query);
	CountClock();
	printf("match : %d, loss : %d\n", match_case, loss_case);
	return 0;
}
