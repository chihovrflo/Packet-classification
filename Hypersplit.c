#include<stdlib.h>
#include<stdio.h>
#include<string.h>
////////////////////////////////////////////////////////////////////////////////////
struct ENTRY{
	unsigned int src_ip_s;
	unsigned int src_ip_e;
	unsigned int dst_ip_s;
	unsigned int dst_ip_e;
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
struct list{//structure of binary trie
	unsigned int port;
	unsigned int num;
	struct list *left,*right;
};
struct split_node{//structure of hypersplit
    int dim;
    unsigned int endpt;
    void **child;
    int *num_child;
};
struct entryIndex {
    int index;
    struct entryIndex *next;
};
////////////////////////////////////////////////////////////////////////////////////
/*global variables*/
struct ENTRY *query;
int num_entry=0;
int num_query=0;
struct ENTRY *table;
int N=0;//number of nodes
unsigned long long int begin,end,total=0;
unsigned long long int *clock;
int num_node=0;//total number of nodes in the binary trie
int num_snode = 1;//total number of split_node
struct split_node *root;
#define BINTH 100
////////////////////////////////////////////////////////////////////////////////////
void read_table(char *str, struct ENTRY *node){
	int i, len;
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
	len = atoi(buf);
	node->src_ip_s = (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];
	node->src_ip_e = node->src_ip_s + ((1 << (32 - len)) - 1);
	//destination ip
	for(i=0; i<4; i++){
        sprintf(buf, "%s", strtok(NULL, tok));
        n[i] = atoi(buf);
    }
    str1 = (char *)strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    len = atoi(buf);
	node->dst_ip_s = (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];
	node->dst_ip_e = node->dst_ip_s + ((1 << (32 - len)) - 1);
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
int search(struct ENTRY *node){
	int index;
    struct split_node *current = root;
    struct entryIndex *tmp;
    int flag = 0;
    while(current != NULL){
        switch(current->dim){
        case (1):
            index = node->src_ip_s > current->endpt;
            break;
        case (2):
            index = node->dst_ip_s > current->endpt;
            break;
        case (3):
            index = node->src_port > current->endpt;
            break;
        case (4):
            index = node->dst_port > current->endpt;
            break;
        case (5):
            index = node->protocol > current->endpt;
            break;
        }
        if (current->child[index] == NULL) {
            // Not Found
            return 0;
        } else if (current->num_child[index] == 0) {
            // next splitnode
            current = (struct split_node *) current->child[index];
        } else {
            flag = 1;
            break;
        }
    }
    if(flag){
        for(tmp = (struct ENTRY_INDEX *) (current->child[index]); tmp; tmp = tmp->next){
            if (node->src_ip_s >= table[tmp->index].src_ip_s &&
                node->src_ip_s <= table[tmp->index].src_ip_e &&
                node->dst_ip_s >= table[tmp->index].dst_ip_s &&
                node->dst_ip_s <= table[tmp->index].dst_ip_e &&
                node->src_port >= (table[tmp->index].src_port >> 16) &&
                node->src_port <= (table[tmp->index].src_port & 0xFFFF) &&
                node->dst_port >= (table[tmp->index].dst_port >> 16) &&
                node->dst_port <= (table[tmp->index].dst_port & 0xFFFF) &&
                node->protocol == table[tmp->index].protocol)
                return 1;
        }
        return 0;
    }
    return 0;
	/*if(temp==NULL)
	  printf("default\n");
	  else
	  printf("%u\n",temp->port);*/
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
int cmp(const void *a, const void *b)
{
    int c = *(int *)a;
    int d = *(int *)b;
    return c - d;
}
////////////////////////////////////////////////////////////////////////////////////
unsigned int *sort_endpoint(struct entryIndex *index, int num_entry, int dim, int *num_endpoint){
	int i;
	struct entryIndex *current = index;
	unsigned int *new_table;
	new_table = (unsigned int *)malloc(sizeof(unsigned int) * num_entry * 2);
	if(dim == 1){
		for(i=0; i<num_entry*2; i+=2){
            new_table[i] = table[current->index].src_ip_s;
            new_table[i+1] = table[current->index].src_ip_e;
            current = current->next;
        }
	}
	if(dim == 2){
		for(i=0; i<num_entry*2; i+=2){
            new_table[i] = table[current->index].dst_ip_s;
            new_table[i+1] = table[current->index].dst_ip_e;
            current = current->next;
        }
	}
	if(dim == 3){
		for(i=0; i<num_entry*2; i+=2){
            new_table[i] = table[current->index].src_port >> 16;
            new_table[i+1] = table[current->index].src_port & 0xFFFF;
            current = current->next;
        }
	}
	if(dim == 4){
		for(i=0; i<num_entry*2; i+=2){
            new_table[i] = table[current->index].dst_port >> 16;
            new_table[i+1] = table[current->index].dst_port & 0xFFFF;
            current = current->next;
        }
	}
	if(dim == 5){
		for(i=0; i<num_entry; i++){
            new_table[i] = table[current->index].protocol;
            current = current->next;
        }
	}
	if (dim < 5)
        qsort(new_table, num_entry * 2, sizeof(unsigned int), cmp);
    else
        qsort(new_table, num_entry, sizeof(unsigned int), cmp);
	//filter distinct pattern
	int j = 0;
    unsigned int *distinct_table;
    distinct_table = (unsigned int *) malloc(sizeof(unsigned int) * (num_entry));
    distinct_table[0] = new_table[0];
    *num_endpoint = 1;
    for(i=1; i<num_entry; i++){
        if(new_table[i] != new_table[i-1]){
            distinct_table[j++] = new_table[i];
            *num_endpoint += 1;
        }
    }
    distinct_table = (unsigned int *)realloc(distinct_table, sizeof(unsigned int) * (*num_endpoint));
    free(new_table);
    return distinct_table;
}
////////////////////////////////////////////////////////////////////////////////////
int cal_sr(int dim, int num_ep, struct entryIndex *node_index, unsigned int *distinct_table, unsigned int *sr){
	int i;
	unsigned int sum = 0;
	struct entryIndex *current = node_index;
	if(dim == 1){
		for(i=0; i<num_ep-1; i++){
            sr[i] = 0;
            for(current = node_index; current; current = current->next){
                if(!((table[current->index].src_ip_s < distinct_table[i]) &&
                      (table[current->index].src_ip_e < distinct_table[i])) ||
                    !((table[current->index].src_ip_s >
                       distinct_table[i+1]) &&
                      (table[current->index].src_ip_e > distinct_table[i+1]))) {
                    sr[i]++;
                }
            }
            sum += sr[i];
        }
	}
	if(dim == 2){
		for(i=0; i<num_ep-1; i++){
            sr[i] = 0;
            for(current = node_index; current; current = current->next){
                if(!((table[current->index].dst_ip_s < distinct_table[i]) &&
                      (table[current->index].dst_ip_e < distinct_table[i])) ||
                    !((table[current->index].dst_ip_s >
                       distinct_table[i+1]) &&
                      (table[current->index].dst_ip_e > distinct_table[i+1]))) {
                    sr[i]++;
                }
            }
            sum += sr[i];
        }
	}
	if(dim == 3){
		for(i=0; i<num_ep-1; i++){
            sr[i] = 0;
            for(current = node_index; current; current = current->next){
                if(!(((table[current->index].src_port >> 16) <
                       distinct_table[i]) &&
                      ((table[current->index].src_port & 0xFFFF) <
                       distinct_table[i])) ||
                    !(((table[current->index].src_port >> 16) >
                       distinct_table[i + 1]) &&
                      ((table[current->index].src_port & 0xFFFF) >
                       distinct_table[i + 1]))) {
                    sr[i]++;
                }
            }
            sum += sr[i];
        }
	}
	if(dim == 4){
		for(i=0; i<num_ep-1; i++){
            sr[i] = 0;
            for(current = node_index; current; current = current->next){
                if(!(((table[current->index].dst_port >> 16) <
                       distinct_table[i]) &&
                      ((table[current->index].dst_port & 0xFFFF) <
                       distinct_table[i])) ||
                    !(((table[current->index].dst_port >> 16) >
                       distinct_table[i + 1]) &&
                      ((table[current->index].dst_port & 0xFFFF) >
                       distinct_table[i + 1]))) {
                    sr[i]++;
                }
            }
            sum += sr[i];
        }
	}
	if(dim == 5){
		for(i=0; i<num_ep; i++){
            sr[i] = 0;
            for(current = node_index; current; current = current->next){
                if(table[current->index].protocol == distinct_table[i]) {
                    sr[i]++;
                }
            }
            sum += sr[i];
        }
	}
	return sum;
}
////////////////////////////////////////////////////////////////////////////////////
//Heuristic 3
int pick_endpoint(int dim, int num_ep, unsigned int *distinct_table, int num_entry, struct entryIndex *node_index){
	int i;
	unsigned int *sr;
	sr = (unsigned int *)malloc(sizeof(unsigned int) * num_ep);
	unsigned int sum_sr = cal_sr(dim, num_ep, node_index, distinct_table, sr);
	unsigned int tmp = 0;
	for(i=0; i<num_ep; i++){
		tmp += sr[i];
		if(tmp > sum_sr/2)
			return distinct_table[i];
	}
	printf("No appropriate endpoint !");
}	
////////////////////////////////////////////////////////////////////////////////////
void choose(struct entryIndex *node_rule, int num_entry, int *dimension, unsigned int *endpoint){
	//choose the dimension to split
	unsigned int *(endpoints[5]);
	int num_endpoint[5];
	int i;
	for(i=0; i<5; i++){
		endpoints[i] = sort_endpoint(node_rule, num_entry, i+1, &num_endpoint[i]);
	}
	//計算entropy，(1/M)sum(∑Sr[j]) 最小者
	double entropy[5];
    unsigned int *sr;
    double min_entropy = 999999;
    for(i=0; i<5; i++){
        sr = (unsigned int *) malloc(sizeof(unsigned int) * num_endpoint[i]);
        entropy[i] = cal_sr(i+1, num_endpoint[i], node_rule, endpoints[i], sr) / (double)num_endpoint[i];
        if (entropy[i] < min_entropy && entropy[i] != 0) {
            min_entropy = entropy[i];
            *dimension = i + 1;
        }
        free(sr);
    }
	*endpoint = pick_endpoint(*dimension, num_endpoint[(*dimension)-1], endpoints[(*dimension)-1], num_entry, node_rule);
}
////////////////////////////////////////////////////////////////////////////////////
void classify(struct entryIndex *node, struct split_node *snode){
	unsigned int index = 0;
	int i;
	int copy_time = 1;
	if(snode->dim == 1){
		index = (table[node->index].src_ip_s <= snode->endpt) ? 0 : 1;
        copy_time = (table[node->index].src_ip_e > snode->endpt && index == 0) ? 2 : 1;
	}
	if(snode->dim == 2){
		index = (table[node->index].dst_ip_s <= snode->endpt) ? 0 : 1;
        copy_time = (table[node->index].dst_ip_e > snode->endpt && index == 0) ? 2 : 1;
	}
	if(snode->dim == 3){
		index = ((table[node->index].src_port >> 16) <= snode->endpt) ? 0 : 1;
        copy_time = ((table[node->index].src_port & 0xFFFF) > snode->endpt && index == 0) ? 2 : 1;
	}
	if(snode->dim == 4){
		index = ((table[node->index].dst_port >> 16) <= snode->endpt) ? 0 : 1;
        copy_time = ((table[node->index].dst_port & 0xFFFF) > snode->endpt && index == 0) ? 2 : 1;
	}
	if(snode->dim == 5){
		index = (table[node->index].protocol <= snode->endpt) ? 0 : 1;
	}
	for(i=0; i<copy_time; i++){
        struct entryIndex *new_node;
        new_node = (struct entryIndex *)malloc(sizeof(struct entryIndex));
        new_node->index = node->index;
        new_node->next = (struct entryIndex *) snode->child[index + i];
        snode->child[index + i] = new_node;
        snode->num_child[index + i] += 1;
        num_node++;
    }
}
////////////////////////////////////////////////////////////////////////////////////
void *split(struct entryIndex *node, int num_entry){
	struct entryIndex *entryptr, *tmp;
	struct split_node *new_split;
	unsigned int i;
	new_split = (struct split_node *)malloc(sizeof(struct split_node));

	if(root == NULL){//first split
		struct entryIndex *new_node;
		new_node = (struct entryIndex *)malloc(sizeof(struct entryIndex));
		new_node->index = 0;
		entryptr = new_node;
		tmp = new_node;
		new_node = NULL;
		for(i=1; i<(unsigned int)num_entry; i++){
			new_node = (struct entryIndex *)malloc(sizeof(struct entryIndex));
			new_node->index = i;
			tmp->next = new_node;
			tmp = new_node;
			new_node = NULL;
		}
		root = new_split;
	}
	else
		entryptr = node;
	//choose the dimension and the endpoint to split
	choose(entryptr, num_entry, &(new_split->dim), &(new_split->endpt));
	new_split->child = (void **)malloc(sizeof(struct entryIndex *) * 2);
	new_split->num_child = (int *)malloc(sizeof(int) * 2);
	for(i=0; i<2; i++){
		new_split->child[i] = NULL;
		new_split->num_child[i] = 0;
	}
	while(entryptr != NULL){
		tmp = entryptr;
		classify(entryptr, new_split);
		entryptr = entryptr->next;
		free(tmp);
	}
	for(i=0; i<2; i++){
		if(new_split->num_child[i] > BINTH && new_split->num_child[i] < num_entry){
			new_split->child[i] = (void *)split((struct ENTRY_INDEX *) new_split->child[i],new_split->num_child[i]);
			new_split->num_child[i] = 0;
            num_snode++;
		}
		else if (new_split->num_child[i] > BINTH && new_split->num_child[i] >= num_entry){
            printf("could not split rules: %d, dim: %d, endpt: %u\n",new_split->num_child[i], new_split->dim, new_split->endpt);
        }
	}
	return new_split;
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

/*void shuffle(struct ENTRY *array, int n) {
    srand((unsigned)time(NULL));
    struct ENTRY *temp=(struct ENTRY *)malloc(sizeof(struct ENTRY ));
    for (int i = 0; i < n - 1; i++) {
        size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
        temp->ip=array[j].ip;
        temp->len=array[j].len;
        temp->port=array[j].port;
        array[j].ip = array[i].ip;
        array[j].len = array[i].len;
        array[j].port = array[i].port;
        array[i].ip = temp->ip;
        array[i].len = temp->len;
        array[i].port = temp->port;
    }
}*/
void free_splitnode(struct split_node *node){
	if(node == NULL){
        return;
    }
    struct entryIndex *tmp, *freenode;
    unsigned int i;
    for(i=0; i<2; i++){
        if(node->num_child[i] == 0){
            free_splitnode((struct split_node *) node->child[i]);
        } else if (node->child[i]) {
            tmp = (struct entryIndex *) (node->child[i]);
            while (tmp) {
                freenode = tmp;
                tmp = tmp->next;
                freenode->next = NULL;
                free(freenode);
            }
        }
    }
    free(node->child);
    free(node->num_child);
    free(node);
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
	/*for(i=0; i<num_entry; i++){
		printf("src_ip: %x dst_ip: %x src_port: %d dst_port: %d protocol: %x \n",table[i].src_ip,table[i].dst_ip,table[i].src_port,table[i].dst_port,table[i].protocol);
	}*/
	begin = rdtsc();
    split(NULL, num_entry);
    end = rdtsc();
    printf("Avg. Insert: %llu\n", (end - begin) / num_entry);
	////////////////////////////////////////////////////////////////////////////
	for(j=0;j<100;j++){
		for(i=0;i<num_query;i++){
			begin=rdtsc();
			search(&query[i]);
			end=rdtsc();
			if(clock[i]>(end-begin))
				clock[i]=(end-begin);
		}
	}
	total=0;
	for(j=0;j<num_query;j++)
		total+=clock[j];
	printf("Avg. Search: %llu\n", total / num_query);
    printf("number of nodes: %d\n", num_node);
    printf("Total memory requirement: %ld KB\n",((num_node * sizeof(struct entryIndex) + num_snode * sizeof(struct split_node)) /1024));
	CountClock();
	////////////////////////////////////////////////////////////////////////////
	//count_node(root);
	//printf("There are %d nodes in binary trie\n",N);
	free_splitnode(root);
	free(query);
    free(table);
    free(clock);
	return 0;
}
