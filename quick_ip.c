/*
 * IP地址快速查询表的使用方法：
 * 1、需要以局域网地址为索引地址
 * 2、可以快速查找到每个本地IP地址的各个网络连接
 * 3、
 *
 * Yang Youyi, 2019.08.02
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>  
#include <arpa/inet.h>

#define WHITE_IP_LIST_LEN 512
#define ERROR_EMPTY_PARAMETER_POINTER 10
#define WHITE_IP_LIST  "/home/nac/white_ip.conf"

struct conn_t
{
	unsigned int remote_ip;
	unsigned short remote_port;
	unsigned int local_ip;
	unsigned short local_port;
};

struct conn_link_t
{
	struct conn_t *conn;
	unsigned short  node_type;
	struct conn_link_t *next, *pre;
	void **pdata;
};

static void *g_ip_path[256];


int ip2seg(unsigned int ip, unsigned short *byte_index1, 
		unsigned short *byte_index2,  unsigned short *byte_index3,
		unsigned short *byte_index4)
{

	if (ip == 0) 
	{
		return -1;
	}

	*byte_index4 = (ip >> 24) & 0xff;
	*byte_index3 = (ip >> 16) & 0xff;
	*byte_index2 = (ip  >> 8) & 0xff;
	*byte_index1 = ip & 0xff;

	return 0;
}

int init_iplist()
{
	memset(g_ip_path, 0, 256 * sizeof(int *));
	return 0;
}

int is_same_link(struct conn_t *src_conn, struct conn_t *dst_conn)
{
	int ret = -1;
	ret = memcmp(src_conn, dst_conn, sizeof(struct conn_t));

	if (ret == 0)
		return 1;

	return 0;
}

struct conn_link_t *new_link()
{
	struct conn_link_t *p;

	p = (struct conn_link_t *)malloc(sizeof(struct conn_link_t));
	if (!p)
		return NULL;

	p->next = NULL;
	p->pre = NULL;
	p->pdata = NULL;
	p->conn = NULL;

	return p;
}

int add_pack_data(struct conn_link_t *empty_node, 
		struct conn_t *conn, unsigned short type, void **add_pack)
{
	if (!empty_node)
		return -2;

	empty_node->pdata = *add_pack;
	empty_node->conn = (struct conn_t *) malloc(sizeof(struct conn_t));
	empty_node->conn->remote_ip = conn->remote_ip;
	empty_node->conn->remote_port = conn->remote_port;
	empty_node->conn->local_ip = conn->local_ip;
	empty_node->conn->local_port = conn->local_port;

	return 0;
}

int appe_pack_data(struct conn_link_t *link, struct conn_t *conn, 
		unsigned short type, void **add_pack)
{
	struct conn_link_t   *p = link, *newp;

	while (p->next != NULL)
	{
		if (p->conn) {
			if (p->conn->remote_ip == conn->remote_ip 
					&& p->conn->remote_port == conn->remote_port
					&& p->conn->local_ip == conn->local_ip 
					&& p->conn->local_port == conn->local_port)
				return -1;
		}
		p = p->next;
	}

	if (p->conn) 
	{
		if (p->conn->remote_ip == conn->remote_ip 
				&& p->conn->remote_port == conn->remote_port 
				&& p->conn->local_ip == conn->local_ip 
				&& p->conn->local_port == conn->local_port)
		{
			return -1;
		}
	}

	newp = (struct conn_link_t *) malloc(sizeof(struct conn_link_t));
	if (!newp)
		return -2;
	memset(newp, 0, sizeof(struct conn_link_t));
	newp->pdata = *add_pack;
	newp->conn = (struct conn_t *) malloc(sizeof(struct conn_t));
	newp->conn->remote_ip = conn->remote_ip;
	newp->conn->remote_port = conn->remote_port;
	newp->conn->local_ip = conn->local_ip;
	newp->conn->local_port = conn->local_port;

	newp->pre = p;
	newp->node_type = type;
	newp->next = NULL;
	p->next = newp;   //we append the node to link at last, so it avoid collision.

	return 0;
}

struct conn_link_t *find_conn(unsigned int ip, struct conn_t *conn)
{
	int coun = 0;
	unsigned short byte_index1,byte_index2,byte_index3,byte_index4;
	void **tmp_layer = NULL;
	struct conn_link_t *conn_link;

	if( ip2seg(ip, &byte_index1, &byte_index2, &byte_index3, &byte_index4) != 0)
	{
		return NULL;
	}

	tmp_layer = g_ip_path[byte_index1];
	if (tmp_layer != NULL) {
		tmp_layer = tmp_layer[byte_index2];
		if (tmp_layer != NULL) {
			tmp_layer = tmp_layer[byte_index3];
			if (tmp_layer != NULL) {
				conn_link = tmp_layer[byte_index4];
				if (conn_link != NULL)
				{
					while (conn_link != NULL)
					{
						if (is_same_link(conn_link->conn, conn))
							return conn_link;
					}
				}
			}
		}
	}

	return NULL;
}

int print_iptree()
{
	FILE *fh;
	int coun1, coun2, coun3, coun4;
	void **second_p, **third_p, **fourth_p;

	fh = fopen("./iptree.txt", "w");
	if (fh == NULL) 
		return -1;

	fprintf(fh,"\n Tree level first:\n");
	for (coun1 = 0; coun1 < 256; coun1++) 
	{
		if (g_ip_path[coun1] != 0)
		{
			fprintf(fh,"\n\t1st: %d", coun1);
			second_p = g_ip_path[coun1];
			for (coun2 = 0; coun2 < 256; coun2++) 
			{
				if (second_p[coun2] != 0) 
				{
					fprintf(fh,"\n\t\t2nd: %d", coun2);
					third_p = second_p[coun2];
					for (coun3 = 0; coun3 < 256; coun3++)
					{
						if (third_p[coun3] != 0) 
						{
							fprintf(fh,"\n\t\t\t3rd: %d", coun3);
							fourth_p = third_p[coun3];
							for (coun4 = 0; coun4 < 256; coun4++)
							{
								if (fourth_p[coun4] != 0)
								{
									struct conn_link_t *p = fourth_p[coun4];
									fprintf(fh,"\n\t\t\t\t4th: %d, ip_tree_link=%x\t\n", coun4, p);
									printf("\n\t\t\t\t4th: %d, ip_tree_link=%x\t\n", coun4, p);
									while(p != NULL) {
										struct in_addr raddr;
										struct in_addr laddr;
										raddr.s_addr = p->conn->remote_ip;
										printf("\n rip=%s,", inet_ntoa(raddr));
										laddr.s_addr = p->conn->local_ip;
										printf(" lip=%s \n", inet_ntoa(laddr));
										fprintf(fh, "\t rip=%s, rport=%d, lip=%s, lport=%d, ntype=%d\n",
												inet_ntoa(raddr),p->conn->remote_port,inet_ntoa(laddr),p->conn->local_port,
												p->node_type);
										p = p->next;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	fclose(fh);
	return 0;
}

/*
 *在加入一个新数据的时候需要确这个数据在ip矩阵中不存在，已经查找过了，没有。
 */
int add_pack(unsigned int ip, struct conn_t *conn, unsigned short type, void **add_pack)
{
	unsigned int *tmp_arp_pck;
	int ret = 0;

	unsigned short byte_index1, byte_index2, byte_index3, byte_index4;
	void **root_addr = NULL, **tmp_addr;

#if 0
	if (NULL == add_pack) {
		return ERROR_EMPTY_PARAMETER_POINTER;
	}
#endif

#define ERR_INTERNAL  1
	if( ip2seg(ip, &byte_index1, &byte_index2, &byte_index3, &byte_index4) != 0)
	{
		return ERR_INTERNAL;
	}

	// we add a lock for each new connection from here.

	//first, we process the byte 192 for IP address 192.168.2.8;
	if (g_ip_path[byte_index1] != NULL) {
		root_addr = (void **)g_ip_path[byte_index1];
		if (root_addr[byte_index2] != NULL) {
			root_addr = (void **)root_addr[byte_index2];
			if (root_addr[byte_index3] != NULL) {
				root_addr = (void **)root_addr[byte_index3];
				if (root_addr[byte_index4] != NULL) {
					appe_pack_data(root_addr[byte_index4], conn, type, add_pack);
				} else {
					//每个末端单元里保存的是一个链表的头。一个本地IP地址可能有N个网络连接。
					root_addr[byte_index4] = new_link(); 
					ret = add_pack_data(root_addr[byte_index4], conn, type, add_pack);
				}
			}else {
				void *tree_root;
				tmp_addr = root_addr[byte_index3] = malloc(sizeof(int *) * 256);
				tree_root = tmp_addr;
				if (tree_root == NULL) 
				{
					//unlock before return
					return -1;
				}
				memset(tmp_addr, 0, sizeof(int *) * 256);
				tmp_addr[byte_index4] = new_link();
				ret = add_pack_data(tmp_addr[byte_index4], conn, type, add_pack);
			}
		} else {  //g_ip_path[byte_index1])[byte_index2] == NULL
			void *tree_root;

			tmp_addr = root_addr[byte_index2] = malloc(sizeof(int *) * 256);
			tree_root = tmp_addr;
			if (tree_root == NULL)
			{
				//unlock before return
				return -1;
			}
			memset(tmp_addr, 0, sizeof(int *) * 256);

			tmp_addr[byte_index3] = malloc(sizeof(int *) * 256);
			if (tmp_addr[byte_index3] == NULL)
			{
				//unlock before return
				return -1;
			}
			memset(tmp_addr[byte_index3], 0, sizeof(int *) * 256);
			tmp_addr = tmp_addr[byte_index3];
			tmp_addr[byte_index4] = new_link();
			ret = add_pack_data(tmp_addr[byte_index4], conn, type, add_pack);
		}
	} else {
		root_addr = g_ip_path[byte_index1] = malloc(sizeof(int *) * 256);
		tmp_addr = root_addr;
		if (root_addr == NULL)
		{
			//unlock before return
			return -1;
		}

		memset((void *)root_addr, 0, sizeof(int *) * 256);
		tmp_addr[byte_index2] = malloc(sizeof(int *) * 256);
		tmp_addr = tmp_addr[byte_index2];
		if (tmp_addr == NULL)
		{
			//unlock before return
			return -1;
		}
		memset(tmp_addr, 0, sizeof(int *) * 256);
		tmp_addr[byte_index3] = malloc(sizeof(int *) * 256);
		memset(tmp_addr[byte_index3], 0, sizeof(int *) * 256);
		tmp_addr = tmp_addr[byte_index3];
		if (tmp_addr == NULL)
		{
			//unlock before return
			return -1;
		}
		tmp_addr[byte_index4] = new_link();
		ret = add_pack_data(tmp_addr[byte_index4], conn, type, add_pack);
	}

	return ret;
}

#if 1

struct a_t {
	char *src_ip;
	char *tgt_ip;
	unsigned short node_type;
};

struct a_t test_a[] = {
	{"192.168.20.2", "192.168.20.3", 20},
	{"192.168.20.2", "192.168.20.4", 20},
	{"192.168.20.2", "192.168.20.5", 0},
	{"192.168.20.2", "192.168.20.6", 20},
	{"192.168.20.2", "192.168.20.7", 0},
	{"192.168.20.2", "192.168.20.8", 20},
	{"192.168.20.2", "192.168.20.9", 20},
	{"192.168.20.2", "192.168.20.13", 0},
	{"192.168.20.2", "192.168.20.23", 20},
	{"192.168.20.2", "192.168.20.33", 20},
	{"192.168.20.3", "192.168.20.4", 0},
	{"192.168.20.4", "192.168.20.5", 0},
	{"192.168.20.5", "192.168.20.6", 20},
	{"192.168.20.6", "192.168.20.7", 20},
	{"192.168.20.7", "192.168.20.8", 0},
	{"192.168.20.8", "192.168.20.9", 20},
	{"192.168.20.9", "192.168.20.19", 20},
	{"192.168.20.13", "192.168.20.23", 20},
	{"192.168.20.23", "192.168.20.33", 20},
	{"192.168.20.33", "192.168.20.43", 20},
	{"192.168.20.46", "192.168.20.53", 20},
	{"192.168.20.62", "192.168.20.63", 20}
};

int main()
{
	unsigned int ips[10];
	unsigned short byte_index1, byte_index2, byte_index3, byte_index4;
	int coun;
	struct in_addr ips_1,ips_2;
	struct ip_reco_t *root_addr = NULL;
	void **tmp_layer;
	int ret;
	int index;
	unsigned int net;
	unsigned int ip;


	for (int idx = 0; idx < sizeof(test_a)/sizeof(struct a_t); idx++) 
	{
		struct conn_t conn;

		conn.remote_ip = inet_addr(test_a[idx].src_ip);
		conn.local_ip = inet_addr(test_a[idx].tgt_ip);
		conn.remote_port = 1;
		conn.local_port = 2;

		add_pack(conn.remote_ip, &conn, test_a[idx].node_type, ips);
	}

	print_iptree();

}

#endif 


