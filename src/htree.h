/* htree.h */

struct htree_node {
  char *label;              /* key */
  void *ptr;

  /* open addressing hash table uses double hashing */
  uint32_t h1;              /* from hash function 1 */
  uint32_t h2;              /* from hash function 2 */

  struct htree_node **sub;  /* the hash table */
  unsigned sub_size;        /* size of hash table */
  int sub_count;            /* items stored in hash table */
  int sub_loadmax;          /* max items stored before upsizing sub */
  int sub_maxprobe;         /* max probes for insertion, upsizing upon reach */
};

struct special_domain {
  struct server *server;
  union mysockaddr addr;
  int domain_flags;
};

struct ipsets_names {
  char **sets;          /* ipsets names end with NULL ptr */
  int   count;
};

/* htree.c */
#define MAXLABELS 128
struct htree_node *htree_new_node(char *label, int len);
struct htree_node *htree_find (struct htree_node *node, char *label);
struct htree_node *htree_find_or_add(struct htree_node *node, char *label);
struct htree_node *domain_match(struct htree_node *root, char *domain);
struct htree_node *domain_find_or_add(struct htree_node *root, char *domain);
struct server *lookup_or_install_new_server(struct server *serv);
void htree_free (struct htree_node *node);
void print_server_special_domains(struct htree_node *node, char *parents[],
                                  int current_level, int *count);
