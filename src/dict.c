/* dict.c is Copyright (c) 2015 Chen Wei <weichen302@gmail.com>

   Use a dictionary like structure to store config options for fast lookup

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

#define OPEN_ADDRESSING_MAXJUMP 7                /* no reason, just like 7 */
#define OPEN_ADDRESSING_DEFAULT_SLOT 4
#define FNV1_32A_INIT ((uint32_t)0x811c9dc5)
#define FNV_32_PRIME  ((uint32_t)0x01000193)
#define max(A, B) ((A) > (B) ? (A) : (B))

static char buf[MAXDNAME];

/* prototypes */
static struct dict_node *lookup_dictnode (struct dict_node *node, char *label);
static void add_dicttree (struct dict_node *node, struct dict_node *sub);
static void upsize_dicttree (struct dict_node *np);

/* hash function 1 for double hashing
 * 32 bit Fowler/Noll/Vo hash */
static inline uint32_t fnv_32_hash (char *str)
{
  uint32_t hval = FNV1_32A_INIT;
  unsigned char *s = (unsigned char *) str;

  while (*s)
    {
      hval ^= (uint32_t) * s++;
      hval +=
        (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
    }

  return hval;
}

/* hash function 2 for double hashing
 * the modified Bernstein hash, return an odd number */
static inline unsigned int bernstein_odd (char *key)
{
  unsigned char *s = (unsigned char *) key;
  unsigned int h = 0;

  while (*s)
    h = 33 * h ^ *s++;

  return h % 2 ? h : h + 1;
}

/* convert domain to lower cases, remove leading blank, leading and trailing
 * dot, string end with \0 */
static inline void memcpy_lower (void *dst, void *src, int len)
{
  char *d = (char *) dst;
  char *s = (char *) src;
  int i;

  /* skip leading dot and blank */
  for ( ; *s != '\0' && (*s == '.' || *s == '\t' || *s == ' '); s++ );

  for (i = 0; i < len; i++, d++, s++)
    {
      if (*s >= 'A' && *s <= 'Z')
        *d = *s + 'a' - 'A';
      else
        *d = *s;
    }

  if (*--d == '.')
      *d = '\0';
  else
      *++d = '\0';
}

struct dict_node * init_sub_dictnode (struct dict_node *node)
{
  unsigned n;

  if (node->sub != NULL)
    return node;

  node->sub_slots = OPEN_ADDRESSING_DEFAULT_SLOT;
  node->sub_loadmax = node->sub_slots * 3 / 4;        // loading factor 0.75
  node->sub = safe_malloc (node->sub_slots * sizeof (struct dict_node *));
  for (n = 0; n < node->sub_slots; n++)
    node->sub[n] = NULL;

  return node;
}

/* allocate and initialize a new node */
struct dict_node * new_dictnode (char *label, int label_len)
{
  struct dict_node *node;

  node = safe_malloc (sizeof (struct dict_node));
  if (node == NULL)
    return NULL;

  if (label == NULL || label_len == 0)
    {
      node->h1 = 0;
      node->h2 = 0;
      node->label = NULL;
    }
  else
    {
      node->label = strdup (label);
      node->h1 = fnv_32_hash (label);
      node->h2 = bernstein_odd (label);
    }

  node->sub_count = 0;
  node->sub_slots = 0;
  node->sub_loadmax = 0;
  node->sub_maxjump = 0;
  node->sub = NULL;
  node->obj = NULL;

  return node;
}

/* double the slots of dns node, it calls with add_dicttree each other
 * the table size starts with 2^2, so that the new size remains 2^x, the
 * double hash used is choosed to work with 2^n slots and perform well */
static void upsize_dicttree (struct dict_node *np)
{
  struct dict_node **oldnodes;
  unsigned i, oldsize;

  oldsize = np->sub_slots;
  oldnodes = np->sub;
  np->sub_slots = oldsize * 2;
  np->sub_loadmax = np->sub_slots * 3 / 4;
  np->sub_count = 0;
  np->sub_maxjump = 0;
  np->sub = safe_malloc (np->sub_slots * sizeof (struct dict_node *));
  for (i = 0; i < np->sub_slots; i++)
    np->sub[i] = NULL;

  for (i = 0; i < oldsize; i++)
    {
      if (oldnodes[i] != NULL)
        {
          add_dicttree (np, oldnodes[i]);
        }
    }

  free (oldnodes);
}

/* add a sub-node, upsize if needed, calls with upsize_dicttree each other */
static void add_dicttree (struct dict_node *node, struct dict_node *sub)
{
  int n;
  uint32_t dh, idx;

  if (node->sub == NULL)
    init_sub_dictnode (node);

  n = 0;
  dh = sub->h1;
  while (1)
    {
      idx = dh % node->sub_slots;
      if (node->sub[idx] == NULL)
        {
          node->sub[idx] = sub;
          node->sub_count += 1;
          break;
        }
      else
        {
          dh += sub->h2;
          n++;
        }
    }

  node->sub_maxjump = max (n, node->sub_maxjump);
  /* If it takes a lots of jumps to find an empty slot, or the used slots
   * close to loading max, upsize the table */
  if (node->sub_maxjump > OPEN_ADDRESSING_MAXJUMP ||
      node->sub_count > node->sub_loadmax)
    {
      upsize_dicttree (node);
    }

  return;
}

/* add a new subnode to node, or update the attr of the subnode with same
 * label
 * return the subnode */
struct dict_node *add_or_lookup_dictnode (struct dict_node *node, char *label)
{
  struct dict_node *np;

  if ((np = lookup_dictnode (node, label)) == NULL)
    {
      if (node->sub == NULL)
        {
          init_sub_dictnode (node);
        }
      np = new_dictnode (label, strlen (label));
      add_dicttree (node, np);
    }

  return np;
}

/* lookup the label in node's sub, return pointer if found, NULL if not */
static struct dict_node *lookup_dictnode (struct dict_node *node, char *label)
{
  uint32_t h1, h2, dh, idx;
  struct dict_node *np;

  /* this domain doesn't have sub-domains */
  if (node->sub == NULL)
    {
      return NULL;
    }

  dh = h1 = fnv_32_hash (label);
  h2 = bernstein_odd (label);
  idx = dh % node->sub_slots;
  while ((np = node->sub[idx]) != NULL)
    {
      if (np->h1 == h1 && np->h2 == h2)
        if (strcmp (np->label, label) == 0)
          {
            return np;
          }

      dh += h2;
      idx = dh % node->sub_slots;
    }

  return NULL;
}

/* look up the whole domain pattern by step over DNS name hierarchy top down.
 * for example, if the pattern is cn.debian.org, the lookup will start with
 * org, then debian, then cn */
struct dict_node * match_domain(struct dict_node *root, char *domain)
{
  char *labels[MAXLABELS];
  int i, label_num;
  int len = strlen (domain);
  struct dict_node *node, *res;

  if (root == NULL)
      return NULL;

  memset(buf, 0, sizeof(buf));
  memcpy_lower (buf, domain, len);
  /*
  remove the trailing dot, make the last label top domain
  if (buf[len - 1] == '.')
    buf[len - 1] = '\0';
  else
    buf[len] = '\0';
  */

  for (i = 0; i < MAXLABELS; i++)
    labels[i] = NULL;

  label_num = 0;
  labels[label_num++] = &buf[0];

  /* split domain name into labels */
  for (i = 0; buf[i] != '\0'; i++)
    {
      if (buf[i] == '.')
        {
          buf[i] = '\0';
          labels[label_num++] = &buf[i + 1];
        }
    }

  node = root;
  res = NULL;
  for (i = label_num - 1; i >= 0; i--)
    {
      node = lookup_dictnode (node, labels[i]);

      /* match longest pattern, e.g. for pattern debian.org and cn.debian.org,
       * domain name ftp.cn.debian.org will match pattern cn.debian.org */
      if (node == NULL)
          break;

      if (node->obj != NULL)
          res = node;
    }

  if (res == NULL)
    return NULL;

  return res;
}

/* look up the whole domain pattern by step over DNS name hierarchy top down.
 * for example, if the pattern is cn.debian.org, the lookup will start with
 * org, then debian, then cn */
struct dict_node * lookup_domain (struct dict_node *root, char *domain)
{
  char *labels[MAXLABELS];
  int i, label_num;
  int len = strlen (domain);
  struct dict_node *node;

  memset(buf, 0, sizeof(buf));
  memcpy_lower (buf, domain, len);

  for (i = 0; i < MAXLABELS; i++)
    labels[i] = NULL;

  label_num = 0;

  labels[label_num++] = &buf[0];

  for (i = 0; buf[i] != '\0'; i++)
    {
      if (buf[i] == '.')
        {
          buf[i] = '\0';
          labels[label_num++] = &buf[i + 1];
        }
    }

  node = root;
  for (i = label_num - 1; i >= 0 && node != NULL; i--)
    {
      node = lookup_dictnode (node, labels[i]);
    }

  return i == -1 ? node : NULL;
}

/* add a domain pattern in the form of debian.org to root
 * return the node with lowest hierarchy */
struct dict_node *add_or_lookup_domain (struct dict_node *root, char *domain)
{
  char *labels[MAXLABELS];
  int i, label_num;
  int len = strlen (domain);
  struct dict_node *node;

  memset(buf, 0, sizeof(buf));
  memcpy_lower (buf, domain, len);

  for (i = 0; i < MAXLABELS; i++)
    labels[i] = NULL;

  label_num = 0;
  labels[label_num++] = &buf[0];

  for (i = 0; buf[i] != '\0'; i++)
    {
      if (buf[i] == '.')
        {
          buf[i] = '\0';
          labels[label_num++] = &buf[i + 1];
        }
    }

  node = root;
  for (i = label_num - 1; i >= 0; i--)
    {
      node = add_or_lookup_dictnode (node, labels[i]);
    }

  return node;
}

/* free node and all sub-nodes recursively. Unused. */
void free_dicttree (struct dict_node *node)
{
  struct dict_node *np;
  unsigned i;

  if (node->sub_count > 0)
    {
      for (i = 0; i < node->sub_slots; i++)
        {
          np = node->sub[i];
          if (np != NULL)
            {
              if (np->label != NULL)
                free (np->label);

              if (np->obj != NULL)
                free (np->obj);

              free_dicttree (np);
            }
        }
      free (node->sub);
    }

  free (node);
}

/* only compare addr, source_addr, interface, and flags */
static inline int is_same_server(struct server *s1, struct server *s2)
{
    if (memcmp(&s1->addr, &s2->addr, sizeof(union mysockaddr)) != 0)
        return 0;

    if (strncmp(s1->interface, s2->interface, IF_NAMESIZE + 1) != 0)
        return 0;

    if (s1->flags != s2->flags)
        return 0;

    return 1;
}

/* duplicate a struct server, but only copy addr, source_addr, interfaces, and
 * flags
 * return the allocated pointer */
static inline struct server *serverdup(struct server *src)
{
    struct server *dst;

    dst = safe_malloc(sizeof(struct server));
    memcpy(dst, src, sizeof(struct server));

    return dst;
}

/* lookup server by compare addr, source_addr, interface, and flags with
 * servers in daemon->servers link list. If no match found, then insert a new
 * server
 *
 * Return the lookup result or the newly created server*/
struct server *lookup_or_install_new_server(struct server *serv)
{
    struct server *res;

    res = NULL;
    for (res = daemon->servers; res != NULL; res = res->next) {
        if (is_same_server(res, serv))
            break;
    }

    if (res == NULL) {
        res = serverdup(serv);
        res->next = daemon->servers;
        daemon->servers = res;
    }

    return res;
}

/* print the daemon->dh_special_domains tree recursively
 *
 * do we really need it?  */
void print_server_special_domains (struct dict_node *node,
                                   char *parents[], int current_level)
{
  struct dict_node *np;
  struct special_domain *obj;
  char buf[MAXDNAME];
  char ip_buf[16];
  int j, level;
  int port = 0;
  uint32_t i;

  level = current_level + 1;
  if (node->label != NULL)
    {
      parents[level] = node->label;
      if (node->obj != NULL)
        {
          obj = (struct special_domain *) node->obj;
          if (obj->domain_flags & SERV_HAS_DOMAIN)
            {
              memset (buf, 0, MAXDNAME);
              for (j = level; j > 1; j--)
                {
                  strcat (buf, parents[j]);
                  strcat (buf, ".");
                }
              buf[strlen (buf) - 1] = '\0';
              port = prettyprint_addr (&obj->server->addr, ip_buf);
              my_syslog(LOG_INFO, _("using nameserver %s#%d for domain %s"), 
                                    ip_buf, port, buf);
            }
        }
    }

  if (node->sub_count > 0)
    {
      for (i = 0; i < node->sub_slots; i++)
        if ((np = node->sub[i]) != NULL)
          print_server_special_domains (np, parents, level);
    }
}
