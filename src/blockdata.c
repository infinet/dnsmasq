/* dnsmasq is Copyright (c) 2000-2014 Simon Kelley

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

#ifdef HAVE_DNSSEC

static struct blockdata *keyblock_free = NULL;
static unsigned int blockdata_count = 0, blockdata_hwm = 0;

void blockdata_report(void)
{
  my_syslog(LOG_INFO, _("DNSSEC memory in use %u, max %u"), 
	    blockdata_count * KEYBLOCK_LEN,  blockdata_hwm * KEYBLOCK_LEN);
} 

struct blockdata *blockdata_alloc(char *data, size_t len)
{
  struct blockdata *block, *ret = NULL;
  struct blockdata **prev = &ret;
  size_t blen;

  while (len > 0)
    {
      if (keyblock_free)
	{
	  block = keyblock_free;
	  keyblock_free = block->next;
	  blockdata_count++; 
	}
      else if ((block = whine_malloc(sizeof(struct blockdata))))
	{
	  blockdata_count++;
	  if (blockdata_hwm < blockdata_count)
	    blockdata_hwm = blockdata_count;
	}
	  
      if (!block)
	{
	  /* failed to alloc, free partial chain */
	  blockdata_free(ret);
	  return NULL;
	}
      
      blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
      memcpy(block->key, data, blen);
      data += blen;
      len -= blen;
      *prev = block;
      prev = &block->next;
      block->next = NULL;
    }
  
  return ret;
}

size_t blockdata_walk(struct blockdata **key, unsigned char **p, size_t cnt)
{
  if (*p == NULL)
    *p = (*key)->key;
  else if (*p == (*key)->key + KEYBLOCK_LEN)
    {
      *key = (*key)->next;
      if (*key == NULL)
        return 0;
      *p = (*key)->key;
    }

  return MIN(cnt, (size_t)((*key)->key + KEYBLOCK_LEN - (*p)));
}

void blockdata_free(struct blockdata *blocks)
{
  struct blockdata *tmp;

  if (blocks)
    {
      for (tmp = blocks; tmp->next; tmp = tmp->next)
	blockdata_count--;
      tmp->next = keyblock_free;
      keyblock_free = blocks; 
      blockdata_count--;
    }
}

/* copy blocks into data[], return 1 if data[] unchanged by so doing */
int blockdata_retrieve(struct blockdata *block, size_t len, void *data)
{
  size_t blen;
  struct  blockdata *b;
  int match = 1;
  
  for (b = block; len > 0 && b;  b = b->next)
    {
      blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
      if (memcmp(data, b->key, blen) != 0)
	match = 0;
      memcpy(data, b->key, blen);
      data += blen;
      len -= blen;
    }

  return match;
}
 
#endif
