/* dnsmasq is Copyright (c) 2000 - 2003 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* Author's email: simon@thekelleys.org.uk */

#include "dnsmasq.h"

struct myoption {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

#define OPTSTRING "ZDNLERzowefnbvhdqr:m:p:c:l:s:i:t:u:g:a:x:S:C:A:T:H:Q:I:B:F:G:O:M:X:V:"

static struct myoption opts[] = { 
  {"version", 0, 0, 'v'},
  {"no-hosts", 0, 0, 'h'},
  {"no-poll", 0, 0, 'n'},
  {"help", 0, 0, 'w'},
  {"no-daemon", 0, 0, 'd'},
  {"log-queries", 0, 0, 'q'},
  {"user", 1, 0, 'u'},
  {"group", 1, 0, 'g'},
  {"resolv-file", 1, 0, 'r'},
  {"mx-host", 1, 0, 'm'},
  {"mx-target", 1, 0, 't'},
  {"cache-size", 1, 0, 'c'},
  {"port", 1, 0, 'p'},
  {"dhcp-leasefile", 1, 0, 'l'},
  {"dhcp-lease", 1, 0, 'l' },
  {"dhcp-host", 1, 0, 'G'},
  {"dhcp-range", 1, 0, 'F'},
  {"dhcp-option", 1, 0, 'O'},
  {"dhcp-boot", 1, 0, 'M'},
  {"domain", 1, 0, 's'},
  {"domain-suffix", 1, 0, 's'},
  {"interface", 1, 0, 'i'},
  {"listen-address", 1, 0, 'a'},
  {"bogus-priv", 0, 0, 'b'},
  {"bogus-nxdomain", 1, 0, 'B'},
  {"selfmx", 0, 0, 'e'},
  {"filterwin2k", 0, 0, 'f'},
  {"pid-file", 1, 0, 'x'},
  {"strict-order", 0, 0, 'o'},
  {"server", 1, 0, 'S'},
  {"local", 1, 0, 'S' },
  {"address", 1, 0, 'A' },
  {"conf-file", 1, 0, 'C'},
  {"no-resolv", 0, 0, 'R'},
  {"expand-hosts", 0, 0, 'E'},
  {"localmx", 0, 0, 'L'},
  {"local-ttl", 1, 0, 'T'},
  {"no-negcache", 0, 0, 'N'},
  {"addn-hosts", 1, 0, 'H'},
  {"query-port", 1, 0, 'Q'},
  {"except-interface", 1, 0, 'I'},
  {"domain-needed", 0, 0, 'D'},
  {"dhcp-lease-max", 1, 0, 'X' },
  {"bind-interfaces", 0, 0, 'z'},
  {"read-ethers", 0, 0, 'Z' },
  {"alias", 1, 0, 'V' },
  {0, 0, 0, 0}
};

struct optflags {
  char c;
  unsigned int flag; 
};

static struct optflags optmap[] = {
  { 'b', OPT_BOGUSPRIV },
  { 'f', OPT_FILTER },
  { 'q', OPT_LOG },
  { 'e', OPT_SELFMX },
  { 'h', OPT_NO_HOSTS },
  { 'n', OPT_NO_POLL },
  { 'd', OPT_DEBUG },
  { 'o', OPT_ORDER },
  { 'R', OPT_NO_RESOLV },
  { 'E', OPT_EXPAND },
  { 'L', OPT_LOCALMX },
  { 'N', OPT_NO_NEG },
  { 'D', OPT_NODOTS_LOCAL },
  { 'z', OPT_NOWILD },
  { 'Z', OPT_ETHERS },
  { 'v', 0},
  { 'w', 0},
  { 0, 0 }
};

static char *usage =
"Usage: dnsmasq [options]\n"
"\nValid options are :\n"
"-a, --listen-address=ipaddr         Specify local address(es) to listen on.\n"
"-A, --address=/domain/ipaddr        Return ipaddr for all hosts in specified domains.\n"
"-b, --bogus-priv                    Fake reverse lookups for RFC1918 private address ranges.\n"
"-B, --bogus-nxdomain=ipaddr         Treat ipaddr as NXDOMAIN (defeats Verisign wildcard).\n" 
"-c, --cache-size=cachesize          Specify the size of the cache in entries (defaults to %d).\n"
"-C, --conf-file=path                Specify configuration file (defaults to " CONFFILE ").\n"
"-d, --no-daemon                     Do NOT fork into the background: run in debug mode.\n"
"-D, --domain-needed                 Do NOT forward queries with no domain part.\n" 
"-e, --selfmx                        Return self-pointing MX records for local hosts.\n"
"-E, --expand-hosts                  Expand simple names in /etc/hosts with domain-suffix.\n"
"-f, --filterwin2k                   Don't forward spurious DNS requests from Windows hosts.\n"
"-F, --dhcp-range=ipaddr,ipaddr,time Enable DHCP in the range given with lease duration.\n"
"-g, --group=groupname               Change to this group after startup (defaults to " CHGRP ").\n"
"-G, --dhcp-host=<hostspec>          Set address or hostname for a specified machine.\n"
"-h, --no-hosts                      Do NOT load " HOSTSFILE " file.\n"
"-H, --addn-hosts=path               Specify a hosts file to be read in addition to " HOSTSFILE ".\n"
"-i, --interface=interface           Specify interface(s) to listen on.\n"
"-I, --except-interface=int          Specify interface(s) NOT to listen on.\n"
"-l, --dhcp-leasefile=path           Specify where to store DHCP leases (defaults to " LEASEFILE ").\n"
"-L, --localmx                       Return MX records for local hosts.\n"
"-m, --mx-host=host_name             Specify the MX name to reply to.\n"
"-M, --dhcp-boot=<bootp opts>        Specify BOOTP options to DHCP server.\n"
"-n, --no-poll                       Do NOT poll " RESOLVFILE " file, reload only on SIGHUP.\n"
"-N, --no-negcache                   Do NOT cache failed search results.\n"
"-o, --strict-order                  Use nameservers strictly in the order given in " RESOLVFILE ".\n"
"-O, --dhcp-option=<optspec>         Set extra options to be set to DHCP clients.\n"
"-p, --port=number                   Specify port to listen for DNS requests on (defaults to 53).\n"
"-q, --log-queries                   Log queries.\n"
"-Q, --query-port=number             Force the originating port for upstream queries.\n"
"-R, --no-resolv                     Do NOT read resolv.conf.\n"
"-r, --resolv-file=path              Specify path to resolv.conf (defaults to " RESOLVFILE ").\n"
"-S, --server=/domain/ipaddr         Specify address(es) of upstream servers with optional domains.\n"
"    --local=/domain/                Never forward queries to specified domains.\n"
"-s, --domain=domain                 Specify the domain to be assigned in DHCP leases.\n"
"-t, --mx-target=host_name           Specify the host in an MX reply.\n"
"-T, --local-ttl=time                Specify time-to-live in seconds for replies from /etc/hosts.\n"
"-u, --user=username                 Change to this user after startup. (defaults to " CHUSER ").\n" 
"-v, --version                       Display dnsmasq version.\n"
"-V, --alias=addr,addr,mask          Translate IPv4 addresses from upstream servers.\n"
"-w, --help                          Display this message.\n"
"-x, --pid-file=path                 Specify path of PID file. (defaults to " RUNFILE ").\n"
"-X, --dhcp-lease-max=number         Specify maximum number of DHCP leases (defaults to %d).\n"
"-z, --bind-interfaces               Bind only to interfaces in use.\n"
"-Z, --read-ethers                   Read DHCP static host information from " ETHERSFILE ".\n"
"\n";


unsigned int read_opts (int argc, char **argv, char *buff, struct resolvc **resolv_files, 
			char **mxname, char **mxtarget, char **lease_file, 
			char **username, char **groupname, char **domain_suffix, char **runfile, 
			struct iname **if_names, struct iname **if_addrs, struct iname **if_except,
			struct bogus_addr **bogus_addr, struct server **serv_addrs, int *cachesize, int *port, 
			int *query_port, unsigned long *local_ttl, char **addn_hosts, struct dhcp_context **dhcp,
			struct dhcp_config **dhcp_conf, struct dhcp_opt **dhcp_opts, char **dhcp_file,
			char **dhcp_sname, struct in_addr *dhcp_next_server, int *dhcp_max, 
			unsigned int *min_leasetime, struct doctor **doctors)
{
  int option = 0, i;
  unsigned int flags = 0;
  FILE *f = NULL;
  char *conffile = CONFFILE;
  int conffile_set = 0;
  int lineno = 0;

  opterr = 0;
  
  *min_leasetime = UINT_MAX;

  while (1)
    {
      if (!f)
#ifdef HAVE_GETOPT_LONG
	option = getopt_long(argc, argv, OPTSTRING, (struct option *)opts, NULL);
#else
        option = getopt(argc, argv, OPTSTRING);
#endif
      else
	{ /* f non-NULL, reading from conffile. */
	  if (!fgets(buff, MAXDNAME, f))
	    {
	      /* At end of file, all done */
	      fclose(f);
	      break;
	    }
	  else
	    {
	      char *p;
	      lineno++;
	      /* dump comments */
	      for (p = buff; *p; p++)
		if (*p == '#')
		  *p = 0;
	      /* fgets gets end of line char too. */
	      while (strlen(buff) > 0 && 
		     (buff[strlen(buff)-1] == '\n' || 
		      buff[strlen(buff)-1] == ' ' ||  
		      buff[strlen(buff)-1] == '\r' || 
		      buff[strlen(buff)-1] == '\t'))
		buff[strlen(buff)-1] = 0;
	      if (*buff == 0)
		continue; 
	      if ((p=strchr(buff, '=')))
		{
		  optarg = p+1;
		  *p = 0;
		}
	      else
		optarg = NULL;
	      
	      option = 0;
	      for (i=0; opts[i].name; i++) 
		if (strcmp(opts[i].name, buff) == 0)
		  option = opts[i].val;
	      if (!option)
		{
		  sprintf(buff, "bad option at line %d of %s ", lineno, conffile);
		  complain(buff, NULL);
		  continue;
		}
	    }
	}
      
      if (option == -1)
	{ /* end of command line args, start reading conffile. */
	  if (!conffile)
	    break; /* "confile=" option disables */
	  option = 0;
	  if (!(f = fopen(conffile, "r")))
	    {   
	      if (errno == ENOENT && !conffile_set)
		break; /* No conffile, all done. */
	      else
		die("cannot read %s: %s", conffile);
	    }
	}
     
      if (!f && option == 'w')
	{
	  fprintf (stderr, usage,  CACHESIZ, MAXLEASES);
	  exit(0);
	}

      if (!f && option == 'v')
        {
          fprintf(stderr, "dnsmasq version %s\n", VERSION);
          exit(0);
        }
      
      for (i=0; optmap[i].c; i++)
	if (option == optmap[i].c)
	  {
	    flags |= optmap[i].flag;
	    option = 0;
	    if (f && optarg)
	      {
		sprintf(buff, "extraneous parameter at line %d of %s ", lineno, conffile);
		complain(buff, NULL);
	      }
	    break;
	  }
      
      if (option && option != '?')
	{
	  if (f && !optarg)
	    {
	      sprintf(buff, "missing parameter at line %d of %s ", lineno, conffile);
	      complain(buff, NULL);
	      continue;
	    }
	               
	  switch (option)
	    { 
	     case 'C': 
	       conffile = safe_string_alloc(optarg);
	       conffile_set = 1;
	       break;
	      
	    case 'x': 
	      *runfile = safe_string_alloc(optarg);
	      break;
	      
	    case 'r':
	      {
		char *name = safe_string_alloc(optarg);
		struct resolvc *new, *list = *resolv_files;
		if (list && list->is_default)
		  {
		    /* replace default resolv file - possibly with nothing */
		    if (name)
		      {
			list->is_default = 0;
			list->name = name;
		      }
		    else
		      list = NULL;
		  }
		else if (name)
		  {
		    new = safe_malloc(sizeof(struct resolvc));
		    new->next = list;
		    new->name = name;
		    new->is_default = 0;
		    new->logged = 0;
		    list = new;
		  }
		*resolv_files = list;
		break;
	      }

	    case 'm':
	      if (!canonicalise(optarg))
		option = '?';
	      else 
		*mxname = safe_string_alloc(optarg);
	      break;
	      
	    case 't':
	      if (!canonicalise(optarg))
		option = '?';
	      else
		*mxtarget = safe_string_alloc(optarg);
	      break;
	      
	    case 'l':
	      *lease_file = safe_string_alloc(optarg);
	      break;
	      
	    case 'H':
	      if (*addn_hosts)
		option = '?';
	      else
		*addn_hosts = safe_string_alloc(optarg);
	      break;
	      
	    case 's':
	      if (!canonicalise(optarg))
		option = '?';
	      else
		*domain_suffix = safe_string_alloc(optarg);
	      break;
	      
	    case 'u':
	      *username = safe_string_alloc(optarg);
	      break;
	      
	    case 'g':
	      *groupname = safe_string_alloc(optarg);
	      break;
	      
	    case 'i':
	      {
		struct iname *new = safe_malloc(sizeof(struct iname));
		new->next = *if_names;
		*if_names = new;
		/* new->name may be NULL if someone does
		   "interface=" to disable all interfaces except loop. */
		new->name = safe_string_alloc(optarg);
		break;
	      }
	      
	    case 'I':
	      {
		struct iname *new = safe_malloc(sizeof(struct iname));
		new->next = *if_except;
		*if_except = new;
		new->name = safe_string_alloc(optarg);
		break;
	      }
	      
	    case 'B':
	      {
		struct in_addr addr;
		if ((addr.s_addr = inet_addr(optarg)) != (in_addr_t)-1)
		  {
		    struct bogus_addr *baddr = safe_malloc(sizeof(struct bogus_addr));
		    baddr->next = *bogus_addr;
		    *bogus_addr = baddr;
		    baddr->addr = addr;
		  }
		else
		  option = '?'; /* error */
		break;	
	      }

	    case 'a':
	      {
		struct iname *new = safe_malloc(sizeof(struct iname));
		new->next = *if_addrs;
#ifdef HAVE_IPV6
		if (inet_pton(AF_INET, optarg, &new->addr.in.sin_addr))
		  {
		    new->addr.sa.sa_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
		    new->addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
		  }
		else if (inet_pton(AF_INET6, optarg, &new->addr.in6.sin6_addr))
		  {
		    new->addr.sa.sa_family = AF_INET6;
		    new->addr.in6.sin6_flowinfo = htonl(0);
#ifdef HAVE_SOCKADDR_SA_LEN
		    new->addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		  }
#else
		if ((new->addr.in.sin_addr.s_addr = inet_addr(optarg)) != (in_addr_t)-1)
		  {
		    new->addr.sa.sa_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
		    new->addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
		  }
#endif
		else
		  {
		    option = '?'; /* error */
		    free(new);
		    new = NULL;
		  }
		
		if (new)
		  *if_addrs = new;
		break;
	      }
	      
	    case 'S':
	    case 'A':
	      {
		struct server *serv, *newlist = NULL;
		
		if (*optarg == '/')
		  {
		    char *end;
		    optarg++;
		    while ((end = strchr(optarg, '/')))
		      {
			char *domain;
			*end = 0;
			if (!canonicalise(optarg))
			  option = '?';
			domain = safe_string_alloc(optarg); /* NULL if strlen is zero */
			serv = safe_malloc(sizeof(struct server));
			serv->next = newlist;
			newlist = serv;
			serv->sfd = NULL;
			serv->domain = domain;
			serv->flags = domain ? SERV_HAS_DOMAIN : SERV_FOR_NODOTS;
			optarg = end+1;
		      }
		    if (!newlist)
		      {
			option = '?';
			break;
		      }
		
		  }
		else
		  {
		    newlist = safe_malloc(sizeof(struct server));
		    newlist->next = NULL;
		    newlist->flags = 0;
		    newlist->sfd = NULL;
		    newlist->domain = NULL;
		  }
		
		if (option == 'A')
		  {
		    newlist->flags |= SERV_LITERAL_ADDRESS;
		    if (!(newlist->flags & SERV_TYPE))
		      option = '?';
		  }
		
		if (!*optarg)
		  {
		    newlist->flags |= SERV_NO_ADDR; /* no server */
		    if (newlist->flags & SERV_LITERAL_ADDRESS)
		      option = '?';
		  }
		else
		  {
		    int source_port = 0, serv_port = NAMESERVER_PORT;
		    char *portno, *source;
		    
		    if ((source = strchr(optarg, '@'))) /* is there a source. */
		      {
			*source = 0; 
			if ((portno = strchr(source+1, '#')))
			  { 
			    *portno = 0;
			    source_port = atoi(portno+1);
			  }
		      }
		    
		    if ((portno = strchr(optarg, '#'))) /* is there a port no. */
		      {
			*portno = 0;
			serv_port = atoi(portno+1);
		      }

#ifdef HAVE_IPV6
		    if (inet_pton(AF_INET, optarg, &newlist->addr.in.sin_addr))
#else
		    if ((newlist->addr.in.sin_addr.s_addr = inet_addr(optarg)) != (in_addr_t) -1)
#endif
		      {
			newlist->addr.in.sin_port = htons(serv_port);	
			newlist->source_addr.in.sin_port = htons(source_port); 
			newlist->addr.sa.sa_family = newlist->source_addr.sa.sa_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
			newlist->source_addr.in.sin_len = newlist->addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
			if (source)
			  {
#ifdef HAVE_IPV6
			    if (inet_pton(AF_INET, source+1, &newlist->source_addr.in.sin_addr))
#else
			    if ((newlist->source_addr.in.sin_addr.s_addr = inet_addr(source+1)) != (in_addr_t) -1)
#endif
				newlist->flags |= SERV_HAS_SOURCE;
			    else
			      option = '?'; /* error */
			  }
			else
			  newlist->source_addr.in.sin_addr.s_addr = INADDR_ANY;
		      }
#ifdef HAVE_IPV6
		    else if (inet_pton(AF_INET6, optarg, &newlist->addr.in6.sin6_addr))
		      {
			newlist->addr.in6.sin6_port = htons(serv_port);
			newlist->source_addr.in6.sin6_port = htons(source_port);
			newlist->addr.sa.sa_family = newlist->source_addr.sa.sa_family = AF_INET6;
			newlist->addr.in6.sin6_flowinfo = newlist->source_addr.in6.sin6_flowinfo = htonl(0);
#ifdef HAVE_SOCKADDR_SA_LEN
			newlist->addr.in6.sin6_len = newlist->source_addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			if (source)
			  {
			    if (inet_pton(AF_INET6, source+1, &newlist->source_addr.in6.sin6_addr))
			      newlist->flags |= SERV_HAS_SOURCE;
			    else
			      option = '?'; /* error */
			  }
			else
			  newlist->source_addr.in6.sin6_addr = in6addr_any; 
		      }
#endif
		    else
		      option = '?'; /* error */
		    
		  }
		
		if (option == '?')
		  while (newlist)
		    { 
		      serv = newlist;
		      newlist = newlist->next;
		      free(serv);
		    }
		else
		  {
		    serv = newlist;
		    while (serv->next)
		      {
			serv->next->flags = serv->flags;
			serv->next->addr = serv->addr;
			serv->next->source_addr = serv->source_addr;
			serv = serv->next;
		      }
		    serv->next = *serv_addrs;
		    *serv_addrs = newlist;
		  }
		break;
	      }
	      
	    case 'c':
	      {
		int size = atoi(optarg);
		/* zero is OK, and means no caching. */
		
		if (size < 0)
		  size = 0;
		else if (size > 10000)
		  size = 10000;
		
		*cachesize = size;
		break;
	      }
	      
	    case 'p':
	      *port = atoi(optarg);
	      break;
	      
	    case 'Q':
	      *query_port = atoi(optarg);
	      break;

	    case 'T':
	      *local_ttl = (unsigned long)atoi(optarg);
	      break;

	    case 'X':
	      *dhcp_max = atoi(optarg);
	      break;

	    case 'F':
	      {
		int k, leasepos = 2;
		char *cp, *comma, *a[5] = { NULL, NULL, NULL, NULL, NULL };
		struct dhcp_context *new = safe_malloc(sizeof(struct dhcp_context));
		
		new->next = *dhcp;
		new->lease_time = DEFLEASE; 
		new->netmask.s_addr = 0;
		new->broadcast.s_addr = 0;
		new->netid = NULL;
		
		
		for (cp = optarg; *cp; cp++)
		  if (!(*cp == ' ' || *cp == '.' ||  (*cp >='0' && *cp <= '9')))
		    break;

		if (*cp != ',' && (comma = strchr(optarg, ',')))
		  {
		    *comma = 0;
		    new->netid = safe_string_alloc(optarg);
		    a[0] = comma + 1;
		  }
		else
		  a[0] = optarg;

		
		for (k = 1; k < 5; k++)
		  {
		    if (!(a[k] = strchr(a[k-1], ',')))
		      break;
		    *(a[k]++) = 0;
		  }
		  
		if ((k < 2) ||
		    ((new->start.s_addr = inet_addr(a[0])) == (in_addr_t)-1) ||
		    ((new->end.s_addr = inet_addr(a[1])) == (in_addr_t)-1))
		  {
		    option = '?';
		    free(new);
		    break;
		  }
		else
		  *dhcp = new;
		
		if (k >= 3 && strchr(a[2], '.') &&  
		    ((new->netmask.s_addr = inet_addr(a[2])) != (in_addr_t)-1))
		  leasepos = 3;
		
		if (k >= 4 && strchr(a[3], '.') &&  
		    ((new->broadcast.s_addr = inet_addr(a[3])) != (in_addr_t)-1))
		  leasepos = 4;

		if (k >= leasepos+1)
		  {
		    if (strcmp(a[leasepos], "infinite") == 0)
		      new->lease_time = 0xffffffff;
		    else
		      {
			int fac = 1;
			if (strlen(a[leasepos]) > 0)
			  {
			    switch (a[leasepos][strlen(a[leasepos]) - 1])
			      {
			      case 'h':
			      case 'H':
				fac *= 60;
				/* fall through */
			      case 'm':
			      case 'M':
				fac *= 60;
				/* fall through */
			      case 's':
			      case 'S':
				a[leasepos][strlen(a[leasepos]) - 1] = 0;
			      }
			    
			    new->lease_time = atoi(a[leasepos]) * fac;
			    if (new->lease_time < *min_leasetime)
			      *min_leasetime = new->lease_time;
			  }
		      }
		  }
				
		new->last = new->start;
		
		break;
	      }

	    case 'G':
	      {
		int j, k;
		char *a[4] = { NULL, NULL, NULL, NULL };
		unsigned int e0, e1, e2, e3, e4, e5;
		struct dhcp_config *new = safe_malloc(sizeof(struct dhcp_config));
		struct in_addr in;

		new->next = *dhcp_conf;
				  
		memset(new->hwaddr, 0, ETHER_ADDR_LEN);
		new->clid_len = 0;
		new->clid = NULL;
		new->hostname = NULL;
		new->addr.s_addr = 0;
		new->lease_time = 0; 
		
		a[0] = optarg;
		for (k = 1; k < 4; k++)
		  {
		    if (!(a[k] = strchr(a[k-1], ',')))
		      break;
		    *(a[k]++) = 0;
		  }
		   
		for(j = 0; j < k; j++)
		  if (strchr(a[j], ':')) /* ethernet address or binary CLID */
		    {
		      char *arg = a[j];
		      if ((arg[0] == 'i' || arg[0] == 'I') &&
			  (arg[1] == 'd' || arg[1] == 'D') &&
			  arg[2] == ':')
			{
			  int s, len;
			  arg += 3; /* dump id: */
			  if (strchr(arg, ':'))
			    {
			      s = (strlen(arg)/3) + 1;
			      /* decode in place */
			      for (len = 0; len < s; len++)
				{
				  if (arg[(len*3)+2] != ':')
				    option = '?';
				  arg[(len*3)+2] = 0;
				  arg[len] = strtol(&arg[len*3], NULL, 16);
				}
			    }
			  else
			    len = strlen(arg);
			  
			  new->clid_len = len;
			  new->clid = safe_malloc(len);
			  memcpy(new->clid, arg, len);
			}
		      else if (sscanf(a[j], "%x:%x:%x:%x:%x:%x",
				      &e0, &e1, &e2, &e3, &e4, &e5) == 6)
			{
			  new->hwaddr[0] = e0;
			  new->hwaddr[1] = e1;
			  new->hwaddr[2] = e2;
			  new->hwaddr[3] = e3;
			  new->hwaddr[4] = e4;
			  new->hwaddr[5] = e5;
			}
		      else
			option = '?';
		    }
		  else if (strchr(a[j], '.') && (in.s_addr = inet_addr(a[j])) != (in_addr_t)-1)
		    new->addr = in;
		  else
		    {
		      char *cp, *lastp = NULL, last = 0;
		      int fac = 1;
		      
		      if (strlen(a[j]) > 1)
			{
			  lastp = a[j] + strlen(a[j]) - 1;
			  last = *lastp;
			  switch (last)
			    {
			    case 'h':
			    case 'H':
			      fac *= 60;
			      /* fall through */
			    case 'm':
			    case 'M':
			      fac *= 60;
			      /* fall through */
			    case 's':
			    case 'S':
			      *lastp = 0;
			    }
			}
		      
		      for (cp = a[j]; *cp; cp++)
			if (!isdigit(*cp) && *cp != ' ')
			  break;
		      
		      if (*cp)
			{
			  if (lastp)
			    *lastp = last;
			  if (strcmp(a[j], "infinite") == 0)
			    new->lease_time = 0xffffffff;
			  else
			    new->hostname = safe_string_alloc(a[j]);
			}
		      else
			{
			  new->lease_time = atoi(a[j]) * fac;  
			  if (new->lease_time < *min_leasetime)
			    *min_leasetime = new->lease_time;
			}
		    }

		if (option == '?')
		  free(new);
		else
		  *dhcp_conf = new;
		break;
	      }
	      
	    case 'O':
	      {
		struct dhcp_opt *new = safe_malloc(sizeof(struct dhcp_opt));
		char *cp, *comma;
		int addrs, is_addr;
		
		new->next = *dhcp_opts;
		new->len = 0;
		new->is_addr = 0;
		new->netid = NULL;
				
		if ((comma = strchr(optarg, ',')))
		  {
		    *comma = 0;
		
		    for (cp = optarg; *cp; cp++)
		      if (!(*cp == ' ' || (*cp >='0' && *cp <= '9')))
			break;

		    if (*cp)
		      {
			new->netid = safe_string_alloc(optarg);
			optarg = comma + 1;
			if ((comma = strchr(optarg, ',')))
			  *comma = 0;
		      }
		  }
		
		if ((new->opt = atoi(optarg)) == 0)
		  {
		    option = '?';
		    free(new);
		    break;
		  }

		if (!comma)
		  {
		    *dhcp_opts = new;
		    break;
		  }

		/* check for non-address list characters */
		for (addrs = 1, is_addr = 0, cp = comma+1; *cp; cp++)
		  if (*cp == ',')
		    addrs++;
		  else if (!(*cp == '.' || *cp == ' ' || (*cp >='0' && *cp <= '9')))
		    break;
		  else if (*cp == '.')
		    is_addr = 1;
		    
		if (*cp)
		  {
		    /* text arg */
		    new->len = strlen(comma+1);
		    new->val = safe_malloc(new->len);
		    memcpy(new->val, comma+1, new->len);
		  }
		else
		  {
		    struct in_addr in;
		    unsigned char *op;

		    if (addrs == 1 && !is_addr)
		      {
			new->len = 1;
			new->val = safe_malloc(1);
			*(new->val) = atoi(comma+1);
		      }
		    else
		      {
			new->len = INADDRSZ * addrs;
			new->val = op = safe_malloc(new->len);
			new->is_addr = 1;
			while (addrs--) 
			  {
			    cp = comma;
			    if (cp && (comma = strchr(cp+1, ',')))
			      *comma = 0;
			    if (cp && (in.s_addr = inet_addr(cp+1)) == (in_addr_t)-1)
			      option = '?';
			    memcpy(op, &in, INADDRSZ);
			    op += INADDRSZ;
			  }
		      }
		  }
		*dhcp_opts = new;
		break;
	      }

	    case 'M':
	      {
		char *comma;
		
		if ((comma = strchr(optarg, ',')))
		  *comma = 0;
		*dhcp_file = safe_string_alloc(optarg);
		if (comma)
		  {
		    optarg = comma+1;
		    if ((comma = strchr(optarg, ',')))
		      *comma = 0;
		    *dhcp_sname = safe_string_alloc(optarg);
		    if (comma && (dhcp_next_server->s_addr = inet_addr(comma+1)) == (in_addr_t)-1)
		      option = '?';
		  }
		break;
	      }

	    case 'V':
	      {
		char *a[3] = { NULL, NULL, NULL };
		int k;
		struct in_addr in, out, mask;
		struct doctor *new;

		mask.s_addr = 0xffffffff;
		
		a[0] = optarg;
		for (k = 1; k < 4; k++)
		  {
		    if (!(a[k] = strchr(a[k-1], ',')))
		      break;
		    *(a[k]++) = 0;
		  }

		if ((k < 2) ||
		    ((in.s_addr = inet_addr(a[0])) == (in_addr_t)-1) ||
		    ((out.s_addr = inet_addr(a[1])) == (in_addr_t)-1))
		  {
		    option = '?';
		    break;
		  }

		if (k == 3)
		  mask.s_addr = inet_addr(a[2]);

		new = safe_malloc(sizeof(struct doctor));
		new->in = in;
		new->out = out;
		new->mask = mask;
		new->next = *doctors;
		*doctors = new;
		
		break;
	      }
	    }
	}
      
      if (option == '?')
	{
	  if (f)
	    {
	      sprintf(buff, "error at line %d of %s ", lineno, conffile);
	      complain(buff, NULL);
	    }
	  else
	    die("bad command line options: try --help.", NULL);
	}
    }
      
  /* port might no be known when the address is parsed - fill in here */
  if (*serv_addrs)
    {
      struct server *tmp;
      for (tmp = *serv_addrs; tmp; tmp = tmp->next)
	if (!(tmp->flags & SERV_HAS_SOURCE))
	  {
	    if (tmp->source_addr.sa.sa_family == AF_INET)
	      tmp->source_addr.in.sin_port = htons(*query_port);
#ifdef HAVE_IPV6
	    else if (tmp->source_addr.sa.sa_family == AF_INET6)
	      tmp->source_addr.in6.sin6_port = htons(*query_port);
#endif  
	  }
    }
  
  if (*if_addrs)
    {  
      struct iname *tmp;
      for(tmp = *if_addrs; tmp; tmp = tmp->next)
	if (tmp->addr.sa.sa_family == AF_INET)
	  tmp->addr.in.sin_port = htons(*port);
#ifdef HAVE_IPV6
	else if (tmp->addr.sa.sa_family == AF_INET6)
	  tmp->addr.in6.sin6_port = htons(*port);
#endif /* IPv6 */
    }
		      
  /* only one of these need be specified: the other defaults to the
     host-name */
  if ((flags & OPT_LOCALMX) || *mxname || *mxtarget)
    {
      if (gethostname(buff, MAXDNAME) == -1)
	die("cannot get host-name: %s", NULL);
	      
      if (!*mxname)
	*mxname = safe_string_alloc(buff);
      
      if (!*mxtarget)
	*mxtarget = safe_string_alloc(buff);
    }
  
  if (flags & OPT_NO_RESOLV)
    *resolv_files = 0;
  else if (*resolv_files && (*resolv_files)->next && (flags & OPT_NO_POLL))
    die("only one resolv.conf file allowed in no-poll mode.", NULL);
  
  return flags;
}
      
      

