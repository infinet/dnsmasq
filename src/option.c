/* dnsmasq is Copyright (c) 2000 - 2004 Simon Kelley

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

#define OPTSTRING "ZDNLERKzowefnbvhdkqr:m:p:c:l:s:i:t:u:g:a:x:S:C:A:T:H:Q:I:B:F:G:O:M:X:V:U:j:P:"

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
  {"dhcp-vendorclass", 1, 0, 'U'},
  {"dhcp-userclass", 1, 0, 'j'},
  {"edns-packet-max", 1, 0, 'P'},
  {"keep-in-foreground", 0, 0, 'k'},
  {"dhcp-authoritative", 0, 0, 'K'},
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
  { 'k', OPT_NO_FORK },
  { 'K', OPT_AUTHORITATIVE },
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
"-j, --dhcp-userclass=<id>,<class>   Map DHCP user class to option set.\n"
"-k, --keep-in-foreground            Do NOT fork into the background, do NOT run in debug mode.\n"
"-K, --dhcp-authoritative            Assume we are the only DHCP server on the local network.\n"
"-l, --dhcp-leasefile=path           Specify where to store DHCP leases (defaults to " LEASEFILE ").\n"
"-L, --localmx                       Return MX records for local hosts.\n"
"-m, --mx-host=host_name             Specify the MX name to reply to.\n"
"-M, --dhcp-boot=<bootp opts>        Specify BOOTP options to DHCP server.\n"
"-n, --no-poll                       Do NOT poll " RESOLVFILE " file, reload only on SIGHUP.\n"
"-N, --no-negcache                   Do NOT cache failed search results.\n"
"-o, --strict-order                  Use nameservers strictly in the order given in " RESOLVFILE ".\n"
"-O, --dhcp-option=<optspec>         Set extra options to be set to DHCP clients.\n"
"-p, --port=number                   Specify port to listen for DNS requests on (defaults to 53).\n"
"-P, --edns-packet-max=<size>        Maximum supported UDP packet size for EDNS.0 (defaults to %d).\n"
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
"-U, --dhcp-vendorclass=<id>,<class> Map DHCP vendor class to option set.\n"
"-v, --version                       Display dnsmasq version and copyright information.\n"
"-V, --alias=addr,addr,mask          Translate IPv4 addresses from upstream servers.\n"
"-w, --help                          Display this message.\n"
"-x, --pid-file=path                 Specify path of PID file. (defaults to " RUNFILE ").\n"
"-X, --dhcp-lease-max=number         Specify maximum number of DHCP leases (defaults to %d).\n"
"-z, --bind-interfaces               Bind only to interfaces in use.\n"
"-Z, --read-ethers                   Read DHCP static host information from " ETHERSFILE ".\n"
"\n";


struct daemon *read_opts (int argc, char **argv)
{
  struct daemon *daemon = safe_malloc(sizeof(struct daemon));
  char *problem = NULL, *buff = safe_malloc(MAXDNAME);
  int option = 0, i;
  FILE *file_save = NULL, *f = NULL;
  char *file_name_save = NULL, *conffile = CONFFILE;
  int hosts_index = 1, conffile_set = 0;
  int line_save = 0, lineno = 0;
  opterr = 0;
  
  memset(daemon, 0, sizeof(struct daemon));
  daemon->namebuff = buff;

  /* Set defaults - everything else is zero or NULL */
  daemon->min_leasetime = UINT_MAX;
  daemon->cachesize = CACHESIZ;
  daemon->port = NAMESERVER_PORT;
  daemon->default_resolv.is_default = 1;
  daemon->default_resolv.name = RESOLVFILE;
  daemon->resolv_files = &daemon->default_resolv;
  daemon->username = CHUSER;
  daemon->groupname = CHGRP;
  daemon->runfile =  RUNFILE;
  daemon->dhcp_max = MAXLEASES;
  daemon->edns_pktsz = EDNS_PKTSZ;
  
  while (1)
    {
      problem = NULL;

      if (!f)
#ifdef HAVE_GETOPT_LONG
	option = getopt_long(argc, argv, OPTSTRING, (struct option *)opts, NULL);
#else
        option = getopt(argc, argv, OPTSTRING);
#endif
      else
	{ /* f non-NULL, reading from conffile. */
	reread:
	  if (!fgets(buff, MAXDNAME, f))
	    {
	      /* At end of file, all done */
	      fclose(f);
	      if (file_save)
		{
		  /* may be nested */
		  conffile = file_name_save;
		  f = file_save;
		  file_save = NULL;
		  lineno = line_save;
		  goto reread;
		}
	      break;
	    }
	  else
	    {
	      char *p;
	      int white;
	      lineno++;
	      /* dump comments */
	      for (white = 1, p = buff; *p; p++)
		if (white && *p == '#')
		  { 
		    *p = 0;
		    break;
		  }
		else
		  white = isspace(*p);
	      /* fgets gets end of line char too. */
	      while (strlen(buff) > 0 && isspace(buff[strlen(buff)-1]))
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
	fileopen:
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
	  fprintf (stderr, usage,  CACHESIZ, EDNS_PKTSZ, MAXLEASES);
	  exit(0);
	}

      if (!f && option == 'v')
        {
          fprintf(stderr, "Dnsmasq version %s  %s\n\n", VERSION, COPYRIGHT);
	  fprintf(stderr, "This software comes with ABSOLUTELY NO WARRANTY.\n");
	  fprintf(stderr, "Dnsmasq is free software, and you are welcome to redistribute it\n");
	  fprintf(stderr, "under the terms of the GNU General Public License, version 2.\n");
          exit(0);
        }
      
      for (i=0; optmap[i].c; i++)
	if (option == optmap[i].c)
	  {
	    daemon->options |= optmap[i].flag;
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
	       if (!f)
		 {
		   conffile = safe_string_alloc(optarg);
		   conffile_set = 1;
		   break;
		 }
	      
	       /* nest conffiles one deep */
	       if (file_save)
		 {
		   sprintf(buff, "nested includes not allowed at line %d of %s ", lineno, conffile);
		   complain(buff, NULL);
		   continue;
		 }
	       file_name_save = conffile;
	       file_save = f;
	       line_save = lineno;
	       conffile = safe_string_alloc(optarg);
	       conffile_set = 1;
	       lineno = 0;
	       goto fileopen;
	      
	    case 'x': 
	      daemon->runfile = safe_string_alloc(optarg);
	      break;
	      
	    case 'r':
	      {
		char *name = safe_string_alloc(optarg);
		struct resolvc *new, *list = daemon->resolv_files;
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
		daemon->resolv_files = list;
		break;
	      }

	    case 'm':
	      {
		char *comma = strchr(optarg, ',');
		if (comma)
		  *(comma++) = 0;
		if (!canonicalise(optarg) || (comma && !canonicalise(comma)))
		  {
		    option = '?';
		    problem = "bad MX name";
		  }
		else 
		  {
		    struct mx_record *new = safe_malloc(sizeof(struct mx_record));
		    new->next = daemon->mxnames;
		    daemon->mxnames = new;
		    new->mxname = safe_string_alloc(optarg);
		    new->mxtarget = safe_string_alloc(comma); /* may be NULL */
		  }
		break;
	      }
	      
	    case 't':
	      if (!canonicalise(optarg))
		{
		  option = '?';
		  problem = "bad MX target";
		}
	      else
		daemon->mxtarget = safe_string_alloc(optarg);
	      break;
	      
	    case 'l':
	      daemon->lease_file = safe_string_alloc(optarg);
	      break;
	      
	    case 'H':
	      {
		struct hostsfile *new = safe_malloc(sizeof(struct hostsfile));
		new->fname = safe_string_alloc(optarg);
		new->index = hosts_index++;
		new->next = daemon->addn_hosts;
		daemon->addn_hosts = new;
		break;
	      }

	    case 's':
	      if (strcmp (optarg, "#") == 0)
		daemon->options |= OPT_RESOLV_DOMAIN;
	      else if (!canonicalise(optarg))
		option = '?';
	      else
		daemon->domain_suffix = safe_string_alloc(optarg);
	      break;
	      
	    case 'u':
	      daemon->username = safe_string_alloc(optarg);
	      break;
	      
	    case 'g':
	      daemon->groupname = safe_string_alloc(optarg);
	      break;
	      
	    case 'i':
	      {
		struct iname *new = safe_malloc(sizeof(struct iname));
		new->next = daemon->if_names;
		daemon->if_names = new;
		/* new->name may be NULL if someone does
		   "interface=" to disable all interfaces except loop. */
		new->name = safe_string_alloc(optarg);
		new->isloop = new->used = 0;
		if (strchr(optarg, ':'))
		  daemon->options |= OPT_NOWILD;
		break;
	      }
	      
	    case 'I':
	      {
		struct iname *new = safe_malloc(sizeof(struct iname));
		new->next = daemon->if_except;
		daemon->if_except = new;
		new->name = safe_string_alloc(optarg);
		if (strchr(optarg, ':'))
		   daemon->options |= OPT_NOWILD;
		break;
	      }
	      
	    case 'B':
	      {
		struct in_addr addr;
		if ((addr.s_addr = inet_addr(optarg)) != (in_addr_t)-1)
		  {
		    struct bogus_addr *baddr = safe_malloc(sizeof(struct bogus_addr));
		    baddr->next = daemon->bogus_addr;
		    daemon->bogus_addr = baddr;
		    baddr->addr = addr;
		  }
		else
		  option = '?'; /* error */
		break;	
	      }

	    case 'a':
	      {
		struct iname *new = safe_malloc(sizeof(struct iname));
		new->next = daemon->if_addrs;
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
		  daemon->if_addrs = new;
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
			char *domain = NULL;
			*end = 0;
			/* # matches everything and becomes a zero length domain string */
			if (strcmp(optarg, "#") == 0)
			  domain = "";
			else if (!canonicalise(optarg) && strlen(optarg) != 0)
			  option = '?';
			else
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
			    if (!atoi_check(portno+1, &source_port))
			      {
				option = '?';
				problem = "bad port";
			      }
			  }
		      }
		    
		    if ((portno = strchr(optarg, '#'))) /* is there a port no. */
		      {
			*portno = 0;
			if (!atoi_check(portno+1, &serv_port))
			  {
			    option = '?';
			    problem = "bad port";
			  }
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
		    serv->next = daemon->servers;
		    daemon->servers = newlist;
		  }
		break;
	      }
	      
	    case 'c':
	      {
		int size;
		if (!atoi_check(optarg, &size))
		  option = '?';
		else
		  {
		    /* zero is OK, and means no caching. */
		    
		    if (size < 0)
		      size = 0;
		    else if (size > 10000)
		      size = 10000;
		    
		    daemon->cachesize = size;
		  }
		break;
	      }
	      
	    case 'p':
	      if (!atoi_check(optarg, &daemon->port))
		option = '?';
	      break;
	      
	    case 'P':
	      {
		int i;
		if (!atoi_check(optarg, &i))
		  option = '?';
		daemon->edns_pktsz = (unsigned short)i;	
		break;
	      }

	    case 'Q':
	      if (!atoi_check(optarg, &daemon->query_port))
		option = '?';
	      break;

	    case 'T':
	      {
		int ttl;
		if (!atoi_check(optarg, &ttl))
		  option = '?';
		else
		  daemon->local_ttl = (unsigned long)ttl;
		break;
	      }

	    case 'X':
	      if (!atoi_check(optarg, &daemon->dhcp_max))
		option = '?';
	      break;

	    case 'F':
	      {
		int k, leasepos = 2;
		char *cp, *comma, *a[5] = { NULL, NULL, NULL, NULL, NULL };
		struct dhcp_context *new = safe_malloc(sizeof(struct dhcp_context));
		
		new->next = daemon->dhcp;
		new->lease_time = DEFLEASE;
		new->addr_epoch = 0;
		new->netmask.s_addr = 0;
		new->broadcast.s_addr = 0;
		new->router.s_addr = 0;
		new->netid.net = NULL;
		new->static_only = 0;
		
		problem = "bad dhcp-range";

		for (cp = optarg; *cp; cp++)
		  if (!(*cp == ' ' || *cp == '.' ||  (*cp >='0' && *cp <= '9')))
		    break;

		if (*cp != ',' && (comma = strchr(optarg, ',')))
		  {
		    *comma = 0;
		    new->netid.net = safe_string_alloc(optarg);
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
		  
		if ((k < 2) || ((new->start.s_addr = inet_addr(a[0])) == (in_addr_t)-1))
		  option = '?';
		else if (strcmp(a[1], "static") == 0)
		  {
		    new->end = new->start;
		    new->static_only = 1;
		  }
		else if ((new->end.s_addr = inet_addr(a[1])) == (in_addr_t)-1)
		  option = '?';
		  
		if (ntohl(new->start.s_addr) > ntohl(new->end.s_addr))
		  {
		    struct in_addr tmp = new->start;
		    new->start = new->end;
		    new->end = tmp;
		  }
		    
		if (option != '?' && k >= 3 && strchr(a[2], '.') &&  
		    ((new->netmask.s_addr = inet_addr(a[2])) != (in_addr_t)-1))
		  {
		    leasepos = 3;
		    if (!is_same_net(new->start, new->end, new->netmask))
		      {
			problem = "inconsistent DHCP range";
			option = '?';
		      }
		  }

		if (option == '?')
		  {
		    free(new);
		    break;
		  }
		else
		  daemon->dhcp = new;

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
			  }
		      }
		  }
				
		if (new->lease_time < daemon->min_leasetime)
		  daemon->min_leasetime = new->lease_time;
		break;
	      }

	    case 'G':
	      {
		int j, k;
		char *a[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
		unsigned int e0, e1, e2, e3, e4, e5;
		struct dhcp_config *new = safe_malloc(sizeof(struct dhcp_config));
		struct in_addr in;

		new->next = daemon->dhcp_conf;
		new->flags = 0;		  
		
		
		a[0] = optarg;
		for (k = 1; k < 6; k++)
		  {
		    if (!(a[k] = strchr(a[k-1], ',')))
		      break;
		    *(a[k]++) = 0;
		  }
		   
		for(j = 0; j < k; j++)
		  if (strchr(a[j], ':')) /* ethernet address, netid or binary CLID */
		    {
		      char *arg = a[j];
		      if ((arg[0] == 'i' || arg[0] == 'I') &&
			  (arg[1] == 'd' || arg[1] == 'D') &&
			  arg[2] == ':')
			{
			  if (arg[3] == '*')
			    new->flags |= CONFIG_NOCLID;
			  else
			    {
			      int len;
			      arg += 3; /* dump id: */
			      if (strchr(arg, ':'))
				{
				  /* decode hex in place */
				  char *p = arg, *q = arg, *r;
				  while (*p)
				    {
				      for (r = p; *r && *r != ':'; r++);
				      if (*r)
					{
					  if (r != p)
					    {
					      *r = 0;
					      *(q++) = strtol(p, NULL, 16);
					    }
					  p = r+1;
					}
				      else
					{
					  if (*p)
					    *(q++) = strtol(p, NULL, 16);
					  break;
					}
				    }
				  len = q - arg;
				}
			      else
				len = strlen(arg);
			      
			      new->flags |= CONFIG_CLID;
			      new->clid_len = len;
			      new->clid = safe_malloc(len);
			      memcpy(new->clid, arg, len);
			    }
			}
		      else if ((arg[0] == 'n' || arg[0] == 'N') &&
			       (arg[1] == 'e' || arg[1] == 'E') &&
			       (arg[2] == 't' || arg[3] == 'T') &&
			       arg[3] == ':')
			{
			  new->flags |= CONFIG_NETID;
			  new->netid.net = safe_string_alloc(arg+4);
			}
		      else if (sscanf(a[j], "%x:%x:%x:%x:%x:%x",
				      &e0, &e1, &e2, &e3, &e4, &e5) == 6)
			{
			  new->flags |= CONFIG_HWADDR;
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
		    {
		      new->addr = in;
		      new->flags |= CONFIG_ADDR;
		    }
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
			    {
			      new->lease_time = 0xffffffff;
			      new->flags |= CONFIG_TIME;
			    }
			  else if (strcmp(a[j], "ignore") == 0)
			    new->flags |= CONFIG_DISABLE;
			  else
			    {
			      new->hostname = safe_string_alloc(a[j]);
			      new->flags |= CONFIG_NAME;
			    }
			}
		      else
			{
			  new->lease_time = atoi(a[j]) * fac; 
			  new->flags |= CONFIG_TIME;
			}
		    }

		if (option == '?')
		  {
		    problem = "bad dhcp-host";
		    if (new->flags & CONFIG_NAME)
		      free(new->hostname);
		    if (new->flags & CONFIG_CLID)
		      free(new->clid);
		    if (new->flags & CONFIG_NETID)
		      free(new->netid.net);
		    free(new);
		  }
		else
		  {
		    if ((new->flags & CONFIG_TIME) && new->lease_time < daemon->min_leasetime)
		      daemon->min_leasetime = new->lease_time;
		    daemon->dhcp_conf = new;
		  }
		break;
	      }
	      
	    case 'O':
	      {
		struct dhcp_opt *new = safe_malloc(sizeof(struct dhcp_opt));
		char *cp, *comma;
		int addrs, digs, is_addr, is_hex, is_dec;
		
		new->next = daemon->dhcp_opts;
		new->len = 0;
		new->is_addr = 0;
		new->netid = NULL;
		new->val = NULL;
				
		if ((comma = strchr(optarg, ',')))
		  {
		    *comma++ = 0;
		
		    for (cp = optarg; *cp; cp++)
		      if (!(*cp == ' ' || (*cp >='0' && *cp <= '9')))
			break;

		    if (*cp)
		      {
			new->netid = safe_string_alloc(optarg);
			optarg = comma;
			if ((comma = strchr(optarg, ',')))
			  *comma++ = 0;
		      }
		  }
		
		if ((new->opt = atoi(optarg)) == 0)
		  {
		    option = '?';
		    problem = "bad dhcp-opt";
		  }
		else if (comma && new->opt == 119)
		  {
		    /* dns search, RFC 3397 */
		    unsigned char *q, *r, *tail;
		    unsigned char *p = NULL;
		    int newlen, len = 0;
		    
		    optarg = comma;
		    if ((comma = strchr(optarg, ',')))
		      *(comma++) = 0;

		    while (optarg && *optarg)
		      {
			if (!canonicalise(optarg))
			  {
			    option = '?';
			    problem = "bad dhcp-search-opt";
			    break;
			  }
			
			if (!(r = realloc(p, len + strlen(optarg) + 2)))
			  die("could not get memory", NULL);
			p = memmove(r, p, len);
			
			q = p + len;
			
			/* add string on the end in RFC1035 format */
			while (*optarg) 
			  {
			    char *cp = q++;
			    int j;
			    for (j = 0; *optarg && (*optarg != '.'); optarg++, j++)
			      *q++ = *optarg;
			    *cp = j;
			    if (*optarg)
			      optarg++;
			  }
			*q++ = 0;
			
			/* Now tail-compress using earlier names. */
			newlen = q - p;
			for (tail = p + len; *tail; tail += (*tail) + 1)
			  for (r = p; r - p < len; r += (*r) + 1)
			    if (strcmp(r, tail) == 0)
			      {
				PUTSHORT((r - p) | 0xc000, tail); 
				newlen = tail - p;
				goto end;
			      }
		      end:
			len = newlen;
		    
			optarg = comma;
			if (optarg && (comma = strchr(optarg, ',')))
			  *(comma++) = 0;
		      }

		    new->len = len;
		    new->val = p;
		  }
		else if (comma)
		  {
		    /* not option 119 */
		    /* characterise the value */
		    is_addr = is_hex = is_dec = 1;
		    addrs = digs = 1;
		    for (cp = comma; *cp; cp++)
		      if (*cp == ',')
			{
			  addrs++;
			  is_dec = is_hex = 0;
			}
		      else if (*cp == ':')
			{
			  digs++;
			  is_dec = is_addr = 0;
			}
		      else if (*cp == '.')
			is_dec = is_hex = 0;
		      else if (!(*cp >='0' && *cp <= '9'))
			{
			  is_dec = is_addr = 0;
			  if (!((*cp >='A' && *cp <= 'F') ||
				(*cp >='a' && *cp <= 'f')))
			    is_hex = 0;
			}
		
		    if (is_hex && digs > 1)
		      {
			char *p = comma, *q, *r;
			new->len = digs;
			q = new->val = safe_malloc(new->len);
			while (*p)
			  {
			    for (r = p; *r && *r != ':'; r++);
			    if (*r)
			      {
				if (r != p)
				  {
				    *r = 0;
				    *(q++) = strtol(p, NULL, 16);
				  }
				p = r+1;
			      }
			    else
			      {
				if (*p)
				  *(q++) = strtol(p, NULL, 16);
				break;
			      }
			  }
		      }
		    else if (is_dec)
		      {
			/* Given that we don't know the length,
			   this appaling hack is the best available */
			unsigned int val = atoi(comma);
			if (val < 256)
			  {
			    new->len = 1;
			    new->val = safe_malloc(1);
			    *(new->val) = val;
			  }
			else if (val < 65536)
			  {
			    new->len = 2;
			    new->val = safe_malloc(2);
			    *(new->val) = val>>8;
			    *(new->val+1) = val;
			  }
			else
			  {
			    new->len = 4;
			    new->val = safe_malloc(4);
			    *(new->val) = val>>24;
			    *(new->val+1) = val>>16;
			    *(new->val+2) = val>>8;
			    *(new->val+3) = val;
			  }
		      }
		    else if (is_addr)	
		      {
			struct in_addr in;
			unsigned char *op;
			new->len = INADDRSZ * addrs;
			new->val = op = safe_malloc(new->len);
			new->is_addr = 1;
			while (addrs--) 
			  {
			    cp = comma;
			    if ((comma = strchr(cp, ',')))
			      *comma++ = 0;
			    in.s_addr = inet_addr(cp);
			    memcpy(op, &in, INADDRSZ);
			    op += INADDRSZ;
			  }
		      }
		    else
		      {
			/* text arg */
			new->len = strlen(comma);
			new->val = safe_malloc(new->len);
			memcpy(new->val, comma, new->len);
		      }
		  }

		if (new->len > 256)
		  {
		    option = '?';
		    problem = "dhcp-option too long";
		  }

		if (option == '?')
		  {
		    if (new->netid)
		      free(new->netid);
		    if (new->val)
		      free(new->val);
		    free(new);
		  }
		else
		  daemon->dhcp_opts = new;

		break;
	      }

	    case 'M':
	      {
		char *comma;
		
		if ((comma = strchr(optarg, ',')))
		  *comma = 0;
		daemon->dhcp_file = safe_string_alloc(optarg);
		if (comma)
		  {
		    optarg = comma+1;
		    if ((comma = strchr(optarg, ',')))
		      *comma = 0;
		    daemon->dhcp_sname = safe_string_alloc(optarg);
		    if (comma && (daemon->dhcp_next_server.s_addr = inet_addr(comma+1)) == (in_addr_t)-1)
		      option = '?';
		  }
		break;
	      }

	    case 'U':
	    case 'j':
	      {
		char *comma;
		
		if (!(comma = strchr(optarg, ',')))
		  option = '?';
		else
		  {
		    struct dhcp_vendor *new = safe_malloc(sizeof(struct dhcp_vendor));
		    *comma = 0;
		    new->netid.net = safe_string_alloc(optarg);
		    new->len = strlen(comma+1);
		    new->data = safe_malloc(new->len);
		    memcpy(new->data, comma+1, new->len);
		    new->is_vendor = (option == 'U');
		    new->next = daemon->dhcp_vendors;
		    daemon->dhcp_vendors = new;
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
		new->next = daemon->doctors;
		daemon->doctors = new;
		
		break;
	      }
	    }
	}
      
      if (option == '?')
	{
	  if (f)
	    {
	      sprintf(buff, "%s at line %d of %s ", 
		      problem ? problem : "error", lineno, conffile);
	      complain(buff, NULL);
	    }
	  else
	    die("bad command line options: %s.", problem ? problem : "try --help");
	}
    }
      
  /* port might no be known when the address is parsed - fill in here */
  if (daemon->servers)
    {
      struct server *tmp;
      for (tmp = daemon->servers; tmp; tmp = tmp->next)
	if (!(tmp->flags & SERV_HAS_SOURCE))
	  {
	    if (tmp->source_addr.sa.sa_family == AF_INET)
	      tmp->source_addr.in.sin_port = htons(daemon->query_port);
#ifdef HAVE_IPV6
	    else if (tmp->source_addr.sa.sa_family == AF_INET6)
	      tmp->source_addr.in6.sin6_port = htons(daemon->query_port);
#endif  
	  }
    }
  
  if (daemon->if_addrs)
    {  
      struct iname *tmp;
      for(tmp = daemon->if_addrs; tmp; tmp = tmp->next)
	if (tmp->addr.sa.sa_family == AF_INET)
	  tmp->addr.in.sin_port = htons(daemon->port);
#ifdef HAVE_IPV6
	else if (tmp->addr.sa.sa_family == AF_INET6)
	  tmp->addr.in6.sin6_port = htons(daemon->port);
#endif /* IPv6 */
    }
		      
  /* only one of these need be specified: the other defaults to the
     host-name */
  if ((daemon->options & OPT_LOCALMX) || daemon->mxnames || daemon->mxtarget)
    {
      if (gethostname(buff, MAXDNAME) == -1)
	die("cannot get host-name: %s", NULL);
	      
      if (!daemon->mxnames)
	{
	  daemon->mxnames = safe_malloc(sizeof(struct mx_record));
	  daemon->mxnames->next = NULL;
	  daemon->mxnames->mxtarget = NULL;
	  daemon->mxnames->mxname = safe_string_alloc(buff);
}
      
      if (!daemon->mxtarget)
	daemon->mxtarget = safe_string_alloc(buff);
    }
  
  if (daemon->options & OPT_NO_RESOLV)
    daemon->resolv_files = 0;
  else if (daemon->resolv_files && (daemon->resolv_files)->next && (daemon->options & OPT_NO_POLL))
    die("only one resolv.conf file allowed in no-poll mode.", NULL);
  
  if (daemon->options & OPT_RESOLV_DOMAIN)
    {
      char *line;
      
      if (!daemon->resolv_files || (daemon->resolv_files)->next)
	die("must have exactly one resolv.conf to read domain from.", NULL);
      
      if (!(f = fopen((daemon->resolv_files)->name, "r")))
	die("failed to read %s: %m", (daemon->resolv_files)->name);
      
      while ((line = fgets(buff, MAXDNAME, f)))
	{
	  char *token = strtok(line, " \t\n\r");
	  
	  if (!token || strcmp(token, "search") != 0)
	    continue;
	  
	  if ((token = strtok(NULL, " \t\n\r")) &&  
	      canonicalise(token) &&
	      (daemon->domain_suffix = safe_string_alloc(token)))
	    break;
	}

      fclose(f);

      if (!daemon->domain_suffix)
	die("no search directive found in %s", (daemon->resolv_files)->name);
    }
      
  return daemon;
}
      
      

