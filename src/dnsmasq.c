/* dnsmasq is Copyright (c) 2000-2003 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* See RFC1035 for details of the protocol this code talks. */

/* Author's email: simon@thekelleys.org.uk */

#include "dnsmasq.h"

static int sigterm, sighup, sigusr1, sigalarm;

static void sig_handler(int sig)
{
  if (sig == SIGTERM)
    sigterm = 1;
  else if (sig == SIGHUP)
    sighup = 1;
  else if (sig == SIGUSR1)
    sigusr1 = 1;
  else if (sig == SIGALRM)
    sigalarm = 1;
}

int main (int argc, char **argv)
{
  int cachesize = CACHESIZ;
  int port = NAMESERVER_PORT;
  int maxleases = MAXLEASES;
  int query_port = 0;
  int first_loop = 1;
  int bind_fallback = 0;
  unsigned long local_ttl = 0;
  unsigned int options, min_leasetime;
  char *runfile = RUNFILE;
  time_t resolv_changed = 0;
  time_t now, last = 0;
  struct irec *interfaces = NULL;
  struct listener *listener, *listeners = NULL;
  struct doctor *doctors = NULL;
  struct mx_record *mxnames = NULL;
  char *mxtarget = NULL;
  char *lease_file = NULL;
  char *addn_hosts = NULL;
  char *domain_suffix = NULL;
  char *username = CHUSER;
  char *groupname = CHGRP;
  struct iname *if_names = NULL;
  struct iname *if_addrs = NULL;
  struct iname *if_except = NULL;
  struct server *serv_addrs = NULL;
  char *dnamebuff, *packet;
  int uptime_fd = -1;
  struct server *servers, *last_server;
  struct resolvc default_resolv = { NULL, 1, 0, RESOLVFILE };
  struct resolvc *resolv = &default_resolv;
  struct bogus_addr *bogus_addr = NULL;
  struct serverfd *serverfdp, *sfds = NULL;
  struct dhcp_context *dhcp_tmp, *dhcp = NULL;
  struct dhcp_config *dhcp_configs = NULL;
  struct dhcp_opt *dhcp_options = NULL;
  struct dhcp_vendor *dhcp_vendors = NULL;
  char *dhcp_file = NULL, *dhcp_sname = NULL;
  struct in_addr dhcp_next_server;
  int leasefd = -1, dhcpfd = -1, dhcp_raw_fd = -1;
  struct sigaction sigact;
  sigset_t sigmask;

  sighup = 1; /* init cache the first time through */
  sigusr1 = 0; /* but don't dump */
  sigterm = 0; /* or die */
#ifdef HAVE_BROKEN_RTC
  sigalarm = 1; /* need regular lease dumps */
#else
  sigalarm = 0; /* or not */
#endif
 
  sigact.sa_handler = sig_handler;
  sigact.sa_flags = 0;
  sigemptyset(&sigact.sa_mask);
  sigaction(SIGUSR1, &sigact, NULL);
  sigaction(SIGHUP, &sigact, NULL);
  sigaction(SIGTERM, &sigact, NULL);
  sigaction(SIGALRM, &sigact, NULL);

  /* now block all the signals, they stay that way except
      during the call to pselect */
  sigaddset(&sigact.sa_mask, SIGUSR1);
  sigaddset(&sigact.sa_mask, SIGTERM);
  sigaddset(&sigact.sa_mask, SIGHUP);
  sigaddset(&sigact.sa_mask, SIGALRM);
  sigprocmask(SIG_BLOCK, &sigact.sa_mask, &sigmask); 

  /* These get allocated here to avoid overflowing the small stack
     on embedded systems. dnamebuff is big enough to hold one
     maximal sixed domain name and gets passed into all the processing
     code. We manage to get away with one buffer. */
  dnamebuff = safe_malloc(MAXDNAME);
  packet = safe_malloc(DNSMASQ_PACKETSZ);
  
  dhcp_next_server.s_addr = 0;
  options = read_opts(argc, argv, dnamebuff, &resolv, &mxnames, &mxtarget, &lease_file,
		      &username, &groupname, &domain_suffix, &runfile, 
		      &if_names, &if_addrs, &if_except, &bogus_addr, 
		      &serv_addrs, &cachesize, &port, &query_port, &local_ttl, &addn_hosts,
		      &dhcp, &dhcp_configs, &dhcp_options, &dhcp_vendors,
		      &dhcp_file, &dhcp_sname, &dhcp_next_server, &maxleases, &min_leasetime,
		      &doctors);

  if (!lease_file)
    {
      if (dhcp)
	lease_file = LEASEFILE;
    }
#ifndef HAVE_ISC_READER
  else if (!dhcp)
    die("ISC dhcpd integration not available: set HAVE_ISC_READER in src/config.h", NULL);
#endif
  
  interfaces = enumerate_interfaces(&if_names, &if_addrs, if_except, port);

  if (!(options & OPT_NOWILD) && !(listeners = create_wildcard_listeners(port)))
    {
      bind_fallback = 1;
      options |= OPT_NOWILD;
    }
    
  if (options & OPT_NOWILD) 
    {
      struct iname *if_tmp;
      listeners = create_bound_listeners(interfaces);

      for (if_tmp = if_names; if_tmp; if_tmp = if_tmp->next)
	if (if_tmp->name && !if_tmp->used)
	  die("unknown interface %s", if_tmp->name);
  
      for (if_tmp = if_addrs; if_tmp; if_tmp = if_tmp->next)
	if (!if_tmp->used)
	  {
	    char addrbuff[ADDRSTRLEN];
#ifdef HAVE_IPV6
	    if (if_tmp->addr.sa.sa_family == AF_INET)
	      inet_ntop(AF_INET, &if_tmp->addr.in.sin_addr,
			addrbuff, ADDRSTRLEN);
	    else
	      inet_ntop(AF_INET6, &if_tmp->addr.in6.sin6_addr,
			addrbuff, ADDRSTRLEN);
#else
	    strcpy(addrbuff, inet_ntoa(if_tmp->addr.in.sin_addr));
#endif
	    die("no interface with address %s", addrbuff);
	  }
    }
  
  forward_init(1);
  cache_init(cachesize, options & OPT_LOG);

#ifdef HAVE_BROKEN_RTC
  if ((uptime_fd = open(UPTIME, O_RDONLY)) == -1)
    die("cannot open " UPTIME ":%s", NULL);
#endif
 
  now = dnsmasq_time(uptime_fd);
  
  if (dhcp)
    {
#if !defined(IP_PKTINFO) && !defined(IP_RECVIF)
      int c;
      struct iname *tmp;
      for (c = 0, tmp = if_names; tmp; tmp = tmp->next)
	if (!tmp->isloop)
	  c++;
      if (c != 1)
	die("must set exactly one interface on broken systems without IP_RECVIF", NULL);
#endif
      dhcp_init(&dhcpfd, &dhcp_raw_fd);
      leasefd = lease_init(lease_file, domain_suffix, dnamebuff, packet, now, maxleases);
    }
  
  setbuf(stdout, NULL);

  if (!(options & OPT_DEBUG))
    {
      FILE *pidfile;
      struct passwd *ent_pw;
      int i;
        
      /* The following code "daemonizes" the process. 
	 See Stevens section 12.4 */

#ifndef NO_FORK
      if (fork() != 0 )
	exit(0);
      
      setsid();
      
      if (fork() != 0)
	exit(0);
#endif
      
      chdir("/");
      umask(022); /* make pidfile 0644 */
      
      /* write pidfile _after_ forking ! */
      if (runfile && (pidfile = fopen(runfile, "w")))
      	{
	  fprintf(pidfile, "%d\n", (int) getpid());
	  fclose(pidfile);
	}
      
      umask(0);

      for (i=0; i<64; i++)
	{
	  for (listener = listeners; listener; listener = listener->next)
	    if (listener->fd == i)
	      break;
	  if (listener)
	    continue;

	  if (i == leasefd || 
	      i == uptime_fd ||
	      i == dhcpfd || 
	      i == dhcp_raw_fd)
	    continue;

	  close(i);
	}

      /* Change uid and gid for security */
      if (username && (ent_pw = getpwnam(username)))
	{
	  gid_t dummy;
	  struct group *gp;
	  /* remove all supplimentary groups */
	  setgroups(0, &dummy);
	  /* change group for /etc/ppp/resolv.conf 
	     otherwise get the group for "nobody" */
	  if ((groupname && (gp = getgrnam(groupname))) || 
	      (gp = getgrgid(ent_pw->pw_gid)))
	    setgid(gp->gr_gid); 
	  /* finally drop root */
	  setuid(ent_pw->pw_uid);
	}
    }

  openlog("dnsmasq", 
	  DNSMASQ_LOG_OPT(options & OPT_DEBUG), 
	  DNSMASQ_LOG_FAC(options & OPT_DEBUG));
  
  if (cachesize)
    syslog(LOG_INFO, "started, version %s cachesize %d", VERSION, cachesize);
  else
    syslog(LOG_INFO, "started, version %s cache disabled", VERSION);
  
  if (bind_fallback)
    syslog(LOG_WARNING, "setting --bind-interfaces option because if OS limitations");
  
  for (dhcp_tmp = dhcp; dhcp_tmp; dhcp_tmp = dhcp_tmp->next)
    {
      strcpy(dnamebuff, inet_ntoa(dhcp_tmp->start));
      if (dhcp_tmp->lease_time == 0)
	sprintf(packet, "infinite");
      else
	sprintf(packet, "%ds", (int)dhcp_tmp->lease_time);
      syslog(LOG_INFO, 
	     dhcp_tmp->start.s_addr == dhcp_tmp->end.s_addr ? 
	     "DHCP, static leases only on %.0s%s, lease time %s" :
	     "DHCP, IP range %s -- %s, lease time %s",
	     dnamebuff, inet_ntoa(dhcp_tmp->end), packet);
    }

#ifdef HAVE_BROKEN_RTC
  if (dhcp)
    syslog(LOG_INFO, "DHCP, %s will be written every %ds", lease_file, min_leasetime/3);
#endif

  if (getuid() == 0 || geteuid() == 0)
    syslog(LOG_WARNING, "failed to drop root privs");
  
  servers = check_servers(serv_addrs, interfaces, &sfds);
  last_server = NULL;

  while (sigterm == 0)
    {
      fd_set rset;
      
      if (sighup)
	{
	  cache_reload(options, dnamebuff, domain_suffix, addn_hosts);
	  if (dhcp)
	    {
	      if (options & OPT_ETHERS)
		dhcp_configs = dhcp_read_ethers(dhcp_configs, dnamebuff);
	      dhcp_update_configs(dhcp_configs);
	      lease_update_from_configs(dhcp_configs, domain_suffix); 
	      lease_update_file(0, now); 
	      lease_update_dns();
	    }
	  if (resolv && (options & OPT_NO_POLL))
	    {
	      servers = check_servers(reload_servers(resolv->name, dnamebuff, servers, query_port), 
				      interfaces, &sfds);
	      last_server = NULL;
	    }
	  sighup = 0;
	}
      
      if (sigusr1)
	{
	  dump_cache(options & (OPT_DEBUG | OPT_LOG), cachesize);
	  sigusr1 = 0;
	}
      
      if (sigalarm)
	{
	  if (dhcp)
	    {
	      lease_update_file(1, now);
#ifdef HAVE_BROKEN_RTC
	      alarm(min_leasetime/3);
#endif
	    } 
	  sigalarm  = 0;
	}
      
      FD_ZERO(&rset);
      
      if (!first_loop)
	{
	  int maxfd = 0;
	  
	  for (serverfdp = sfds; serverfdp; serverfdp = serverfdp->next)
	    {
	      FD_SET(serverfdp->fd, &rset);
	      if (serverfdp->fd > maxfd)
		maxfd = serverfdp->fd;
	    }
	  
	  for (listener = listeners; listener; listener = listener->next)
	    {
	      FD_SET(listener->fd, &rset);
	      if (listener->fd > maxfd)
		maxfd = listener->fd;
	    }
	  
	  if (dhcp)
	    {
	      FD_SET(dhcpfd, &rset);
	      if (dhcpfd > maxfd)
		maxfd = dhcpfd;
	    }

#ifdef HAVE_PSELECT
	  if (pselect(maxfd+1, &rset, NULL, NULL, NULL, &sigmask) < 0)
	    FD_ZERO(&rset); /* rset otherwise undefined after error */ 
#else
	  {
	    sigset_t save_mask;
	    sigprocmask(SIG_SETMASK, &sigmask, &save_mask);
	    if (select(maxfd+1, &rset, NULL, NULL, NULL) < 0)
	      FD_ZERO(&rset); /* rset otherwise undefined after error */ 
	    sigprocmask(SIG_SETMASK, &save_mask, NULL);
	  }
#endif
	  
	}

      first_loop = 0;
      now = dnsmasq_time(uptime_fd);

      /* Check for changes to resolv files once per second max. */
      if (last == 0 || difftime(now, last) > 1.0)
	{
	  last = now;

#ifdef HAVE_ISC_READER
	  if (lease_file && !dhcp)
	    load_dhcp(lease_file, domain_suffix, now, dnamebuff);
#endif

	  if (!(options & OPT_NO_POLL))
	    {
	      struct resolvc *res = resolv, *latest = NULL;
	      struct stat statbuf;
	      time_t last_change = 0;
	      /* There may be more than one possible file. 
		 Go through and find the one which changed _last_.
		 Warn of any which can't be read. */
	      while (res)
		{
		  if (stat(res->name, &statbuf) == -1)
		    {
		      if (!res->logged)
			syslog(LOG_WARNING, "failed to access %s: %m", res->name);
		      res->logged = 1;
		    }
		  else
		    {
		      res->logged = 0;
		      if (difftime(statbuf.st_mtime, last_change) > 0.0)
			{
			  last_change = statbuf.st_mtime;
			  latest = res;
			}
		    }
		  res = res->next;
		}
	  
	      if (latest && difftime(last_change, resolv_changed) > 0.0)
		{
		  resolv_changed = last_change;
		  servers = check_servers(reload_servers(latest->name, dnamebuff, servers, query_port),
					  interfaces, &sfds);
		  last_server = NULL;
		}
	    }
	}
		
      for (serverfdp = sfds; serverfdp; serverfdp = serverfdp->next)
	if (FD_ISSET(serverfdp->fd, &rset))
	  last_server = reply_query(serverfdp, options, packet, now, 
				    dnamebuff, servers, last_server, bogus_addr, doctors);

      if (dhcp && FD_ISSET(dhcpfd, &rset))
	dhcp_packet(dhcp, packet, dhcp_options, dhcp_configs, dhcp_vendors,
		    now, dnamebuff, domain_suffix, dhcp_file,
		    dhcp_sname, dhcp_next_server, dhcpfd, dhcp_raw_fd,
		    if_names, if_addrs, if_except);
      
      for (listener = listeners; listener; listener = listener->next)
	if (FD_ISSET(listener->fd, &rset))
	  last_server = receive_query(listener, packet,
			mxnames, mxtarget, options, now, local_ttl, dnamebuff,
			if_names, if_addrs, if_except, last_server, servers);
    }
  
  syslog(LOG_INFO, "exiting on receipt of SIGTERM");

#ifdef HAVE_BROKEN_RTC
  if (dhcp)
    lease_update_file(1, now);
#endif

  if (leasefd != -1)
    close(leasefd);
  return 0;
}






