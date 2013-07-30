/*
 * etherip.c: Ethernet over IPv4 tunnel driver (according to RFC3378)
 *
 * Copyright (C) 2006-2012 Joerg Roedel <joro@8bytes.org>
 *
 * This driver could be used to tunnel Ethernet packets through IPv4
 * networks. This is especially usefull together with the bridging
 * code in Linux.
 *
 * This code was written with an eye on the IPIP driver in linux from
 * Sam Lantinga.
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      version 2 (no later version) as published by the
 *      Free Software Foundation.
 *
 */

#include <linux/version.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/ipip.h>
#include <net/xfrm.h>
#include <net/inet_ecn.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joerg Roedel <joro@8bytes.org>");
MODULE_DESCRIPTION("Ethernet over IPv4 tunnel driver");

#ifndef IPPROTO_ETHERIP
#define IPPROTO_ETHERIP 97
#endif

/*
 * These 2 defines are taken from ipip.c - if it's good enough for them
 * it's good enough for me.
 */
#define HASH_SIZE        16
#define HASH(addr)       ((addr^(addr>>4))&0xF)

#define ETHERIP_HEADER   ((u16)0x0300)
#define ETHERIP_HLEN     2
#define ETHERIP_MAX_MTU  (65535 - 20 - ETHERIP_HLEN)

#define BANNER1 "etherip: Ethernet over IPv4 tunneling driver\n"

struct etherip_tunnel {
	struct etherip_tunnel __rcu *next;
	struct net_device *dev;
	struct net_device_stats stats;
	struct ip_tunnel_parm parms;
};

static int etherip_net_id __read_mostly;

struct etherip_net {
	struct etherip_tunnel __rcu *tunnels[HASH_SIZE];
	struct net_device *etherip_tunnel_dev;
};

#define for_each_ethip_tunnel_rcu(it, start) \
        for (it = rcu_dereference(start); it; it = rcu_dereference(it->next))

static void etherip_tunnel_setup(struct net_device *dev);

/* add a tunnel to the hash */
static void etherip_tunnel_add(struct etherip_net *ethip_net,
			       struct etherip_tunnel *tun)
{
	unsigned h = HASH(tun->parms.iph.daddr);
	struct etherip_tunnel __rcu **tunnel;

	tunnel = &ethip_net->tunnels[h];

	rcu_assign_pointer(tun->next, rtnl_dereference(*tunnel));
	rcu_assign_pointer(*tunnel, tun);
}

/* delete a tunnel from the hash*/
static void etherip_tunnel_del(struct etherip_net *ethip_net,
			       struct etherip_tunnel *tun)
{
	unsigned h = HASH(tun->parms.iph.daddr);
	struct etherip_tunnel __rcu **tunnel;
	struct etherip_tunnel *iter;

	tunnel = &ethip_net->tunnels[h];

	iter = rtnl_dereference(*tunnel);
	while (iter != NULL) {
		if (tun == iter) {
			rcu_assign_pointer(*tunnel, iter->next);
			break;
		}
		tunnel = &iter->next;
		iter = rtnl_dereference(*tunnel);
	}
}

/* find a tunnel by its destination address */
static struct etherip_tunnel* etherip_tunnel_locate(struct net *net,
						    u32 remote)
{
	struct etherip_net *ethip_net = net_generic(net, etherip_net_id);
	struct etherip_tunnel *ret;
	unsigned h = HASH(remote);

	for_each_ethip_tunnel_rcu(ret, ethip_net->tunnels[h])
		if (ret->parms.iph.daddr == remote)
			return ret;

	return NULL;
}

/* find a tunnel in the hash by parameters from userspace */
static struct etherip_tunnel* etherip_tunnel_find(struct net *net,
						  struct ip_tunnel_parm *p,
						  int create)
{
	struct etherip_net *ethip_net;
	struct etherip_tunnel *tun;
	char dev_name[IFNAMSIZ];
	struct net_device *dev;
	int err;

	ethip_net = net_generic(net, etherip_net_id);

	tun = etherip_tunnel_locate(net, p->iph.daddr);
	if (tun != NULL)
		return tun;

	if (!create)
		return NULL;

	if (p->name[0])
		strlcpy(dev_name, p->name, IFNAMSIZ);
	else
		strcpy(dev_name, "ethip%d");

	dev = alloc_netdev(sizeof(struct etherip_tunnel), dev_name,
			   etherip_tunnel_setup);

	if (dev == NULL)
		goto err_out;

	dev->tstats = alloc_percpu(struct pcpu_tstats);
	if (!dev->tstats)
		goto err_free_netdev;

	dev_net_set(dev, net);

	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto err_free_percpu;
	}

	strncpy(p->name, dev->name, IFNAMSIZ);
	tun        = netdev_priv(dev);
	tun->dev   = dev;
	tun->parms = *p;

	err = register_netdevice(dev);
	if (err < 0)
		goto err_free_percpu;

	dev_hold(dev);

	etherip_tunnel_add(ethip_net, tun);

	return tun;

err_free_percpu:
	free_percpu(dev->tstats);

err_free_netdev:
	free_netdev(dev);

err_out:
	return NULL;
}

static void etherip_tunnel_uninit(struct net_device *dev)
{
	struct etherip_net *ethip_net;

	ethip_net = net_generic(dev_net(dev), etherip_net_id);

	if (dev != ethip_net->etherip_tunnel_dev)
		etherip_tunnel_del(ethip_net, netdev_priv(dev));

	dev_put(dev);
}

static int etherip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct etherip_tunnel *tunnel = netdev_priv(dev);
	struct rtable *rt;
	struct iphdr *iph;
	struct net_device *tdev;
	int max_headroom;
	struct flowi4 fl4;

	rt = ip_route_output_ports(dev_net(dev), &fl4, NULL,
				   tunnel->parms.iph.daddr,
				   tunnel->parms.iph.saddr,
				   0, 0, IPPROTO_ETHERIP,
				   RT_TOS(tunnel->parms.iph.tos),
				   tunnel->parms.link);
	if (IS_ERR(rt)) {
		dev->stats.tx_carrier_errors++;
		goto tx_error_icmp;
	}

	tdev = rt->dst.dev;
	if (tdev == dev) {
		ip_rt_put(rt);
		tunnel->stats.collisions++;
		goto tx_error;
	}

	max_headroom = (LL_RESERVED_SPACE(tdev)+sizeof(struct iphdr)
			+ ETHERIP_HLEN);

	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *skn = skb_realloc_headroom(skb, max_headroom);
		if (!skn) {
			ip_rt_put(rt);
			dev->stats.tx_dropped++;
			dev_kfree_skb(skb);
			tunnel->stats.tx_dropped++;
			return 0;
		}
		if (skb->sk)
			skb_set_owner_w(skn, skb->sk);
		dev_kfree_skb(skb);
		skb = skn;
	}

	skb->transport_header = skb->mac_header;
	skb_push(skb, sizeof(struct iphdr)+ETHERIP_HLEN);
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			IPSKB_REROUTED);

	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);

	/* Build the IP header for the outgoing packet
	 *
	 * Note: This driver never sets the DF flag on outgoing packets
	 *       to ensure that the tunnel provides the full Ethernet MTU.
	 *       This behavior guarantees that protocols can be
	 *       encapsulated within the Ethernet packet which do not
	 *       know the concept of a path MTU
	 */
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr)>>2;
	iph->frag_off = 0;
	iph->protocol = IPPROTO_ETHERIP;
	iph->tos = tunnel->parms.iph.tos & INET_ECN_MASK;
	iph->daddr = fl4.daddr;
	iph->saddr = fl4.saddr;
	iph->ttl = tunnel->parms.iph.ttl;
	if (iph->ttl == 0)
		iph->ttl = 64;

	/* add the 16bit etherip header after the ip header */
	((u16*)(iph+1))[0]=htons(ETHERIP_HEADER);
	iptunnel_xmit(skb, dev);

	return NETDEV_TX_OK;

tx_error_icmp:
	dst_link_failure(skb);

tx_error:
	tunnel->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int etherip_tunnel_ioctl(struct net_device *dev,
				struct ifreq *ifr,
				int cmd)
{
	struct net *net = dev_net(dev);
	struct etherip_net *ethip_net;
	struct etherip_tunnel *t;
	struct ip_tunnel_parm p;
	int err = 0;

	ethip_net = net_generic(net, etherip_net_id);

	switch (cmd) {
	case SIOCGETTUNNEL:
		t = netdev_priv(dev);
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &t->parms,
				sizeof(t->parms)))
			err = -EFAULT;
		break;
	case SIOCADDTUNNEL:
		err = -EINVAL;
		if (dev != ethip_net->etherip_tunnel_dev)
			goto out;

	case SIOCCHGTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto out;

		err = -EFAULT;
		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data,
					sizeof(p)))
			goto out;
		p.i_flags = p.o_flags = 0;

		err = -EINVAL;
		if (p.iph.version != 4 ||
		    p.iph.protocol != IPPROTO_ETHERIP ||
		    p.iph.ihl != 5 ||
		    p.iph.daddr == INADDR_ANY ||
		    IN_MULTICAST(p.iph.daddr))
			goto out;

		t = etherip_tunnel_find(net, &p, cmd == SIOCADDTUNNEL);

		if (cmd == SIOCCHGTUNNEL) {
			err = -EEXIST;
			if (t != NULL && t->dev != dev)
				goto out;
			t = netdev_priv(dev);
			etherip_tunnel_del(ethip_net, t);
			synchronize_net();
			t->parms.iph.saddr = p.iph.saddr;
			t->parms.iph.daddr = p.iph.daddr;
			t->parms.iph.ttl   = p.iph.ttl;
			t->parms.iph.tos   = p.iph.tos;
			etherip_tunnel_add(ethip_net, t);
			netdev_state_change(dev);
		}

		if (t != NULL) {
			err = -EFAULT;
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &p,
						sizeof(p)))
				goto out;
		} else
			err = (cmd == SIOCADDTUNNEL ? -ENOBUFS : -ENOENT);

		err = 0;
		break;

	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto out;

		err = -EFAULT;
		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data,
					sizeof(p)))
			goto out;

		err = -EINVAL;
		if (dev == ethip_net->etherip_tunnel_dev) {
			t = etherip_tunnel_find(net, &p, 0);
			if (t == NULL) {
				goto out;
			}
		} else
			t = netdev_priv(dev);

		unregister_netdevice(t->dev);
		err = 0;

		break;
	default:
		err = -EINVAL;
	}

out:
	return err;
}

static int etherip_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < 68 || new_mtu > ETHERIP_MAX_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;

	return 0;
}

static struct rtnl_link_stats64 *etherip_get_stats64(struct net_device *dev,
					struct rtnl_link_stats64 *tot)
{
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_tstats *tstats = per_cpu_ptr(dev->tstats, i);
		u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_bh(&tstats->syncp);
			rx_packets = tstats->rx_packets;
			rx_bytes   = tstats->rx_bytes;
			tx_packets = tstats->tx_packets;
			tx_bytes   = tstats->tx_bytes;
		} while (u64_stats_fetch_retry_bh(&tstats->syncp, start));

		tot->rx_packets += rx_packets;
		tot->rx_bytes   += rx_bytes;
		tot->tx_packets += tx_packets;
		tot->tx_bytes   += tx_bytes;
	}

        tot->tx_fifo_errors	= dev->stats.tx_fifo_errors;
        tot->tx_carrier_errors	= dev->stats.tx_carrier_errors;
        tot->tx_dropped		= dev->stats.tx_dropped;
        tot->tx_aborted_errors	= dev->stats.tx_aborted_errors;
        tot->tx_errors		= dev->stats.tx_errors;
        tot->collisions		= dev->stats.collisions;

	return tot;
}

static int etherip_set_mac_address(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return 0;
}

static const struct net_device_ops etherip_netdev_ops = {
	.ndo_uninit	     = etherip_tunnel_uninit,
	.ndo_start_xmit      = etherip_tunnel_xmit,
	.ndo_do_ioctl        = etherip_tunnel_ioctl,
	.ndo_change_mtu      = etherip_change_mtu,
	.ndo_get_stats64     = etherip_get_stats64,
	.ndo_set_mac_address = etherip_set_mac_address

};

static void free_etheripdev(struct net_device *dev)
{
	free_percpu(dev->tstats);
	free_netdev(dev);
}

static void etherip_tunnel_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops      = &etherip_netdev_ops;
	dev->destructor      = free_etheripdev;
	dev->mtu             = ETH_DATA_LEN;
	dev->hard_header_len = LL_MAX_HEADER + sizeof(struct iphdr) + ETHERIP_HLEN;
	random_ether_addr(dev->dev_addr);
}

static int etherip_rcv(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct etherip_tunnel *tunnel;
	struct net_device *dev;

	iph = ip_hdr(skb);

	rcu_read_lock();
	tunnel = etherip_tunnel_locate(dev_net(skb->dev), iph->saddr);
	if (tunnel == NULL)
		goto drop;

	dev = tunnel->dev;
	secpath_reset(skb);
	skb_pull(skb, (skb_network_header(skb)-skb->data) +
			sizeof(struct iphdr)+ETHERIP_HLEN);

	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, tunnel->dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	__skb_tunnel_rx(skb, dev);
	skb_dst_drop(skb);

	/* do some checks */
	if (skb->pkt_type == PACKET_HOST || skb->pkt_type == PACKET_BROADCAST)
		goto accept;

	if (skb->pkt_type == PACKET_MULTICAST &&
			(dev->mc.count > 0 || dev->flags & IFF_ALLMULTI))
		goto accept;

	if (skb->pkt_type == PACKET_OTHERHOST && dev->flags & IFF_PROMISC)
		goto accept;

drop:
	kfree_skb(skb);
	rcu_read_unlock();

	return 0;

accept:
	tunnel->dev->last_rx = jiffies;
	tunnel->stats.rx_packets++;
	tunnel->stats.rx_bytes += skb->len;
	nf_reset(skb);
	netif_rx(skb);
	rcu_read_unlock();

	return 0;

}

/* destroy all tunnels for one struct net */
static void __exit etherip_destroy_tunnels(struct etherip_net *ethip_net,
					   struct list_head *list)
{
	int i;

	for (i = 0; i < HASH_SIZE; ++i) {
		struct etherip_tunnel *tunnel;

		tunnel = rtnl_dereference(ethip_net->tunnels[i]);
		while (tunnel != NULL) {
			unregister_netdevice_queue(tunnel->dev, list);
			tunnel = rtnl_dereference(tunnel->next);
		}
	}
}

static int __net_init etherip_init_net(struct net *net)
{
	struct etherip_net *ethip_net = net_generic(net, etherip_net_id);
	struct etherip_tunnel *tunnel;
	struct net_device *fb;
	int err;

	err = -ENOMEM;
	fb = alloc_netdev(sizeof(struct etherip_tunnel), "ethip0",
			  etherip_tunnel_setup);

	if (fb == NULL)
		goto err_out;

	dev_net_set(fb, net);

	fb->tstats = alloc_percpu(struct pcpu_tstats);
	if (!fb->tstats)
		goto err_free_netdev;

	tunnel      = netdev_priv(fb);
	tunnel->dev = fb;

	/* set some params for iproute2 */
	strcpy(tunnel->parms.name, "ethip0");
	tunnel->parms.iph.protocol = IPPROTO_ETHERIP;

	dev_hold(fb);

	if ((err = register_netdev(fb)))
		goto err_free_per_cpu;

	ethip_net->etherip_tunnel_dev = fb;

	return 0;

err_free_per_cpu:
	free_percpu(fb->tstats);

err_free_netdev:
	free_netdev(fb);

err_out:
	return err;
}

static void __net_exit etherip_exit_net(struct net *net)
{
	struct etherip_net *ethip_net = net_generic(net, etherip_net_id);
	LIST_HEAD(list);

	rtnl_lock();
	etherip_destroy_tunnels(ethip_net, &list);
	unregister_netdevice_queue(ethip_net->etherip_tunnel_dev, &list);
	unregister_netdevice_many(&list);
	rtnl_unlock();

}

static struct pernet_operations etherip_net_ops = {
	.init = etherip_init_net,
	.exit = etherip_exit_net,
	.id   = &etherip_net_id,
	.size = sizeof(struct etherip_net),
};

static struct net_protocol etherip_protocol = {
	.handler      = etherip_rcv,
	.err_handler  = 0,
	.no_policy    = 0,
};

static int __init etherip_init(void)
{
	int err;

	printk(KERN_INFO BANNER1);

	err = register_pernet_device(&etherip_net_ops);
	if (err)
		goto err_out;

	err = -EBUSY;
	if (inet_add_protocol(&etherip_protocol, IPPROTO_ETHERIP)) {
		printk(KERN_ERR "etherip: can't add protocol\n");
		goto err_unregister_pernet;
	}

	return 0;

err_unregister_pernet:
	unregister_pernet_device(&etherip_net_ops);

err_out:
	return err;
}

static void __exit etherip_exit(void)
{
	if (inet_del_protocol(&etherip_protocol, IPPROTO_ETHERIP))
		printk(KERN_ERR "etherip: can't remove protocol\n");

	unregister_pernet_device(&etherip_net_ops);
}

module_init(etherip_init);
module_exit(etherip_exit);
