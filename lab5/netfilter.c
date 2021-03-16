#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho2;

unsigned int hook_pre_routing_func(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    // Prevent A from doing telnet to Machine B
    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->daddr == in_aton("10.0.2.11"))
    {
        return NF_DROP;
    }

    // Prevent B from doing telnet to Machine A
    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->daddr == in_aton("10.0.2.12"))
    {
        return NF_DROP;
    }

    return NF_ACCEPT; /* Accept other packets */
}
unsigned int hook_post_routing_func(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    // Prevent A from visiting an external web site.
    if (iph->daddr == in_aton("45.60.67.5") || iph->daddr == in_aton("45.60.65.5"))
    {
        return NF_DROP;
    }

    // Prevent A from browsing the web via http (80) and https (443)
    if (iph->protocol == IPPROTO_TCP && (tcph->dest == htons(80) || tcph->dest == htons(443)))
    {
        return NF_DROP;
    }

    // Prevent A from using ssh
    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(22))
    {
        return NF_DROP;
    }

    return NF_ACCEPT; /* Accept other packets */
}

/* Initialization routine */
int init_module()
{                                       /* Fill in our hook structure */
    nfho.hook = hook_pre_routing_func;  /* Handler function */
    nfho.hooknum = NF_INET_PRE_ROUTING; /* First hook for IPv4 */
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST; /* Make our function first */
    nf_register_hook(&nfho);

    nfho2.hook = hook_post_routing_func;  /* Handler function */
    nfho2.hooknum = NF_INET_POST_ROUTING; /* First hook for IPv4 */
    nfho2.pf = PF_INET;
    nfho2.priority = NF_IP_PRI_FIRST; /* Make our function first */
    nf_register_hook(&nfho2);
    return 0;
}

/* Cleanup routine */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
    nf_unregister_hook(&nfho2);
}