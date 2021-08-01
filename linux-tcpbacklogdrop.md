### this is just a tmp doc.

### Get more information about the drop
#### 1. find the code line that increment `LINUX_MIB_TCPBACKLOGDROP` metric
```
1740     if (!sock_owned_by_user(sk)) {
1741         if (!tcp_prequeue(sk, skb))
1742             ret = tcp_v4_do_rcv(sk, skb);
1743     } else if (unlikely(sk_add_backlog(sk, skb,
1744                        sk->sk_rcvbuf + sk->sk_sndbuf))) {
1745         bh_unlock_sock(sk);
1746         NET_INC_STATS_BH(net, LINUX_MIB_TCPBACKLOGDROP);
1747         goto discard_and_relse;
1748     }
```
#### 2. use systemtap statement probe to probe for the  drop location
```
stap -L 'kernel.statement("tcp_v4_rcv@*:*")'
....
kernel.statement("tcp_v4_rcv@net/ipv4/tcp_ipv4.c:1742") $skb:struct sk_buff* $sk:struct sock* $ret:int
kernel.statement("tcp_v4_rcv@net/ipv4/tcp_ipv4.c:1743") $skb:struct sk_buff* $sk:struct sock* $ret:int
kernel.statement("tcp_v4_rcv@net/ipv4/tcp_ipv4.c:1746") $pao_ID__:int const $skb:struct sk_buff* $sk:struct sock* $ret:int
...
```
Then we may place a probe at line 1746, here is the tcpbacklogdrop.stp
```
# script: tcpbacklogdrop.stp
function sock_rmem_alloc:long (sk:long) %{/* pure */
    struct sock* s = (struct sock*)STAP_ARG_sk;
    STAP_RETVALUE = s->sk_backlog.rmem_alloc.counter;
%}

function sock_backlog_len:long (sk:long) %{/* pure */
    struct sock* s = (struct sock*)STAP_ARG_sk;
    STAP_RETVALUE = s->sk_backlog.len;
%}

probe kernel.statement("tcp_v4_rcv@net/ipv4/tcp_ipv4.c:1746") {
   backlog_len = sock_backlog_len($sk)
   rmem_alloc = sock_rmem_alloc($sk)
   lmt = $sk->sk_rcvbuf + $sk->sk_sndbuf;
   saddr   = format_ipaddr(__ip_sock_saddr($sk), __ip_sock_family($sk));
   daddr   = format_ipaddr(__ip_sock_daddr($sk), __ip_sock_family($sk));
   sport   = __tcp_sock_sport($sk);
   dport   = __tcp_sock_dport($sk);
   printf("[%d] %s:%d<=>%s:%d\tsk_rcvbuf:%d sk_sndbuf:%d sk_backlog.len:%d sk_rmem_alloc:%d rcvq_full:%d\n",  gettimeofday_s(),
           saddr, sport, daddr, dport,
           $sk->sk_rcvbuf, $sk->sk_sndbuf,
           backlog_len, rmem_alloc, backlog_len + rmem_alloc > lmt);
}
```
here's the output:
```
[1627803919] 172.16.16.25:8888<=>172.16.16.20:57348	sk_rcvbuf:67108864 sk_sndbuf:46080 sk_backlog.len:3270400 sk_rmem_alloc:64025856 rcvq_full:1
[1627803919] 172.16.16.25:8888<=>172.16.16.20:57348	sk_rcvbuf:67108864 sk_sndbuf:46080 sk_backlog.len:3270400 sk_rmem_alloc:64025856 rcvq_full:1
[1627803919] 172.16.16.25:8888<=>172.16.16.20:57348	sk_rcvbuf:67108864 sk_sndbuf:46080 sk_backlog.len:5503744 sk_rmem_alloc:61758464 rcvq_full:1
[1627803920] 172.16.16.25:8888<=>172.16.16.20:57348	sk_rcvbuf:67108864 sk_sndbuf:46080 sk_backlog.len:2286080 sk_rmem_alloc:65022720 rcvq_full:1
[1627803920] 172.16.16.25:8888<=>172.16.16.20:57348	sk_rcvbuf:67108864 sk_sndbuf:46080 sk_backlog.len:2286080 sk_rmem_alloc:65022720 rcvq_full:1
```
so, it's really full, even with rcvbuf set to 67108864(64M).
how ever, if I call setsockopt manually to set SO_RCVBUF to 8M, there's no more backlogdrop..., need more time to dig the cause.

