`socketsnoop` uses the [`sock/inet_sock_set_state`](https://github.com/torvalds/linux/blob/v4.16/include/trace/events/sock.h#L117) tracepoint that was added in
Linux 4.16 to observe changes to TCP/DCCP/SCTP socket states.

NOTE: The `pid`, `comm`, `uid`, and `gid` values are not accurate for all states.

```json
sudo ./socketsnoop
{
  "timestamp": "2018-09-10T22:35:38.104024504Z",
  "id": 18446628942262106000,
  "pid": 3872,
  "comm": "curl",
  "uid": 1000,
  "gid": 1000,
  "source_ip": "10.0.2.15",
  "destination_ip": "172.217.10.228",
  "destination_port": 443,
  "state_old": "CLOSE",
  "state_new": "SYN_SENT",
  "address_family": "INET",
  "network_protocol": "TCP"
}
{
  "timestamp": "2018-09-10T22:35:38.116792423Z",
  "id": 18446628942262106000,
  "pid": 0,
  "comm": "swapper/0",
  "uid": 0,
  "gid": 0,
  "source_ip": "10.0.2.15",
  "destination_ip": "172.217.10.228",
  "source_port": 55426,
  "destination_port": 443,
  "state_old": "SYN_SENT",
  "state_new": "ESTABLISHED",
  "address_family": "INET",
  "network_protocol": "TCP"
}
{
  "timestamp": "2018-09-10T22:35:38.246734901Z",
  "id": 18446628942262106000,
  "pid": 3872,
  "comm": "curl",
  "uid": 1000,
  "gid": 1000,
  "source_ip": "10.0.2.15",
  "destination_ip": "172.217.10.228",
  "source_port": 55426,
  "destination_port": 443,
  "state_old": "ESTABLISHED",
  "state_new": "FIN_WAIT1",
  "address_family": "INET",
  "network_protocol": "TCP"
}
{
  "timestamp": "2018-09-10T22:35:38.246987074Z",
  "id": 18446628942262106000,
  "pid": 3872,
  "comm": "curl",
  "uid": 1000,
  "gid": 1000,
  "source_ip": "10.0.2.15",
  "destination_ip": "172.217.10.228",
  "source_port": 55426,
  "destination_port": 443,
  "state_old": "FIN_WAIT1",
  "state_new": "FIN_WAIT2",
  "address_family": "INET",
  "network_protocol": "TCP"
}
{
  "timestamp": "2018-09-10T22:35:38.247000026Z",
  "id": 18446628942262106000,
  "pid": 3872,
  "comm": "curl",
  "uid": 1000,
  "gid": 1000,
  "source_ip": "10.0.2.15",
  "destination_ip": "172.217.10.228",
  "source_port": 55426,
  "destination_port": 443,
  "state_old": "FIN_WAIT2",
  "state_new": "CLOSE",
  "address_family": "INET",
  "network_protocol": "TCP"
}
```
