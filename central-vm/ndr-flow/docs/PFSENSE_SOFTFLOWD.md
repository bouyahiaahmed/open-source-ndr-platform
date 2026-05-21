# pfSense softflowd quick config

In pfSense UI:

```text
System → Package Manager → Available Packages → softflowd → Install
Services → softflowd
```

Use:

```text
Enable softflowd: Enabled
Interface: WAN
Host: <hub-ip>
Port: 2055
Sample: 0
Max Flows: 8192
NetFlow version: 9
```

Generate traffic from pfSense shell:

```sh
ping -c 5 8.8.8.8
fetch -o /dev/null https://example.com
```

Force export:

```sh
ls /var/run/softflowd*
softflowctl -c /var/run/softflowd.WAN.ctl expire-all
```

On hub, confirm UDP arrives:

```bash
sudo tcpdump -ni any udp port 2055
```
