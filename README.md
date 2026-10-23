<div align="center">

# 🛡️ NetPurity

**A local DNS traffic monitor that flags anomalous domains and sends real-time alerts to Discord.**

[Features](#-features) · [Install](#-install) · [Usage](#-usage) · [How it works](#-how-it-works) · [Limitations](#-limitations) · [Troubleshooting](#-troubleshooting)

</div>

NetPurity watches DNS queries on a network interface you choose, scores each domain, and posts an alert to a Discord webhook when something looks wrong. Use it on networks you own or administer.

## ✨ Features

- 🔍 **Live DNS sniffing** with scapy and the BPF filter `udp port <port>`, for IPv4 and IPv6.
- 🧮 **Entropy scoring** that catches random-looking, algorithm-generated labels.
- 🚩 **Suspicious TLD checks** for `.tk`, `.xyz`, `.top`, `.gq`, `.ml`, `.cf` and `.ga`.
- ⛔ **Blacklist matching** from a plain text file.
- 📡 **Beaconing detection** with a sliding window per source and domain.
- 🔕 **Alert cooldown** so one finding does not repeat on each packet.
- 💬 **Discord embeds** with a color for each severity.
- 🔒 **Careful secret handling**: the webhook comes from an environment variable, the logs redact its token, and alerts cannot ping `@everyone`.

## 🎯 What it detects

| | Reason | Trigger | Severity |
|---|---|---|---|
| 🔴 | `BLACKLISTED` | The queried domain matches an entry in your blacklist file. | critical |
| 🟠 | `BEACONING` | One source queries the same domain at least `--beacon-threshold` times inside `--beacon-window` seconds. | high |
| 🟡 | `HIGH_ENTROPY` | The label left of the TLD has at least 12 characters and an entropy of at least `--entropy-threshold` bits per character. | medium |
| 🔵 | `SUSPICIOUS_TLD` | The domain ends in one of the suspicious TLDs above. | low |

Entropy cannot exceed log2 of the label length, so a label needs at least 14 characters to reach the default threshold of 3.8.

After a finding fires, NetPurity stays quiet about the same (source IP, domain, reason) combination for `--cooldown` seconds. Memory stays bounded: each beaconing window holds at most `--beacon-threshold` timestamps, and NetPurity sweeps out idle windows and expired cooldowns.

## 📦 Install

NetPurity needs Python 3.9 or newer. The author tested it on Linux with Python 3.13.

```bash
git clone https://github.com/USERNAME/netpurity.git
cd netpurity
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Replace `USERNAME` with the account that hosts the repository. Fish users activate with `source .venv/bin/activate.fish`.

## 🚀 Usage

Create a Discord webhook (Server Settings, Integrations, Webhooks) and store its URL in the `NETPURITY_WEBHOOK_URL` environment variable. Prefer the variable over the `--webhook` flag: other local users can read command-line arguments.

```bash
# bash or zsh
read -rs NETPURITY_WEBHOOK_URL; echo
export NETPURITY_WEBHOOK_URL
```

```fish
# fish
read -s -x -g NETPURITY_WEBHOOK_URL
```

```powershell
# PowerShell
$env:NETPURITY_WEBHOOK_URL = Read-Host "Webhook URL"
```

Run `read` on its own line and paste the URL when the terminal waits for input. Treat the URL as a password: anyone who holds it can post to your channel.

Sniffing needs root. `sudo` drops your environment, so pass the variable through and call the executable by its full path:

```bash
sudo env NETPURITY_WEBHOOK_URL="$NETPURITY_WEBHOOK_URL" \
  .venv/bin/netpurity start --interface eth0
```

On Windows, install [Npcap](https://npcap.com) and run the terminal as Administrator.

Find the interface that carries your DNS traffic. On Linux, `ip route get 1.1.1.1` prints it after the word `dev`.

### ⚙️ Options

| Option | Default | Meaning |
|---|---|---|
| `--interface` | required | Network interface to sniff, such as `eth0`. |
| `--webhook` | env `NETPURITY_WEBHOOK_URL` | Discord webhook URL. |
| `--entropy-threshold` | `3.8` | Minimum label entropy (bits per character) that flags a domain. |
| `--port` | `53` | UDP port to sniff for DNS traffic. |
| `--blacklist-file` | none | Text file with one blacklisted domain per line. A `#` starts a comment. |
| `--beacon-threshold` | `20` | Queries from one source to one domain per window that count as beaconing. |
| `--beacon-window` | `60` | Beaconing window length in seconds. |
| `--cooldown` | `300` | Minimum seconds between two reports of the same finding. |

Press Ctrl+C to stop.

### 📋 Output

Each finding prints one console line and sends one Discord embed with the fields Source IP, Domain, Entropy Score, Reason and Timestamp (UTC).

```
[2026-10-23T08:24:07Z] HIGH_ENTROPY   src=192.168.1.5 domain=x7k2m9qz4w8jp3vn5b.com entropy=4.17 | Label 'x7k2m9qz4w8jp3vn5b' has entropy 4.17 bits/char (threshold 3.8, length 18)
```

The matching Discord embed:

```
🟡 DNS alert: HIGH_ENTROPY
Label 'x7k2m9qz4w8jp3vn5b' has entropy 4.17 bits/char (threshold 3.8, length 18)

Source IP     Domain                   Entropy Score
192.168.1.5   x7k2m9qz4w8jp3vn5b.com   4.170

Reason        Timestamp
HIGH_ENTROPY  2026-10-23T08:24:07Z

Severity: medium
```

## 🧪 Try it

Start the monitor with a low beacon threshold, then send queries from a second terminal. Address each query to `1.1.1.1` with `@1.1.1.1` so the packets cross the interface you monitor.

```bash
sudo env NETPURITY_WEBHOOK_URL="$NETPURITY_WEBHOOK_URL" \
  .venv/bin/netpurity start --interface eth0 --beacon-threshold 5 --cooldown 30
```

```bash
dig @1.1.1.1 example.tk
dig @1.1.1.1 x7k2m9qz4w8jp3vn5b.com
for i in $(seq 8); do dig @1.1.1.1 beacon.example.com +short; sleep 1; done
```

You get a `SUSPICIOUS_TLD` alert, a `HIGH_ENTROPY` alert, and a `BEACONING` alert on the fifth query. The domains do not need to exist: the query itself triggers the rule.

## 🧠 How it works

```
UDP port 53 -> sniffer -> analyzer -> console + Discord notifier
```

| Module | Role |
|---|---|
| `netpurity/sniffer.py` | Captures DNS queries (qr=0) for IPv4 and IPv6 and skips malformed packets. |
| `netpurity/analyzer.py` | Applies the four rules, tracks sliding windows, and enforces the cooldown. |
| `netpurity/notifier.py` | Posts embeds, retries once on HTTP 429, logs network errors, and redacts the webhook token. |
| `netpurity/main.py` | Typer command line that connects the three. |
| `netpurity/utils.py` | Entropy, domain parsing, timestamps and text cleaning. |

## ⚠️ Limitations

- The notifier sends each alert from inside the capture callback. A Discord rate limit or timeout pauses packet processing for tens of seconds, so a flood of findings can make NetPurity miss packets.
- NetPurity reads DNS over UDP. It cannot see DNS over TCP, DNS over HTTPS or DNS over TLS.
- It inspects the first question of each packet.
- Legitimate domains can trip the rules: CDNs with random-looking names, and apps that poll one host often. Tune `--entropy-threshold` and `--beacon-threshold` for your network.
- The label extraction knows common two-part suffixes such as `co.uk`, and it does not ship the full public suffix list.

## 🩺 Troubleshooting

| Symptom | Fix |
|---|---|
| `Insufficient privileges` | Run with `sudo`, or as Administrator on Windows. |
| `Network interface 'NAME' does not exist` | The message lists the available interfaces. Pick one of them. |
| `Errno 97 Address family not supported by protocol` | The terminal runs inside a sandbox such as Flatpak, which blocks the packet sockets scapy needs. Run NetPurity from a terminal outside the sandbox. |
| No alerts appear | The monitor listens on an interface that does not carry the queries. Check it with `ip route get 1.1.1.1`. |
| `Invalid value for '--webhook'` | Copy the full URL, which starts with `https://`. |

## 🛠️ Development

```bash
pip install -e ".[dev]"
pytest -q
```

The tests open no sockets and make no network calls.

## 📜 License

MIT. See [LICENSE](LICENSE).
