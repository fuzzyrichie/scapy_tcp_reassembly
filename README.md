# TCP Reassembly Decorator for Pytthon

Ever wanted to reassemble packets in Scapy while doing a Wireshark parsing or looking at a live network interface capture? I did.

This tool will:
 - Reassemble the stream in the order of parsing sequencing (i.e. the TCP sequence number)
 - Handles re-transmissions of older sequence numbers while showing the delta of data (i.e. not re-processing existing data)
 - Drops spurrious retransmissions and handles future packets by reprocessing them when sequencing returns to normal

This tool does not:
  - Handle connections where data loss happens and never recovers
  - Do well on memory/CPU consumption to reassemble packets (inefficient)

The usage is pretty simple at the moment - we don't support much in terms of features, but we can add more over time. Feel free to contribute ideas or pull requests for this project.

Usage:

```
from scapy.all import sniff
from tcp_reassemble import tcp_reassemble

@tcp_reassemble
def packet_parser(data, pkt):
  print("Looking at seq %d" % pkt.seq)
  print(data)

sniff(prn=packet_parser, filter="tcp and (port 22)")

```

Reach out to me if you have any concerns!

Cheers,
fuzzyrichie
