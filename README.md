# PAHSV

## Passive Automated Host Scanner and Viewer

This is a simple program that passively monitors a network for hosts and some other information. It is designed to be modular, so scanning modules can be added as needed. It uses Scapy's dissection libraries.

Running `python scanner.py eth0` (or whatever interface you want to use) will passively monitor a network for several revealing types of traffic. If you leave it running long enough, it should be able to identify many of the hosts on the network. It is also possible to `python scanner.py capture.pcap`, reading from an already captured file.

Then, upon running `python viewer.py`, the database is read (not in real time) and all the known info about each host is listed.

This was written as an exercise, and I am already beginning to feel the limitations of Scapy. It does very well with individual packets, but streams and many high-level protocols are almost impossible to dissect easily. I will likely be rewriting this with a wireshark-based library in order to handle the high-level dissection I need in a passive scanner like this.

**Requirements:**

- Python 2.7
- Scapy

Before running for the first time, you need to build the database of mac address vendors:

```
cd analyzers/data
python gendb.py
```
