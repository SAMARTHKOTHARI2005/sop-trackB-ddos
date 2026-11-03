# What I would do in week 2

In week 2 I would remove the biggest limitation, the per-flow CSV. I would download the
CIC-IDS2017 pcaps and use scapy or tshark to compute real first-k-packet features for
k = 2 … 10: header fields, packet sizes, inter-arrival times and flags seen so far. Then I
can measure how precision and recall grow with k, which is the actual trade-off a switch
faces. All evaluation would be cross-day (train on one day, test on another, and swap),
because this week showed that a random within-day split mostly measures the attack tool's
TCP fingerprint and that its cross-day result depends on the seed. To catch slow attacks
such as slowloris and Slowhttptest, I would add per-source-IP state that a switch can keep
in registers: concurrent open or half-open connections per source, time since the last
packet, and bytes per second per flow over a time window. Finally, I would compile the best
shallow tree into P4 match-action entries (range or ternary matches per feature, one action
per leaf) on BMv2 and replay the pcaps through a Mininet topology. That would check that the
rules fit in the tables and still give the offline accuracy at line rate. If time allows, I
would connect this to my earlier ResilientDAG work: slow and low-rate attacks, like low-rate
censorship, look valid at every single step but break liveness globally. That suggests
detectors should reason about progress over time, not single packets.
