# tcp-iw-probe
Recreating the initial TCP congestion window results of
Padhye et. al.'s 2001 paper.

### Installation
This repository is run on the python included in Anaconda 3.
In addition, install_dependencies.sh should be run to install scapy.

### Contents
data/ contains a list of the top 1 million URLs. The user can probe sections
of the URLs in the list or individual ones entered at the command line.
By default the output goes to a timestamped folder inside experiment/.
iw-probe.py parses the arguments, probes the provided IPs,
and processes the output.
util.py contains functions for sending and sniffing packets, calculating
the window size, and calculating the category of the results for each IP.

### Output
Inside the results folder, categories contains a pickle dump of the
category outputs and the IP's associated with each. results.csv contains
the raw results of the probe for each IP, including whether a long request
path needed to be used, the initial window size for each repetition, and the
error code for each repetition.

### Examples
To probe both stanford.edu and google.com:
sudo python iw-probe.py --ip=stanford.edu,google.com

To probe the top 100 most popular URLs with an MSS of 128
sudo python iw-probe.py --low=0 --high=100 --mss=128