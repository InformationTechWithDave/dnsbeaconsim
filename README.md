# dnsbeaconsim
DNS Beacon Simulator with HTML Dashboard

DNS beaconing is a technique commonly used by malware and attackers to maintain command and control (C2) communications with infected systems while evading detection.

The basic mechanism is that a compromised host makes periodic DNS queries to attacker-controlled domains at regular intervals. These DNS queries often contain encoded data (exfiltrated information or status updates) in subdomains, TXT records, or other DNS fields. The DNS responses can contain encoded commands or instructions for the malware to execute.

Malware that uses DNS beaconing has some advantages when it comes to evading detection.
For example, DNS traffic is typically allowed through firewalls, communications blend with legitimate DNS traffic, and it can bypass HTTP proxies and content filters.

For my own professional education, I was wondering if I would be able to create a DNS beaconing simulator so I could practice detection. Since I'm not a coder, I also wanted to see if I could an AI tool to create the simulator in Python. Sure enough, with the help of Claude.ai, I was able to build and debug a Python 3 script that's 810 lines that simulates DNS beaconing and provides the user with a dashboard to view the output in a web browser.

The script wasn't perfect in the first iteration and I kept getting an error about a global declaration being out of order. However, going back and forth with the AI allowed me to troubleshoot and fix it so that it runs properly on my MacBook running macOS 15.4 Sequoia.

To run the script save it to your machine, open a terminal in the directory with it, and enter the following command:

% python3 dns-beacon-dashboard.py example.com -i 5 -j 2

This runs the simulator with a 5 second interval between beacons, +/- 2 seconds of random jitter. It will also open a web browser window or tab to display the dashboard. To stop the script either click the Stop Simulation button on the dashboard, or do CTRL-C in the terminal.
