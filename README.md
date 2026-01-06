# Wireshark-detecting-network-anomalies

**Problem Scenario:** IT team observes an unusual spikes in network traffic.    
**Approach to Solving the problem:** 
1. Capturing traffic using Wireshark.
2. Analyzing the data for suspicious patterns and anomalies.
3. Documenting the findings and recommending mitigation strategies.

## Method of Network Anomaly Detection

Filtering is a critical step in network analysis because it narrows down traffic to only the most relevant and high‑priority data. This significantly reduces the time required to identify suspicious behavior.

When investigating unusual traffic patterns, analysts typically begin with broad filters to understand overall activity and then progressively narrow the scope. Common areas of focus include:
- Identifying verified connections to specific domains
- Detecting malformed packets
- Checking for unusual or high‑risk ports
- Investigating potential SYN flood attacks
- Reviewing traffic timelines and communication patterns using Wireshark’s built‑in analysis tools

## Examples of Common Wireshark Filters
**Filtering by Host**
To isolate traffic associated with a specific domain, a filter such as the following is used:  
`http.host contains "adobe.com"`  
This typically returns only the relevant traffic logs for that domain, eliminating the need to manually sift through unrelated packets.

**Detecting Malformed Packets**
Malformed packets may indicate attempts to exploit vulnerabilities or disrupt the system. A common filter is:  
`frame.len < 60`  
This identifies unusually small packets that may be part of malicious probing.

**Identifying Unusual Ports or Protocols**
To focus on non‑standard protocols, common ones such as HTTP and DNS are excluded:  
`!http && !dns`  
Ports known for malicious use can also be searched for, such as port 4444, which is often associated with backdoor activity.

**Detecting SYN Flood Attacks**
A SYN flood attack is typically identified using:  
`tcp.flags.syn == 1 && tcp.flags.ack == 0`  
A large number of SYN requests without corresponding ACK responses suggests an attempted SYN flood. This pattern often appears as multiple source IPs targeting the same destination IP.
Wireshark’s I/O Graphs can then be used to visualize packet spikes over time, while the Conversations feature helps reveal suspicious communication patterns.

## How I performed Traffic aAalysis and Investigation
After loading the `.pcapng` file, I began by selecting the appropriate network interface and applying broad filters such as http and dns. I saved these filtered results into separate .pcapng files to analyze them individually.

I then checked for malformed packets using:  
`tcp.len < 59`  
This revealed a long list of small packets arriving within milliseconds of each other, indicating rapid transmission of malformed traffic. Next, I investigated the possibility of a SYN flood attack. Using the SYN/ACK filter, I found a large number of SYN requests with no ACK responses, confirming suspicious behavior.

I also checked for unusual ports and specifically searched for port 4444, which is commonly used for backdoor access in Metasploit. Using:  
`tcp.port == 4444`  
I found a traffic log attempting to communicate through this port.
Based on these findings (malformed packets, SYN flood patterns, and attempts to access a high‑risk port) the traffic was concluded to be part of a SYN flood attack.

## Mitigation Strategies
To reduce the risk of such attacks, here are some strategies I recommend:  
**1. Deploy Intrusion Detection Systems (IDS) and Firewalls:**   
Properly configured rules can automatically detect and block suspicious traffic before it reaches critical systems.  
**2. Enable SYN Cookies:**  
SYN cookies help protect servers by ensuring that system resources are not allocated until the TCP handshake is fully completed, reducing the impact of SYN flood attempts.
