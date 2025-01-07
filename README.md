# Intrusion-Detection

Task 1 Introduction

This room will serve as an introduction to the world of intrusion detection systems (IDS) and cyber evasion techniques. To complete this room, you will need to orchestrate a full system takeover whilst experimenting with evasion techniques from all stages of the cyber kill chain.

Task 2 Intrusion Detection Basics

Signature (or rule) based IDS will apply a large rule set to search one or more data sources for suspicious activity whereas

Anomaly-based IDS establish what is considered normal activity and then raise alerts when an activity that does not fit the baseline is detected.

What IDS detection methodology relies on rule sets?

```
 Signature Based Detection
```

Two signature-based IDS are attached to this demo; Suricata, a network-based IDS (NIDS), and Wazuh, a host-based IDS (HIDS). Both of these IDS implement the same overarching signature detection methodology; however, their overall behaviour and the types of attacks that they can detect differ greatly. We will cover the exact differences in more detail in the following tasks.

Task 3 Network-based IDS (NIDS)

NIDS monitor networks for malicious activity by checking packets for traces of activity associated with a wide variety of hostile or unwanted activity including:

Malware command and control
Exploitation tools
Scanning
Data exfiltration
Contact with phishing sites
Corporate policy violations

NIDS are more prone to generating false positives than other IDS, this is partly due to the sheer volume of traffic that passes through even a small network and, the difficulty of building a rule set that is flexible enough to reliably detect malicious traffic without detecting safe applications that may leave similar traces.

TLS (Transport Layer Security) is a cryptographic protocol designed to provide secure communication over a computer network. Here are some key points about TLS:

Encryption: TLS encrypts the data transmitted between a client and a server, ensuring that any intercepted data cannot be read by unauthorized parties.

Authentication: TLS uses certificates to authenticate the identity of the parties involved in the communication, ensuring that the client is connecting to the intended server.

Data Integrity: TLS ensures that the data sent and received has not been tampered with during transmission.

TLS is widely used to secure web browsing, email, instant messaging, and other forms of data transfer over the internet. It is the successor to the older SSL (Secure Sockets Layer) protocol and is considered more secure and efficient.

What widely implemented protocol has an adverse effect on the reliability of NIDS?

```
tls
```


Task 4 Reconnaissance and Evasion Basics

simple evasion techniques in the context of the first stage of the cyber kill chain, reconnaissance. First, run the following command against the target at MACHINE_IP

```
nmap -sV MACHINE_IP

```

The above command does not make use of any evasion techniques and as a result, most NIDS should be able to detect it with no issue, in fact, you should be able to verify this now by navigating to MACHINE_IP:8000/alerts. Suricata should have detected that some packets contain the default nmap user agent and triggered an alert. Suricata will have also detected the unusual HTTP requests that nmap makes to trigger responses from applications targeted for service versioning. Wazuh may have also detected the 400 error codes made during the course of the scan.


We can use this information to test our first evasion strategy. By appending the following to change the user_agent ```http.useragent=<AGENT_HERE>,``` we can set the user agent used by nmap to a new value and partially evade detection. 

```nmap -sV --script-args http.useragent="<USER AGENT HERE>" MACHINE_IP ```

Note, that this strategy isn't perfect as both Suricata and Wazuh are more than capable of detecting the activity from the aggressive scans. Try running the following nmap command with the new User-Agent:

``` nmap --script=vuln --script-args http.useragent="<USER AGENT HERE>" MACHINE_IP ```

The above command tells nmap to use the vulnerability detection scripts against the target that can return a wealth of information. However, as you may have noticed they also generate a significant number of IDS alerts even when specifying a different User-Agent as a nmap probes for a large number of potential attack vectors. It is also possible to evade detection by using SYN (-sS) or "stealth" scan mode; however, this returns much less information as it will not perform any service or version detection, try running this now:

``` nmap -sS MACHINE_IP ```












Task 5 Further Reconnaissance Evasion





















Task 6 Open-source Intelligence
















Task 7 Rulesets











Task 8 Host Based IDS (HIDS)













Task 9 Privilege Escalation Recon







Task 10 Performing Privilege Escalation












Task 11 Establishing Persistence









# Task 12 Conclusion











Task 12
Conclusion
