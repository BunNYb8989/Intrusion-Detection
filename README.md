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

<p align="center">
<br/>
  <img src="t4"/>
<br/>
<br/>
</p>

What scale is used to measure alert severity in Suricata? 

```
1-3
```

How many services is nmap able to fully recognise when the service scan (-sV) is performed?

```
3
```


Task 5 Further Reconnaissance Evasion


Of course, nmap is not the only tool that features IDS evasion tools. As an example the web-scanner nikto also features a number of options that we will experiment with within this task, where we perform more aggressive scans to enumerate the services we have already discovered. In general, nikto is a much more aggressive scanner than nmap and is thus harder to conceal; however, these more aggressive scans can return more useful information in some cases. Let's start by running nikto with the minimum options:

nikto -p 80,3000 -h 10.10.234.82
nikto -p 3000 -h 10.10.234.82

openlink 10.10.235.82:3000

<p align="center">
<br/>
  <img src="t5"/>
<br/>
<br/>
</p>

nikto -p3000 -T 1 2 3 -useragent <AGENT_HERE> -h 10.10.234.82

nikto -p3000 -T 1 2 3 -useragent <AGENT_HERE> -e 1 7 -h 10.10.234.82

and check alerts


Nikto, should find an interesting path when the first scan is performed, what is it called?

```
/login
```

What value is used to toggle denial of service vectors when using scan tuning (-T) in nikto?

```
6
```

Which flags are used to modify the request spacing in nikto? Use commas to separate the flags in your answer.

```
6,A,B
```





Task 6 Open-source Intelligence

Welcome to Grafana
Email or username
Password
Forgot your password?

Documentation
Support
Community Open Source v8.2.5 (b57a137acd)


What version of Grafana is the server running?

```
8.2.5
```

What is the ID of the severe CVE that affects this version of Grafana? (google it)

```
CVE-2021-43798
```

If this server was publicly available, What site might have information on its services already?

```
Shodan.
```

How would we search the site "example.com" for pdf files, using advanced Google search tags?

```
site:example.com filetype:pdf
```

Task 7 Rulesets

Any signature-based IDS is ultimately reliant, on the quality of its ruleset; attack signatures must be well defined, tested, and consistently applied otherwise, it is likely that an attack will remain undetected. It is also important that the rule set be, kept up to date in order to reduce the time between a new exploit being discovered and its signatures being loaded into deployed IDS

wget https://raw.githubusercontent.com/Jroo1053/GrafanaDirInclusion/master/src/exploit.py
AND CHECK ALERTS


you're happy with what you've found on the server have a look a the IDS alert history at 10.10.234.82:8000/alerts. Can you see any evidence that this particular exploit was detected? like I said not all rule sets are perfect.

What is the password of the grafana-admin account?

```
GraphingTheWorld32
```

Is it possible to gain direct access to the server now that the grafana-admin password is known? (yay/nay)

```
yay
```

Are any of the attached IDS able to detect the attack if the file /etc/shadow is requested via the exploit, if so what IDS detected it?

```
Suricata
```

Task 8 Host Based IDS (HIDS)
malicious activity involve network traffic that could be detected by a NIDS, ransomware, for example, could be disturbed via an external email service provider installed and executed on a target machine and, only be detected by a NIDS once, it calls home with messages of its success which, of course, is way too late. For this reason, it is often advisable to deploy a host-based IDS alongside a NIDS to check for suspicious activity that occurs on devices and not just over the network including:

    Malware execution
    System configuration changes
    Software errors
    File integrity changes
    Privilege escalation


The primary difference between HIDS and NIDS is the types of activity that they can detect. A HIDS will not typically have access to a log of network traffic and is, therefore, unable to detect certain forms of activity at all or will only be able to detect more aggressive activity. We can demonstrate this now running the following command and taking note of what IDS detects the activity, remembering that Wazuh and Suricata are both attached to the target:

nmap -sV 10.10.234.82

Wazuh should be able to detect that an insecure SSH connection attempt was made to the server but will not mention the connection to the HTTP server, unlike Suricata. However, if we run:

nmap --script=vuln 10.10.234.82

What category does Wazuh place HTTP 400 error codes in?

```
web

```

Task 9 Privilege Escalation Recon



including:

    sudo -l this will return a list of all the commands that an account can run with elevated permissions via sudo
    groups will list all of the groups that the current user is a part of.
    cat /etc/group should return a list of all of the groups on the system and their members. This can help in locating users with higher access privileges and not just our own.
    
What tool does linPEAS detect as having a potential escalation vector?

```
docker
```

Is an alert triggered by Wazuh when linPEAS is added to the system, if so what its severity?

```

```




Task 10 Performing Privilege Escalation












Task 11 Establishing Persistence









# Task 12 Conclusion











Task 12
Conclusion
