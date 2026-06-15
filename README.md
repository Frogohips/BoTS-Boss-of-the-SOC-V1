# Boss of the SOC v1 — My Walkthrough

**Based on the samsclass BOTSv1 challenge | [https://samsclass.info/50/proj/botsv1.htm](https://samsclass.info/50/proj/botsv1.htm)**

---

So I've been working through the Boss of the SOC v1 (BOTSv1) challenge, which is a Splunk-based CTF designed to simulate a real SOC analyst investigating a cyberattack. I'm still very much a beginner with Splunk, and I'll be honest — there were quite a few moments where I stared at the interface not really knowing what I was doing. But that's kind of the point, I think. This writeup is my attempt to document what I did, where I got confused, and how I eventually figured things out.

---

## What is BOTSv1?

BOTSv1 is a Capture The Flag challenge built around a fictional company that has been attacked. You're given access to a Splunk instance loaded with real log data from the incident, and your job is to answer questions by digging through that data. The attack involves a web defacement, a brute force login, a malware upload, and eventually ransomware. It escalates quickly.

The data sources include HTTP stream logs, Sysmon (Windows event logs), Suricata IDS alerts, DNS logs, SMB data, and Windows Registry events. As a beginner, I had to figure out what all of these even were as I went.

---

## Level 1: Finding Attack Servers

### 1.1 — What vulnerability scanner was used? (5 pts)

**Answer: Acunetix**

This was a good introductory question because it got me comfortable with looking at HTTP stream data. I searched in the `stream:http` source and started poking at the `http_user_agent` and product header fields. The scanner announces itself pretty clearly in the User-Agent string — Acunetix is one of the most common web vulnerability scanners, so once I saw the name in the header I was fairly confident.

I initially wasn't sure *which* field to look in. I spent a while on `src_ip` before realising I needed to actually inspect the raw event content and look at headers. Lesson learned: always look at the full event, not just the summary fields.

![1.1](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.1.png?raw=true)
![1.1(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.1(2).png?raw=true)

---

### 1.2 — What is the attacker's IP address? (5 pts)

**Answer: 40.80.148.42**

I pulled up the `src_ip` field from `stream:http` events and looked at the distribution. Three IPs showed up, and one of them — `40.80.148.42` — accounted for about 74.9% of all events. That's a huge proportion, and it made sense: the scanner hammers the target with hundreds of requests in a short time. The other IPs belonged to the web server and staging server.

This was my first real experience using Splunk's field value distribution to identify anomalies. Seeing one IP dominate so heavily was a bit of an "oh, *that's* how you spot something suspicious" moment.

![1.2](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.2.png?raw=true)
![1.2(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.2(2).png?raw=true)

---

### 1.3 — What is the web server's IP address? (5 pts)

**Answer: 192.168.250.70**

I filtered for events going to `imreallynotbatman.com` and looked at the `dest_ip` field. One internal IP — `192.168.250.70` — appeared as the destination for nearly 79% of events. The raw event data confirmed it was listening on port 80, which is standard HTTP.

The `192.168.x.x` range is a private IP, which makes sense for an internal web server. This was a good reminder that real environments mix internal and external IPs in the logs.

![1.3](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.3.png?raw=true)
![1.3(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.3(2).png?raw=true)

---

### 1.4 & 1.5 — What file was used to deface the site, and where was it hosted? (10 pts each)

**Defacement filename: poisonivy-is-coming-for-you-batman.jpeg**
**Staging server FQDN: prankglassinebracket.jumpingcrab.com**

These two questions are closely linked. I needed to find where the attacker downloaded the defacement file from, and what that file was called.

My search was:

```
index="botsv1" src="192.168.250.70" dest_ip="23.22.63.114"
```

This gave me 9 events where the web server was reaching *out* to an external IP — which is suspicious on its own. Looking at the `uri` field on those events revealed the filename. The `url` field gave me the full URL including the domain of the staging server.

I'll be honest — I initially had this backwards. I was searching for traffic *to* the web server, not traffic *from* it. It took me a while to realise the defacement file had to be *pulled* by the web server from somewhere external, meaning the web server was the source. Once I flipped the src/dest in my head, it clicked.

![1.4&5](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.4&5.png?raw=true)
![1.4(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/1.4(2).png?raw=true)

---

## Level 2: Identifying Threat Actors

### 2.1 — What is the staging server's IP address? (10 pts)

**Answer: 23.22.63.114**

With the staging server's domain name from the previous question, I searched for HTTP GET events containing that domain:

```
index="botsv1" prankglassinebracket.jumpingcrab.com source="stream:http" http_method=GET
```

The `dest_ip` field on those events pointed straight to `23.22.63.114`. This is the external IP the attacker controlled.

![2.1](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/2.1.png?raw=true)
![2.1(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/2.1(2).png?raw=true)

---

### 2.2 — What is the Leetspeak domain associated with the attacker? (10 pts)

**Answer: po1s0n1vy.com**

This one moved us outside of Splunk entirely. I took the staging server IP (`23.22.63.114`) and looked it up in AlienVault OTX (Open Threat Exchange) using the Passive DNS tab. This shows all the domains that have historically pointed to that IP.

Several domains came up, and one of them was written in Leetspeak — where letters are replaced with numbers. `po1s0n1vy.com` is "poisonivy" with vowels swapped for digits. Poison Ivy is also the name of a well-known remote access trojan (RAT), which is a hint at what we're dealing with.

This was my first time using threat intelligence lookups alongside Splunk data, and it was actually really satisfying — using one answer to pivot into the next investigation step.

![2.2](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/2.2.png?raw=true)

---

### 2.3 — What IP was used for the brute force attack? (15 pts)

**Answer: 23.22.63.114**

Same IP as the staging server. The attacker consolidated operations.

My search filtered for POST requests to `imreallynotbatman.com`, then excluded anything that looked like the Acunetix scanner:

```
index="botsv1" imreallynotbatman.com source="stream:http" http_method=POST
| search NOT "Acunetix Web Vulnerability Scanner"
| table _time, form_data, src_ip
```

That gave me 441 events, all from the same IP. POST requests to a login page in high volume = brute force. The `form_data` field even showed the username and password being tried each time.

![2.3](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/2.3.png?raw=true)
![2.3(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/2.3(2).png?raw=true)

---

### 2.4 — What executable file was uploaded? (15 pts)

**Answer: 3791.exe**

I filtered the same POST traffic for `.exe` in the data content. The `data_content` field on one event showed a directory listing inside the Joomla administrator component path, which included `3791.exe`. The attacker had uploaded a Windows executable through the compromised CMS.

This took me a while to find because I wasn't sure what field the file upload data would appear in. I ended up looking at several fields before spotting it in `data_content`. The fact that it's a `.exe` sitting in a Joomla directory is pretty alarming when you see it.

![2.4](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/2.4.png?raw=true)
![2.4(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/2.4(2).png?raw=true)

---

## Level 3: Using Sysmon and Stream

At this point the challenge starts using Windows Sysmon logs, which record detailed process and file activity on the host. I had only a vague idea of what Sysmon was before this, so I had to do some reading alongside the challenge.

### 3.1 — What is the MD5 hash of the uploaded executable? (10 pts)

**Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0**

Sysmon Event ID 1 is "Process Creation" — it logs every time a new process starts, including its hash. I searched for events involving `3791.exe`:

```
index="botsv1" EventID=1 Image="*3791.exe"
```

The MD5 hash appeared right in the event data. This hash can then be looked up in VirusTotal to confirm it's malicious.

![3.1](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.1.png?raw=true)
![3.1(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.1(2).png?raw=true)

---

### 3.2 — What was the first password tried in the brute force? (10 pts)

**Answer: 12345678**

I searched for login events targeting the Joomla administrator page and sorted by time ascending. The very first `form_data` entry with a `passwd=` value was `12345678`. Classic.

It felt strangely satisfying to literally see the attacker's wordlist being worked through one attempt at a time.

![3.2](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.2.png?raw=true)
![3.2(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.2(2).png?raw=true)

---

### 3.3 — What was the correct (successful) login password? (10 pts)

**Answer: batman**

This was more interesting than it sounds. The brute force was done using `Python-urllib/2.7` as the user agent, while the eventual manual login used a normal browser user agent. Two different `http_user_agent` values in the same dataset.

I filtered for events with `batman` in the `form_data` field. The event where the response indicated a successful login — rather than a redirect back to the login page — confirmed this was the correct password. Batman's password is "batman." I suppose that tracks.

![3.3](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.3.png?raw=true)

---

### 3.4 — How many seconds between the brute force finding the password and the attacker manually logging in? (10 pts)

**Answer: 92.17 seconds**

I found the two events containing the correct password — one from the Python brute-forcer, one from a real browser — and calculated the time difference using their timestamps. The attacker had the password, then took about a minute and a half to sit down and manually log in. A very human pause.

![3.4](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.4.png?raw=true)
![3.4(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.4(2).png?raw=true)

---

### 3.5 — How many unique passwords were tried in the brute force? (10 pts)

**Answer: 412**

I filtered to only the Python-urllib user agent (the brute-force tool), pulled out all the `passwd=` values from the `form_data` field, and counted the unique ones. 412 attempts before landing on "batman."

![3.5](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/3.5.png?raw=true)

---

## Level 4: Analysing a Ransomware Attack

This final level is the most involved. It traces a Cerber ransomware infection from first contact through to encrypting files on the victim's workstation and a connected file server. The victim in this scenario is Bob Smith, using a workstation called `we8105desk`.

---

### 4.1 — What was the IP address of we8105desk on 24 August 2016? (5 pts)

**Answer: 192.168.250.100**

I searched for `we8105desk` in stream sources using Active Directory authentication protocols (Kerberos/NTLM). The IP addresses in those auth events on that specific date pointed to `192.168.250.100`.

Learning to filter by date in Splunk (`earliest=` and `latest=`) was something I had to look up. The time picker in the UI is helpful but I kept forgetting to set it.

![4.1](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.1.png?raw=true)

---

### 4.2 — What Suricata signature ID fired on the ransomware? (5 pts)

**Answer: 2816763**

I searched Suricata events for "Cerber" and looked at the alert signatures. A few fired, and the one with the fewest hits was `2816763`. Suricata is an IDS (Intrusion Detection System), and its alerts are labelled with signature IDs that map to known threat patterns.

![4.2](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.2.png?raw=true)
![4.2(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.2(2).png?raw=true)

---

### 4.3 — What .onion domain did the ransomware try to contact? (15 pts)

**Answer: cerberhhyed5frqa.xmfir0.win**

This involved cross-referencing two data sources. Suricata had events with "Onion domain lookup" in the alert signature. I took the timestamp of those events and looked at DNS query events within one second of each alert. The `query` field in the DNS events revealed the domain the ransomware was trying to reach — a `.win` domain serving as a proxy for a .onion address. Cerber uses this to phone home after encrypting files.

This was one of the harder questions. Getting the timing correlation right between Suricata and DNS events required a bit of trial and error with the time windows.

![4.3](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.3.png?raw=true)
![4.3(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.3(2).png?raw=true)

---

### 4.4 — What was the first suspicious domain the workstation visited? (15 pts)

**Answer: solidaritedeproximite.org**

I looked at the 86,579 Suricata events on 24 August from Bob's workstation. Filtering to HTTP and DNS event types and examining the top ten hostnames visited, one domain stood out as clearly not a legitimate service. External research confirmed it as a known malware distribution site — this is where the initial infection likely started.

![4.4](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.4.png?raw=true)
![4.4(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.4(2).png?raw=true)

---

### 4.5 — What is the name of the first function in the VB script? (15 pts)

**Answer: GNbiPp**

I searched for events where both a `.vbs` and a `.exe` extension appeared together in the data (16 total events). Looking at the body of the malicious event revealed the actual VB script content, including its first function definition. The function name `GNbiPp` is deliberately obfuscated — random-looking strings are a common malware technique to avoid signature-based detection.

I had no idea what to look for here at first. The hint about searching for `.vbs` and `.exe` together made more sense once I understood that the script was likely a dropper that called another executable.

![4.5](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.5.png?raw=true)
![4.5(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.5(2).png?raw=true)

---

### 4.6 — How many characters long is the script field? (15 pts)

**Answer: 5861**

The VB script field appeared in three events. The longest version — which was HTML-encoded, meaning ampersands and other characters were expanded into their entity forms (e.g., `&amp;`) — came in at 5861 characters. The encoding artificially inflates the length, which is worth noting.

![4.6](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.6.png?raw=true)
![4.6(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.6(2).png?raw=true)

---

### 4.7 — What is the name of the USB drive Bob plugged in? (15 pts)

**Answer: MIRANDA_PRI**

I searched the `WinRegistry` source type for events containing `FriendlyName`. Windows stores a human-readable name for connected USB devices in the registry, and Sysmon logs registry changes. The value data from that event contained the USB drive name.

I thought this was a clever question — it made me realise just how much information Windows logs about connected devices, which is obviously useful for forensics.

![4.7](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.7.png?raw=true)

---

### 4.8 & 4.9 — What is the file server's hostname and IP? (5 pts / 15 pts)

**Hostname: we9041srv**
**IP: 192.168.250.20**

I examined SMB stream data during the ransomware outbreak for Bob's workstation. The SMB `path` field showed connections to another server. The naming convention (`we` prefix, similar to the workstation `we8105desk`) suggested it was a company file server — `we9041srv`.

To find the IP, I searched for that hostname in raw network stream sources and found the associated IP address, `192.168.250.20`.

![4.8&9](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.8&9.png?raw=true)
![4.8&9(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.8&9(2).png?raw=true)

---

### 4.10 — How many PDF files did Cerber encrypt on the file server? (20 pts)

**Answer: 257**

I searched for `.pdf` in SMB stream events, restricted to the `unknown` app category (which captures unusual/unclassified SMB traffic), and counted unique filenames within the timeframe of the attack. 257 distinct PDF files were encrypted on the remote server.

This question made the impact of the ransomware feel concrete. 257 files on just one server, in addition to everything on the local machine. Real damage.

![4.10](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.10.png?raw=true)

---

### 4.11 — What is the ParentProcessId of 121214.tmp? (15 pts)

**Answer: 3968**

Searching for `121214.tmp` returned 190 events. Focusing on Sysmon Event ID 1 (Process Creation), the `CommandLine` and `ParentProcessId` fields identified that the temporary file was launched by process ID 3968.

![4.11](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.11.png?raw=true)

---

### 4.12 — How many .txt files were encrypted in Bob's profile? (15 pts)

**Answer: 406**

I filtered events containing `.txt` to Bob's Windows user profile path. The trick here was using double backslashes in the Splunk search to match the Windows path separator correctly (`\\Users\\Bob`). Counting the unique file paths gave 406 text files.

This was a syntax issue that tripped me up for a bit. Splunk uses backslash as an escape character, so you need to double them up when searching Windows paths.

![4.12](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.12.png?raw=true)

---

### 4.13 — What file did Cerber download from the malicious domain? (15 pts)

**Answer: mhtr.jpg**

I searched for HTTP download events from `solidaritedeproximite.org` — the suspicious domain from question 4.4. One event showed a file being downloaded with a `.jpg` extension, which is unusual for something being executed. External research confirmed that this was the Cerber ransomware cryptor.

![4.13](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.13.png?raw=true)
![4.13(2)](https://github.com/Frogohips/BoTS-Boss-of-the-SOC-V1/blob/main/SC/4.13(2).png?raw=true)

---

### 4.14 — What obfuscation technique was used to hide the ransomware in that file? (10 pts)

**Answer: Steganography**

This one required stepping outside Splunk entirely. Looking up the `mhtr.jpg` hash on VirusTotal and referencing malware analysis reports revealed that the ransomware code was hidden *inside* the image file using steganography — the technique of concealing data within an ordinary-looking file.

It's a smart delivery method because `.jpg` files don't raise the same flags as `.exe` files, and without knowing to look for it, you'd just see an image download.

---

## Reflections

BOTSv1 was genuinely challenging, especially in the later levels. Some things I took away from it:

**Learning to pivot** was the biggest skill. Almost every question gave you a piece of information that you needed to use as the input for the next search. The challenge trains you to think about data relationally — timestamps, IPs, filenames, and hashes all connect to each other.

**Field names matter a lot.** I wasted time early on because I didn't know whether to look in `src_ip`, `dest_ip`, `form_data`, `uri`, or `url`. Getting familiar with the structure of each data source (stream:http, Sysmon, Suricata, WinRegistry) made things much faster by the end.

**OSINT and threat intel are part of the job.** Several questions required going outside Splunk to AlienVault OTX or VirusTotal. Real SOC work isn't just querying logs — it's correlating what you find with external knowledge about threat actors.

**Syntax trips you up constantly.** Double backslashes for Windows paths, time range syntax, wildcard placement — these small things caused me more delays than the actual logic of the problems.

Overall, I'd recommend BOTSv1 to anyone learning Splunk. It's frustrating in the right ways
