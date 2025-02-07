# How-to-Read-Wireshark-TCP-HTTP-log

In this reading, you’ll learn how to read a Wireshark TCP/HTTP log for network traffic between employee website visitors and the company’s web server. Most network protocol/traffic analyzer tools used to capture packets will provide this same information.

## Log Entry Number and Time

| No. | Time     |
|----|---------|
| 47 | 3.144521 |
| 48 | 3.195755 |
| 49 | 3.246989 |

This Wireshark TCP log section starts at log entry number (No.) 47, which is **three seconds and 144521 milliseconds** after the logging tool started recording. This indicates that approximately **47 messages** were sent and received by the web server in the first **3.1 seconds** after logging began. The rapid traffic speed is why the tool tracks time in milliseconds. 

## Source and Destination IP Addresses

| Source       | Destination |
|-------------|------------|
| 198.51.100.23 | 192.0.2.1  |
| 192.0.2.1   | 198.51.100.23 |
| 198.51.100.23 | 192.0.2.1  |

The **Source** column contains the IP address of the machine sending the packet, while the **Destination** column lists the intended recipient.  
- In this log file, the IP address **192.0.2.1** belongs to the **company’s web server**.  
- The IP range **198.51.100.0/24** represents **employee computers**.

## Protocol Type and Related Information

| Protocol | Info |
|----------|------|
| TCP | 42584->443 [SYN] Seq=0 Win-5792 Len=120... |
| TCP | 443->42584 [SYN, ACK] Seq=0 Win-5792 Len=120... |
| TCP | 42584->443 [ACK] Seq=1 Win-5792 Len=120... |

The **Protocol** column shows the transport protocol (**TCP**) in use. Once the connection is established, the protocol will change to **HTTP**, representing the application layer.

The **Info** column contains:  
- **Source port → Destination port** (e.g., `42584->443`)  
- **TCP handshake process**:
  - **[SYN]** - Initial request from the employee’s browser
  - **[SYN, ACK]** - Web server acknowledges the request
  - **[ACK]** - Employee’s browser confirms the connection  

Port **443** is commonly used for **encrypted web traffic.**
# TCP Three-Way Handshake and Attack Analysis

The next data element in the **Info** column is part of the **three-way handshake** process to establish a connection between two machines. In this case, employees are trying to connect to the company’s web server:

- **[SYN]** - The initial request from an employee visitor trying to connect to a web page hosted on the web server. **SYN** stands for **synchronize**.
- **[SYN, ACK]** - The web server’s response to the visitor’s request agreeing to the connection. The server reserves system resources for the final handshake step. **SYN, ACK** stands for **synchronize acknowledge**.
- **[ACK]** - The visitor’s machine acknowledging permission to connect. This is the final step for a successful TCP connection. **ACK** stands for **acknowledge**.

The next few items in the **Info** column provide more packet details, but this data is not needed for this activity. To learn more about packet properties, visit **Microsoft’s Introduction to Network Trace Analysis**.

## Normal Website Traffic

A normal transaction between a website visitor and the web server looks like:

| No. | Time | Source | Destination | Protocol | Info |
|----|------|--------|------------|----------|------|
| 47  | 3.144521 | 198.51.100.23 | 192.0.2.1 | TCP | 42584->443 [SYN] Seq=0 Win=5792 Len=120... |
| 48  | 3.195755 | 192.0.2.1 | 198.51.100.23 | TCP | 443->42584 [SYN, ACK] Seq=0 Win-5792 Len=120... |
| 49  | 3.246989 | 198.51.100.23 | 192.0.2.1 | TCP | 42584->443 [ACK] Seq=1 Win-5792 Len=120... |
| 50  | 3.298223 | 198.51.100.23 | 192.0.2.1 | HTTP | GET /sales.html HTTP/1.1 |
| 51  | 3.349457 | 192.0.2.1 | 198.51.100.23 | HTTP | HTTP/1.1 200 OK (text/html) |

Notice the handshake process takes only a few milliseconds to complete. After that, the employee’s browser requests the `sales.html` webpage via **HTTP**, and the web server responds.

## The Attack: SYN Flood

Malicious actors can exploit the TCP protocol by flooding a server with **SYN** packet requests to initiate the handshake. If the number of SYN requests exceeds the server’s available resources, the server becomes overwhelmed and unable to respond. This results in a **Denial of Service (DoS) attack**, specifically a **SYN flood attack**, targeting network bandwidth to slow or halt traffic.

- A **DoS attack** originates from a **single source**.
- A **Distributed Denial of Service (DDoS) attack** comes from **multiple sources**, often in different locations, making it harder to trace.

## Identifying the Attack in Wireshark

There are two tabs at the bottom of the log file. The **"Color coded TCP log"** tab highlights server interactions with the attacker’s IP address (`203.0.113.0`) in **red**.

| Color | No. | Time | Source | Destination | Protocol | Info |
|------|----|------|--------|------------|----------|------|
| red  | 52  | 3.390692 | 203.0.113.0 | 192.0.2.1 | TCP | 54770->443 [SYN] Seq=0 Win=5792 Len=0... |
| red  | 53  | 3.441926 | 192.0.2.1 | 203.0.113.0 | TCP | 443->54770 [SYN, ACK] Seq=0 Win-5792 Len=120... |
| red  | 54  | 3.493160 | 203.0.113.0 | 192.0.2.1 | TCP | 54770->443 [ACK] Seq=1 Win=5792 Len=0... |
| green | 55  | 3.544394 | 198.51.100.14 | 192.0.2.1 | TCP | 14785->443 [SYN] Seq=0 Win-5792 Len=120... |
| green | 56  | 3.599628 | 192.0.2.1 | 198.51.100.14 | TCP | 443->14785 [SYN, ACK] Seq=0 Win-5792 Len=120... |
| red  | 57  | 3.664863 | 203.0.113.0 | 192.0.2.1 | TCP | 54770->443 [SYN] Seq=0 Win=5792 Len=0... |

Initially, the attacker’s **SYN request** is answered by the web server (log items **52-54**). However, the attacker **keeps sending more SYN requests**, which is **abnormal**. At this stage, the web server is still able to handle normal traffic, as seen in the **green** logs.

An employee visitor (`198.51.100.14`) successfully **completes a handshake** with the web server (**log items 55, 56, 58**) and then requests `sales.html` (**log item 60**). The web server responds with an **HTTP 200 OK** message (**log item 62**), indicating successful communication.

As the attack escalates, the server becomes overloaded, leading to timeouts and failed connections.

---

This log analysis demonstrates how **SYN flood attacks** disrupt normal network traffic. By using Wireshark, analysts can **identify abnormal traffic patterns**, distinguish between legitimate and malicious packets, and implement **mitigation strategies** to protect network resources.

