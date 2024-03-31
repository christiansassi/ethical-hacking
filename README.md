# Ethical Hacking

# Table of contents

-   [Introduction](#introduction)
-   [Challenges](#challenges)
-   [Getting started](#getting-started)

# Introduction

This repository includes solutions for every challenge covered thus far in the Ethical Hacking course. <br>
The solutions provided in this repository are encapsulated in Python scripts, allowing users to obtain the flag of the challenge by simply running the script. <br>
However, it's important to note that not all challenges were intended to be solved using Python scripts. <br>
Each challenge may have multiple solutions and, therefore, it is worth noting that the solutions showcased in this repository may not necessarily be the best ones, but they are, at the very least, functional.

# Challenges

### Web Security

-   [Hacker System Monitor](assignment-1/hacker_system_monitor.py)
-   [Audit](assignment-2/auction.py)

### Cryptography

-   [AESWT PoC](assignment-3/aeswt_poc.py)

# Getting started

1. Initialize the workspace:
    ```bash
    git clone https://github.com/christiansassi/ethical-hacking
    cd ethical-hacking
    ```
2. To install the necessary packages for each challenge, use the `requirements.txt` file. For instance:
    ```bash
    cd assignment-1
    pip install -r requirements.txt
    ```
3. Execute the desired Python script. For example:
    ```bash
    python hacker_system_monitor.py
    ```
