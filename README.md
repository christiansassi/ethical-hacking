# Ethical Hacking

# Table of contents

-   [Introduction](#introduction)
-   [Challenges](#challenges)
-   [Getting started](#getting-started)

# Introduction

This repository contains solutions for all challenges covered in the Ethical Hacking course. <br>
The solutions, written in Python scripts, enable users to retrieve the challenge flag by running the script. 
It's worth noting that while Python scripts are provided for all challenges, not all of them were originally intended to be solved using Python. 
Additionally, each challenge may have multiple solutions, so they may not always be the optimal ones.

# Challenges

### Web Security

-   [Hacker System Monitor](assignment-1/hacker_system_monitor.py)
-   [Audit](assignment-2/auction.py)

### Cryptography

-   [AESWT PoC](assignment-3/aeswt_poc.py)
-   [Identity Delight Provider](assignment-4/identity_delight_provider.py)

### Reverse Engineering

-   [The x86 police](assignment-5/the_x86_police.py)
-   [RandomPasswordGenerator 2.0 (RPG2)](assignment-6/random_password_generator_20_rpg2.py)

### Pwn

-   [BASH - Basic Asynchronous Shell](assignment-7/bash_basic_asynchronous_shell.py)
-   [echo](assignment-8/echo_echo20.py)
-   [Rest on Pieces (ROP)](assignment-9/rest_on_pieces_rop_50.py)

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

> [!IMPORTANT]
> Before solving the challenges, please read the description at the beginning of each file.
