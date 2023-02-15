
# CryptKVS

## Description
    - CryptKVS is a key-value store that encrypts the values before storing them in a file.
    - CryptKVS or "(en)crypted key-value store" is a simplified version of the "secure value recovery" protocol from the messaging app signal.

## Goal of the project
    - The goal of this project is to learn about the technical details involved in the implementation of a system oriented project, using libraries related to cryptography, networking and others.
    - This project is done entirely in C.
    - We implemented multiple commands that are useful for interacting with the key-value store (database).

## Usage
    - CryptKVS is a command line tool that can be used to store and retrieve values from a file.
    - The file is encrypted using AES-256-GCM.
    - The password is never stored in the file.
    - You can interact with the database using the following commands:
        - cryptkvs [<database>|<URL>] stats : will display useful information about the key-value store as well as its content encrypted.
        - cryptkvs [<database>|<URL>] get <key> <password>: will display the value associated with the key.
        - cryptkvs [<database>|<URL>] set <key> <password> <filename>: will set the value associated with the key.
        - cryptkvs [<database>|<URL>] new <key> <password>: will create a new key-password pair (do not forget the password as it will not be possible to retrieve the decrypted value later).
    - Note that this project can work locally, by accessing a database in the server from the server hence the <database> field, as well as remotely, by accessing a database in the server from the client hence the <URL> field.

## Credits
    - This project was done by:
        - Ali Essonni
        - Yasmin Ben Rahhal
    - This project was done as part of the "System Oriented Programming" 2022 course at EPFL under the supervision of Pr. Jean-Cédric Chappelier and Pr. Edouard Bugnion.

