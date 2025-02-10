# A Household Appliance Energy Manager
 
> *Segurança Informática em Redes e Sistemas (SIRS 2022-23)*

> *Challenge 1 of the EcoGES business context (a new energy autonomous feature)* 

> *Security issue: data separation among distinct entities* 

## Authors

* **Afonso Bernardo** - *Everything* - [Adamasnaldo](https://github.com/Adamasnaldo)
* **César Reis** - *Everything* - [cesarsilvareis](https://github.com/cesarsilvareis)
* **Henrique Vinagre** - *Everything* - [Henrique Vinagre](https://github.com/henriquevinagre)

## Our Last Words
The aim of this project was to explore possible attack vectors and design a solution to meet a specific security issue, analysing the attacker model and making assumptions.
For those permisses, a business context was created from scratch, involving setting up all (virtual) network infrastructure and developing a Flask web application server.
On top of that, we formulated firewall rules and established secure channels (details in the [report](./report.pdf)).

## General Information

This solution implements database information separation through a cryptography protocol. For instance, if you need to store various critical information within a single (maybe physical, serverful) database, so that each piece of data should only be accessible by a specific entity in a secure manner, this solution is just right for you!

### Take as an Example  

**The EcoGES scenario**: A new feature lives in rumors inside the company -- a real-time monitor system embedded in the client electricity contracts that can balance the energy consumed by users' household appliances and that is produced by assigned solar panels.

**The Problem**: Several departments operate in the internal scenario with access to all stored user data (including critical for themselves).

### Built With

The implementation made uses Flask as a web framework that allow the webserver provides its services to clients. 

In a way to make it properly, it uses OpenSSL to generate asymmetric keys for each entity, enabling only HTTPS comunications with clients, establish a TLS secure channel for them a other with the Database Server. 

Futhermore, according to our security problem, for the encryption of critical data separeted by the Application Server and for the decryption of the corresponding department is taken the use of pure python-cryptography module. 

* [Python](https://www.python.org/) - Programming Language
* [Flask](https://flask.palletsprojects.com/) - Web API Framework
* [OpenSSL](https://www.openssl.org/) - Generate asysmmetric pair of keys for each entity
* [Python Cryptography](https://cryptography.io/en/latest/) - Generate secret keys and encrypt/decrypt critical data


## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Run PSQL and start the database

To launch the PSQL server and launch the command line interface:

```
$ sudo service postgresql restart
$ sudo -u postgres psql
```

Create a database and populate it:

```sql
CREATE DATABASE ecogesdb;
\c ecogesdb
\i populate.sql
```

Create the user associated with the appserver and grant it permissions on this database:

```sql
CREATE USER appserver WITH PASSWORD 'app-dees';
GRANT ALL ON ALL TABLES IN SCHEMA public TO appserver;
```

### Run the Python WebApp

```
$ python3 app.py
```

And you're all set! Connect to the interface in which you ran the above program through your browser: `https://[ip]:[port]`.

### Prerequisites

The instalation steps provided in this guide were tested on Ubuntu 20.04 but this setup is also possible in Windows (possibly with different commands), with and without WSL, which we used for easier development.

It can be run in any hardware/OS that can have a virtual box (preferably VirtualBox, but we tested in VMware and also worked).

You will need the following programs:

1. [PostgreSQL](https://www.postgresql.org)
2. [Python](https://www.python.org)

For python, you will need the following libraries:

1. [Flask](https://flask.palletsprojects.com/en/2.2.x/)
```
pip install flask
```
2. Cryptography
```
pip install cryptography
```
3. Psycopg2
```
pip install psycopg2
```

### Installing

Running the application is simple:

1. On one machine, run the database server. This was described [previously](#run-psql-and-start-the-database).

2. On another machine, run the Application Server. This was described [previously](#run-the-python-webapp).

Do note that you will need the necessary keys/certificates for running the programs with TLS.

## Demo
This is a simple project focused on the demonstration of our cryptographic solution. Try to create a new user and go to monthly invoices. Notice that you can't see some of the data (as a regular user)!

**Link:**
https://youtu.be/klFIMNZivCc.

## Possible Future Increments

- An actual Key Distributed Center (KDC) hosted by an internal machine to not rely on the assumption that the application server could not be compromissed (in a DMZ).
- Robust authentication with Kerberos protocol or key regeneration by the KDC to ensure perfect foward secrecy (PFS).



