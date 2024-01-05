
# Encryption Based on Multilevel Security for Relational Database (EBMSR)

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/your-username/your-repo-name/blob/main/LICENSE)

## Overview

The Encryption Based on Multilevel Security for Relational Database (EBMSR) is a secure Database Management System (DBMS) that implements a Multilevel Security (MLS) model using various encryption algorithms. This project is developed using Python Flask for the backend, SQLite as the database, and employs AES256, DES, and RC4 encryption algorithms for different security levels.

## Features

- **User Authentication:**
  - Users sign in with a username and password.
  - Passwords are securely hashed using MD5 for storage.

- **Multilevel Security Model:**
  - Three security levels (TS, S, C) with corresponding encryption algorithms (AES256, DES, RC4).

- **User Privileges:**
  - Administrators can add, update, delete users, and assign security levels.
  - Normal users have restricted privileges based on their security levels.

- **Encryption Algorithms:**
  - AES256, DES, and RC4 utilized for TS, S, and C levels, respectively.

- **Technology Stack:**
  - Python Flask for web development.
  - SQLite as the database management system.

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Sivarooprr/EBMSR
