# SQL Injection Union Attack - Lab 8 Exploit

This Go program automates the exploitation of a SQL injection UNION attack vulnerability to retrieve data from other tables. It is designed to work with the PortSwigger Web Security Academy lab: "SQL injection UNION attack, retrieving data from other tables".

## Description

The tool performs a series of steps to enumerate the database and retrieve sensitive data from a web application vulnerable to a SQL injection UNION attack:

1. **Vulnerability Check**: Confirms if the target URL is susceptible to basic SQL injection by appending a single quote.
2. **Comment Style Detection**: Identifies the correct SQL comment style (`--`, `-- `, `#`) usable for terminating injected queries.
3. **Column Count Determination**: Finds the number of columns returned by the vulnerable query using `ORDER BY` clauses.
4. **Text Column Identification**: Finds a column in the `UNION SELECT` statement that is suitable for holding text data.
5. **Table Enumeration**: Retrieves the names of all tables from the database.
6. **Column Enumeration**: Retrieves the column names from a target table (e.g., `users_...`).
7. **Data Retrieval**: Dumps the contents of the target columns (e.g., usernames and passwords).

## Features

- Automated SQL injection vulnerability detection.
- Detection of SQL comment style.
- Determination of the number of columns in the query result set.
- Identification of a text-compatible column for data exfiltration.
- Enumeration of database tables and columns.
- Automated retrieval of user credentials from a target table.
- Support for HTTP/HTTPS proxy.
- Configurable logging levels (debug, info, action, warning, fatal, success).

## Prerequisites

- Go version 1.23.0 or higher (as per `go.mod`).

## Setup

1. Clone the repository or ensure all project files are in a directory (e.g., `lab_8`).
2. Navigate to the project directory:

    ```bash
    cd path/to/lab_8
    ```

3. Ensure dependencies are met (though `go run` or `go build` will handle this):

    ```bash
    go mod tidy
    ```

## Usage

The program is run from the command line, providing the target lab URL.

```bash
go run main.go -u <TARGET_LAB_URL> [OPTIONS]
```

Or, build the executable first:

```bash
go build -o sqli_lab8 main.go
./sqli_lab8 -u <TARGET_LAB_URL> [OPTIONS]
```

### Command-Line Arguments

- `-u string`: (Required) Target URL of the PortSwigger Lab (e.g., `https://your-lab-id.web-security-academy.net`). The program will automatically append the necessary path (`/filter?category=abc`).
- `-proxy string`: (Optional) Proxy URL to route traffic through (e.g., `http://127.0.0.1:8080`).
- `-log-level string`: (Optional) Set log level. Available options: `debug`, `info`, `action`, `warning`, `fatal`, `success`. Default is `info`.

### Example

```bash
go run main.go -u "https://abcdef1234567890.web-security-academy.net" -log-level debug -proxy "http://127.0.0.1:8080"
```

## Project Structure

- `main.go`: Entry point of the application, orchestrates the SQL injection steps.
- `sqli/tester.go`: Contains the core logic for testing SQL injection vulnerabilities, finding comment styles, determining column numbers, and retrieving the database version.
- `utility/`:
  - `args_parser.go`: Handles parsing of command-line arguments.
  - `client.go`: Manages HTTP client creation and request sending, including proxy support.
  - `utilities.go`: Provides helper functions like URL normalization and safe resource closing.
- `constant/`:
  - `constant.go`: Defines general constants like the target URI path and column search limits.
  - `comment_style.go`: Defines supported SQL comment styles.
  - `db_enum.go`: Defines structures and instances for different database types (Oracle, MSSQL, MySQL, PostgreSQL) and their specific version functions and comment styles.
- `logger/logger.go`: Implements a custom logger with different levels and colored output.
- `go.mod`, `go.sum`: Go module files defining dependencies.

## Lab Information

This tool is specifically tailored for the PortSwigger SQL Injection Lab:

- **Lab:** SQL injection UNION attack, retrieving data from other tables
- **Learning Path:** SQL injection
- **URL:** <https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-examining-the-database-in-sql-injection-attacks/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft>

**Disclaimer:** This tool is intended for educational purposes and for use on authorized systems only.
