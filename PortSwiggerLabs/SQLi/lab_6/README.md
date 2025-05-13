# PortSwigger SQLi Lab 6 Solver

This Go program automates the solution for PortSwigger Web Security Academy's SQL Injection Lab 6: "[SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-multiple-values-within-a-single-column/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column#)".

It performs a SQL attack to determine the number of columns returned by the original query and then extracts the usernames and passwords from the `users` table, specifically targeting the `administrator` user's password.

## Features

*   Determines the number of columns returned by the vulnerable query using the `ORDER BY` technique.
*   Constructs and executes a SQL injection payload (e.g., `UNION SELECT`) tailored to retrieve specific data as per Lab 6 requirements.
*   Retrieves target data (e.g., credentials, version numbers, etc.).
*   Parses the HTTP response (e.g., using `goquery` for HTML) to find the required information.
*   Supports using an HTTP proxy (e.g., for debugging with Burp Suite).
*   Customizable logging levels for detailed output.

## Prerequisites

*   **Go:** Version 1.18 or later recommended (see `go.mod` for the exact version used).
*   **Target Lab:** Access to an instance of the PortSwigger SQL Injection Lab 6.

## Installation

1.  Ensure you have the project files in the `lab_6` directory.
2.  Navigate to the project directory in your terminal:
3.  Dependencies are managed by Go modules (`go.mod`). They will typically be downloaded automatically when you build or run the code. You can explicitly download them if needed:
    ```bash
    go mod tidy
    ```

## Usage

You can run the program directly using `go run` or build an executable first with `go build`.

**Required Argument:**

*   `-u <LAB_URL>`: The full base URL of your specific PortSwigger lab instance (e.g., `https://YOUR-LAB-ID.web-security-academy.net`).

**Optional Argument:**

*   `-log-level <LEVEL>`: Set the logging level (debug, info, action, warn, fatal, success). Default is info.
*   `-proxy <PROXY_URL>`: The URL of an HTTP proxy to use (e.g., `http://127.0.0.1:8080`).
* 

**Examples:**

1.  **Run directly:**
    ```bash
    go run . -u https://YOUR-LAB-ID.web-security-academy.net
    ```

2.  **Run directly using a proxy (Burp Suite default):**
    ```bash
    go run . -u https://YOUR-LAB-ID.web-security-academy.net -proxy http://127.0.0.1:8080
    ```

3.  **Build first, then run:**
    ```bash
    go build
    ./lab_5 -u https://YOUR-LAB-ID.web-security-academy.net
    ```

The program will output the steps it's taking, the number of columns found, and finally, the administrator's password if successful.

## How it Works

1.  **Column Count Determination (`findNumOfColumns`):**
    *   It injects `'+ORDER+BY+N--` payloads into the `category` parameter, incrementing `N` starting from 1.
    *   It sends requests like `/filter?category=abc'+ORDER+BY+1--`, `/filter?category=abc'+ORDER+BY+2--`, etc.
    *   When the server returns an HTTP 500 Internal Server Error, it indicates that `N` is an invalid column index. The number of columns is therefore `N-1`.

2.  **Payload Generation (`generateUNIONPayload`):**
    *   Based on the determined column count, it crafts a `UNION SELECT` payload.
    *   **Important Assumption:** This implementation assumes the *first two columns* of the original query's result set are compatible with string data types.
    *   It places the target database columns (`username`, `password`) into these first two slots and fills the remaining slots with `NULL`.
    *   Example payload for 3 columns: `'+UNION+SELECT+username,password,NULL+FROM+users--`

3.  **Attack Execution (`performSQLAttack`, `getAdminPassword`):**
    *   The generated `UNION SELECT` payload is appended to the vulnerable URL path (`/filter?category=abc`).
    *   A GET request is sent with the full attack URL.
    *   It expects an HTTP 200 OK response if the attack syntax is correct.

4.  **Password Extraction (`getAdminPassword`):**
    *   The HTML content of the successful response body is read.
    *   The `goquery` library is used to parse the HTML.
    *   It searches for a table header (`<th>`) containing the text `administrator`.
    *   It then extracts the text content of the immediately following table data cell (`<td>`), assuming this cell contains the corresponding password.

## Dependencies

*   `github.com/PuerkitoBio/goquery`: Used for parsing the HTML response to extract the password.

## Disclaimer

This tool is intended for educational purposes and for use solely on the PortSwigger Web Security Academy labs. Using such tools against systems without explicit permission is illegal and unethical.
