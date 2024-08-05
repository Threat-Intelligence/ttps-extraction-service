# IoC and TTP Extraction Service

This repository contains a suite of services designed to extract Indicators of Compromise (IoCs) and Tactics, Techniques, and Procedures (TTPs) from given content. Leveraging the OpenAI API for natural language processing and MongoDB for data storage, these services are intended to support cybersecurity operations by automating the extraction of critical threat intelligence from unstructured data sources.

## Features

- **IoC Extraction Service**: Identifies and extracts IoCs such as IP addresses, domain names, email addresses, URLs, file hashes, and registry keys.
- **TTP Extraction Service**: Extracts TTPs from content to identify attack patterns and behaviors based on the MITRE ATT&CK framework.
- **Actor Extraction Service**: Identifies threat actors from the content, utilizing a MongoDB database for storing and retrieving actor information.

## Folder Structure

ioc-ttp-extraction-service/
├── source/
│ ├── init.py
│ ├── main.py
│ ├── ioc_extraction_service.py
│ ├── ttp_extraction_service.py
│ ├── actor_extraction_service.py
│ ├── api_service.py
│ ├── extract_actor.py
├── .env
├── .gitignore
├── requirements.txt
└── README.md


## Services Overview

### IoC Extraction Service

This service leverages OpenAI's GPT model to identify and extract various types of IoCs from the provided content. It supports the extraction of:
- IP Addresses
- Domain Names
- Email Addresses
- URLs
- File Hashes (MD5, SHA-1, SHA-256)
- Registry Keys

### TTP Extraction Service

The TTP Extraction Service uses OpenAI's GPT model to parse content and identify TTPs related to cybersecurity threats. By using natural language processing, this service helps in understanding attack patterns and behaviors based on the MITRE ATT&CK framework.

### Actor Extraction Service

The Actor Extraction Service identifies threat actors mentioned in the content. It uses the Aho–Corasick algorithm for efficient pattern matching to identify threat actors and leverages a MongoDB database to store and retrieve information about various threat actors.

## Installation

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/ioc-ttp-extraction-service.git
    cd ioc-ttp-extraction-service
    ```

2. Create and activate a virtual environment:
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

4. Set up environment variables by creating a `.env` file in the root directory and adding your configuration:
    ```sh
    AZURE_OPENAI_ENDPOINT=your_azure_openai_endpoint
    AZURE_OPENAI_API_KEY=your_azure_openai_api_key
    MONGODB_CONNECTION_STRING=your_mongodb_connection_string
    MONGODB_DATABASE=your_database_name
    ```

## Running the Service

1. Start the Flask application:
    ```sh
    python source/main.py
    ```

2. The service will be available at `http://127.0.0.1:5000`.

## API Endpoints

### Extract IoCs
- **Endpoint:** `/extract/iocs`
- **Method:** `POST`
- **Description:** Extracts IoCs from the provided content.
- **Request Body:**
    ```json
    {
        "title": "Article title",
        "author": "Article author",
        "URL": "Article URL",
        "content": "Full article content",
        "mentioned_links": ["Link1", "Link2", ...]
    }
    ```
- **Response:**
    ```json
    {
        "ip_addresses": [],
        "domain_names": [],
        "email_addresses": [],
        "urls": [],
        "file_hashes": [],
        "registry_keys": []
    }
    ```

### Extract TTPs
- **Endpoint:** `/extract/ttps`
- **Method:** `POST`
- **Description:** Extracts TTPs from the provided content.
- **Request Body:**
    ```json
    {
        "content": "Your content here..."
    }
    ```
- **Response:**
    ```json
    {
        "ttps": []
    }
    ```

### Extract Actors
- **Endpoint:** `/extract/actors`
- **Method:** `POST`
- **Description:** Identifies threat actors from the provided content.
- **Request Body:**
    ```json
    {
        "content": "Your content here..."
    }
    ```
- **Response:**
    ```json
    {
        "actors": []
    }
    ```

