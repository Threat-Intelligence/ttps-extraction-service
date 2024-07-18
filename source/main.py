import json
import openai
import time
from dotenv import load_dotenv
import os
import argparse
from pymongo import MongoClient
import logging
import re

# Load environment variables
load_dotenv()

# Initialize OpenAI API client
# api_key = "7bfdf01df34743a5b00b15ecdf89457d" #YOUR_OPENAI_API_KEY
# openai.api_key = api_key

client = openai.AzureOpenAI(
  azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT"), 
  api_key=os.getenv("AZURE_OPENAI_API_KEY"),  
  api_version="2024-02-01"
)

# Configure logging
logging.basicConfig(level=logging.WARNING,  # Set to WARNING to hide INFO logs
                    format='%(asctime)s %(levelname)s %(message)s',
                    handlers=[logging.FileHandler('main.log'), logging.StreamHandler()])


# def extract_iocs(content):
#     prompt = f"Extract all thge IOCs from the content:\n\n{content}\n\nIOCs:"

#     response = client.chat.completions.create(
#         model="TTPmodel",  # Specify your desired model here
#         messages=[
#             {"role": "system", "content": prompt}
#         ],
#         # max_tokens=1500,
#         stop=None,
#         temperature=0.5,
#     )

        
#     return response.choices[0].message.content.strip().split('\n')

def extract_ip_addresses(content):
    prompt = f"Extract all the IP Address from the content and if there are no IP addresses present return are 'No IP addresses are present.':\n\n{content}\n\nIP Addresses:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )
        
    result = response.choices[0].message.content.strip().split('\n')
    return result if "No IP addresses are present." not in result else []


def extract_file_hashes(content):
    prompt = f"Extract all the file hashes (MD5, SHA-1, SHA-256) from the content and if there are no hash files are present return 'No file hashes are present.':\n\n{content}\n\nFile Hashes:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

        
    result = response.choices[0].message.content.strip().split('\n')
    return result if "No file hashes are present." not in result else []


def extract_domain_names(content):
    prompt = f"Extract all the domain names from the content and if there are no domain names are present return 'No domain names are present.':\n\n{content}\n\nDomain Names:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )
 
    result = response.choices[0].message.content.strip().split('\n')
    return result if "No domain names are present." not in result else []


def extract_email_addresses(content):
    prompt = f"Extract all the email addresses from the content and if there are no email addresses are present return 'No email addresses are present.':\n\n{content}\n\nEmail Addresses:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

        
    result = response.choices[0].message.content.strip().split('\n')
    return result if "No email addresses are present." not in result else []

def extract_urls(content):
    prompt = f"Extract all the URLs from the content and if there are no URLs are present return 'No URLS are present.':\n\n{content}\n\nURLs:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

    result = response.choices[0].message.content.strip().split('\n')
    return result if "No URLs are present." not in result else []

def extract_registry_keys(content):
    prompt = f"Extract all the registry keys from the content and if there are no registry keys are present return 'No registry keys are present.':\n\n{content}\n\nRegistry Keys:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

    result = response.choices[0].message.content.strip().split('\n')
    return result if "No registry keys are present." not in result else []


def map_iocs_to_ttps(iocs):
    # ttps = []
    # for ioc in iocs:
    prompt = prompt = (
        "Based on the following Indicators of Compromise (IoCs), list all possible Tactics, Techniques, and Procedures (TTPs) "
        "that could be associated with these IoCs according to the MITRE ATT&CK framework. Please format your response with clear bullet points as follows:\n\n"
        "Tactics:\n"
        "- **Tactic Name (TID):** Brief description of how the IoCs relate to this tactic.\n\n"
        "Techniques:\n"
        "- **Technique Name (TID):** Brief description of how it is used in relation to the IoCs.\n\n"
        "Procedures:\n"
        "- **Procedure Name:** Brief description of how the IoCs are used in this procedure.\n\n"
        "Here are the IoCs:\n\n"
        f"{(iocs)}\n\n"
        "Provide your response in the following structured format:\n\n"
        "### Tactics:\n"
        "- Tactic Name (TID): Description.\n\n"
        "### Techniques:\n"
        "- Technique Name (TID): Description.\n\n"
        "### Procedures:\n"
        "- Procedure Name: Description.\n\n"
    )

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

        
    return response.choices[0].message.content.strip()

def parse_ttp_response(response_text):
    # Initialize dictionary to store TTPs
    ttp_dict = {'Tactics': [], 'Techniques': [], 'Procedures': []}
    
    # Define section headers
    section_headers = {
        'Tactics': re.compile(r'^###\s*Tactics:', re.IGNORECASE),
        'Techniques': re.compile(r'^###\s*Techniques:', re.IGNORECASE),
        'Procedures': re.compile(r'^###\s*Procedures:', re.IGNORECASE)
    }
    
    # Initialize the current section
    current_section = None

    # Split the response text by newlines and process each line
    lines = response_text.strip().split('\n')
    for line in lines:
        line = line.strip()

        # Check if the line starts a new section
        for section_name, pattern in section_headers.items():
            if pattern.match(line):
                current_section = section_name
                continue

        # Add lines to the current section if it's set
        if current_section:
            # Check if line is part of a list item
            if line.startswith('- **'):
                ttp_dict[current_section].append(line)
                
    return ttp_dict


def process_osint_file(file_path, num_records):
    with open(file_path, 'r') as file:
        data = json.load(file)
        # print(data[0])

    results = []
    for i, article in enumerate(data[:num_records]):
        # article_content = article.get('description', '')
        # content = [content['content'] for content in article.get('content', [])]
        content = article.get('content', '')
        # Parse the HTML content
        # soup = BeautifulSoup(content, 'lxml')
        # # Extract and join the text content
        # text_content = ' '.join(soup.stripped_strings)
        file_hashes = extract_file_hashes(content)
        ip_addresses = extract_ip_addresses(content)
        domain_names = extract_domain_names(content)
        email_addresses = extract_email_addresses(content)
        urls = extract_urls(content)
        registry_keys = extract_registry_keys(content)

        iocs = {
                'ip_addresses': ip_addresses,
                'file_hashes': file_hashes,
                'domain_names': domain_names,
                'email_addresses': email_addresses,
                'urls': urls,
                'registry_keys': registry_keys
            }
        
        # If no IOCs are found, skip the document
        if all(not iocs[key] for key in iocs):
            logging.info(f"No IOCs found in the article '{article.get('URL', '')}'. Skipping...")
            continue
        
        ttp = map_iocs_to_ttps(iocs)
        print(ttp)
        # Parse the response into structured data
        ttp_data = parse_ttp_response(ttp)
        results.append({
            'title': article.get('title'),
            'article_author': article.get('author'),
            'URL': article.get('URL', ''),
            'iocs': iocs,
            'ttp' : ttp_data,
        })

    return results

def save_to_mongodb(data_list, connection_string, db_name, collection_name):
    client = MongoClient(connection_string)
    db = client[db_name]
    collection = db[collection_name]
    
    # Insert each document in the list
    inserted_ids = []
    for data in data_list:
        result = collection.insert_one(data)
        inserted_ids.append(result.inserted_id)
    
    print(f"Data inserted with record ids: {inserted_ids}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process OSINT JSON file to extract IoCs and deduce TTPs.')
    parser.add_argument('input_file', type=str, help='Path to the input JSON file')
    parser.add_argument('output_file', type=str, help='Path to the output JSON file')
    parser.add_argument('--num_records', type=int, default=8, help='Number of records to process')


    args = parser.parse_args()

    result = process_osint_file(args.input_file, args.num_records)

    with open(args.output_file, 'w') as outfile:
        json.dump(result, outfile, indent=4)

    print(f"Processed {args.input_file} and saved results to {args.output_file}")

    # Save to MongoDB Cosmos DB
    # connection_string = "mongodb+srv://Haritik:Proj%40123@tiacosmosdb.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000"
    # db_name = "Threat_Intelligence"
    # collection_name = "ioc-ttp-collection"

    # save_to_mongodb(result, connection_string, db_name, collection_name)