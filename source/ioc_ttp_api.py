from flask import Flask, jsonify, request
import openai
from dotenv import load_dotenv
import os
from pymongo import MongoClient
from bson import ObjectId
import json
import logging
import re
import ahocorasick
from collections import defaultdict

# Load environment variables
load_dotenv()



# MongoDB connection setup
# connection_string = os.getenv('MONGODB_CONNECTION_STRING')
connection_string = "mongodb+srv://Haritik:Proj%40123@tiacosmosdb.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000"
db_name = os.getenv('MONGODB_DATABASE')

if not connection_string or not db_name:
    raise ValueError("MongoDB connection details are not set. Please set the MONGODB_CONNECTION_STRING and MONGODB_DATABASE environment variables.")

# Initialize OpenAI API client
openai_client = openai.AzureOpenAI(
  azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT"), 
  api_key=os.getenv("AZURE_OPENAI_API_KEY"),  
  api_version="2024-02-01"
)

db_client = MongoClient(connection_string)
db = db_client[db_name]
source_collection = db["crawler_data"]
target_collection = db["ioc-ttp-collection"]  # New collection name for saving IoCs and TTPs
actors_data_collection = db["actors_data"]


# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,  # Set to INFO for relevant logging
                    format='%(asctime)s %(levelname)s %(message)s',
                    handlers=[logging.FileHandler('flask_api.log'), logging.StreamHandler()])

# Suppress logging from http.client and urllib3
logging.getLogger('http.client').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Middleware to log requests
@app.before_request
def log_request_info():
    logging.info(f"Received {request.method} request for {request.url}")

# Middleware to log responses
@app.after_request
def log_response_info(response):
    logging.info(f"Responding with status {response.status_code} for {request.url}")
    return response

def serialize_doc(doc):
    """Helper function to serialize MongoDB documents to JSON, converting ObjectId to str."""
    if "_id" in doc:
        doc['_id'] = str(doc['_id'])  # Convert ObjectId to str for easier handling in UI
    return doc


def extract_ip_addresses(content):
    prompt = f"Extract all the IP Address from the content and if there are no IP addresses present return are 'No IP addresses are present.':\n\n{content}\n\nIP Addresses:(List of all the values as comma seperated)"

    response = openai_client.chat.completions.create(
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
    prompt = f"Extract all the file hashes (MD5, SHA-1, SHA-256) from the content and if there are no hash files are present return 'No file hashes are present.':\n\n{content}\n\nFile Hashes:(List of all the values as comma seperated)"

    response = openai_client.chat.completions.create(
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
    prompt = f"Extract all the domain names from the content and if there are no domain names are present return 'No domain names are present.':\n\n{content}\n\nDomain Names:(List of all the values as comma seperated)"

    response = openai_client.chat.completions.create(
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
    prompt = f"Extract all the email addresses from the content and if there are no email addresses are present return 'No email addresses are present.':\n\n{content}\n\nEmail Addresses:(List of all the values as comma seperated)"

    response = openai_client.chat.completions.create(
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
    prompt = f"Extract all the URLs from the content and if there are no URLs are present return 'No URLS are present.':\n\n{content}\n\nURLs:(List of all the values as comma seperated)"

    response = openai_client.chat.completions.create(
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
    prompt = f"Extract all the registry keys from the content and if there are no registry keys are present return 'No registry keys are present.':\n\n{content}\n\nRegistry Keys:(List of all the values as comma seperated)"

    response = openai_client.chat.completions.create(
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


# def extract_actors(content, known_actors):
#     actors_present = set()

#     automaton = ahocorasick.Automaton()
#     for actor in known_actors:
#         name = actor.get('name', '')
#         actor_id = str(actor.get('_id', ''))
#         if name and actor_id:
#             automaton.add_word(name, (name, actor_id))

#     automaton.make_automaton()

#     for _, (name, actor_id) in automaton.iter(content):
#         actors_present.add((name, actor_id))

#     # Convert set back to list of dictionaries
#     return [{'name': name, 'id': actor_id} for name, actor_id in actors_present]

def extract_actors(content, known_actors):
    actors_present = defaultdict(lambda: {"id": "", "aliases": set()})
    
    # Initialize the Aho-Corasick automaton
    automaton = ahocorasick.Automaton()
    
    for actor in known_actors:
        name = actor.get('name', '')
        actor_id = str(actor.get('_id', ''))
        aliases = actor.get('alias', '')

        # Add the actor's name to the automaton
        if name and actor_id:
            automaton.add_word(name, (name, actor_id, name))
        
        # Add aliases to the automaton
        if aliases:
            for alias in aliases.split(', '):
                automaton.add_word(alias, (name, actor_id, alias))
    
    automaton.make_automaton()
    
    # Extract matches from the content
    for _, (name, actor_id, alias) in automaton.iter(content):
        actors_present[name]["id"] = actor_id
        actors_present[name]["aliases"].add(alias)
    
    # Format the result
    return [{'name': name, 'id': details["id"], 'aliases': list(details["aliases"])} for name, details in actors_present.items()]


# Function to map IoCs to TTPs using OpenAI
def map_iocs_to_ttps(iocs):
    # ttps = []
    # for ioc in iocs:
    prompt = (
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

    response = openai_client.chat.completions.create(
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

# Function to fetch data from MongoDB, process, and update
def fetch_process_update():
    try:


        delete_result = target_collection.delete_many({})
        print(f"Deleted {delete_result.deleted_count} documents from the collection.")
        # Fetch first 8 documents from the source collection
        logging.info("Fetching data from the database.")
        documents = list(source_collection.find().limit(60))

        logging.info("Fetching actors list")
        know_actors = list(actors_data_collection.find())
        print(know_actors[0])


        # Process each document
        results = []
        for doc in documents:
            content = doc.get('content', '')
            article_id = str(doc.get('_id', ''))
            # logging.info(f"Extracted IoCs: {iocs}")
            
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
                logging.info(f"No IOCs found in the article '{doc.get('URL', '')}'. Skipping...")
                continue
            
            logging.info(f"Collecting TTPs for article '{doc.get('URL', '')}'")
            ttp = map_iocs_to_ttps(iocs)
            # Parse the response into structured data
            ttp_data = parse_ttp_response(ttp)
            actors = extract_actors(content, know_actors)
            
            
            # Save IoCs and TTPs to the new collection
            target_collection.insert_one({
                'article_id': article_id,
                'title': doc.get('title'),
                'article_author': doc.get('author'),
                'URL': doc.get('URL', ''),
                'iocs': iocs,
                'ttp' : ttp_data,
                'actors' : actors
            })
            logging.info("Saved IoCs and TTPs to the database.")
            
            # Prepare result for local saving
            results.append({
                'article_id': article_id,
                'title': doc.get('title'),
                'article_author': doc.get('author'),
                'URL': doc.get('URL', ''),
                'iocs': iocs,
                'ttp' : ttp_data,
                'actors': actors
            })

        # Save results to a local JSON file
        with open('processed_results.json', 'w') as outfile:
            json.dump(results, outfile, indent=4)

        logging.info("Data processed and saved successfully.")
        return True, None
    except Exception as e:
        logging.error(f"Error in fetch_process_update: {str(e)}")
        return False, str(e)
    
# Root endpoint for testing
@app.route('/', methods=['GET'])
def index():
    return jsonify({"message": "Welcome to the IOC and TTP API"}), 200

# Route to fetch and process first 8 documents with IoCs and generate TTPs
@app.route('/ioc-ttp-collections', methods=['GET'])
def fetch_process_update_route():
    success, message = fetch_process_update()
    if success:
        return jsonify({"message": "Data fetched, processed, and saved to ioc-ttp-collection successfully for the first 50 documents."}), 200
    else:
        return jsonify({"error": message}), 500

# Additional routes to fetch the processed data

@app.route('/ttp/<id>', methods=['GET'])
def get_ttp(id):
    try:
        ttp = target_collection.find_one({"article_id": id})
        if ttp:
            return jsonify(serialize_doc(ttp)), 200
        else:
            return jsonify({"error": "TTP not found"}), 404
    except Exception as e:
        logging.error(f"Error fetching TTP with ID {id}: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/ttps', methods=['GET'])
def get_all_ttps():
    try:
        ttps = target_collection.find()
        ttps_list = [serialize_doc(doc) for doc in ttps]
        return jsonify(ttps_list), 200
    except Exception as e:
        logging.error(f"Error fetching all TTPs: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False, port=5000)
