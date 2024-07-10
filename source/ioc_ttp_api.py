from flask import Flask, jsonify, request
import openai
from dotenv import load_dotenv
import os
from pymongo import MongoClient
from bson import ObjectId
import json
import logging

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

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,  # Set to INFO for relevant logging
                    format='%(asctime)s %(levelname)s %(message)s',
                    handlers=[logging.FileHandler('flask_api.log'), logging.StreamHandler()])

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

def extract_iocs(content):
    prompt = f"Extract all thge IOCs from the content:\n\n{content}\n\nIOCs:"

    response = openai_client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

        
    return response.choices[0].message.content.strip().split('\n')

# Function to map IoCs to TTPs using OpenAI
def map_iocs_to_ttps(iocs):
    logging.info(f"Extracting TTPs for IoCs")
    
    prompt = f"List out all possible Tactics, Techniques, and Procedures related to the following IoC using MITRE ATTACK framework :\n\n{iocs}\n\nTTPs:"

    response = openai_client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        stop=None,
        temperature=0.5,
    )
        
    return response.choices[0].message.content.strip().split('\n')

# Function to fetch data from MongoDB, process, and update
def fetch_process_update():
    try:
        # Fetch first 8 documents from the source collection
        logging.info("Fetching data from the database.")
        documents = list(source_collection.find().limit(8))

        # Process each document
        results = []
        for doc in documents:
            content = doc.get('content', '')
            # logging.info(f"Extracted IoCs: {iocs}")
            
            iocs = extract_iocs(content)
            ttps = map_iocs_to_ttps(iocs)
            # logging.info(f"Extracted TTPs: {ttps}")

            # # Ensure 'name' is a string
            # name = str(doc.get('name', ''))  # Convert to string if not already
            
            # Save IoCs and TTPs to the new collection
            target_collection.insert_one({
                'article_author': doc.get('author'),
                'URL': doc.get('URL', ''),
                'iocs': iocs,
                'ttp' : ttps
            })
            logging.info("Saved IoCs and TTPs to the database.")
            
            # Prepare result for local saving
            results.append({
                'article_author': doc.get('author'),
                'URL': doc.get('URL', ''),
                'iocs': iocs,
                'ttp' : ttps
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
        return jsonify({"message": "Data fetched, processed, and saved to ioc-ttp-collection successfully for the first 8 documents."}), 200
    else:
        return jsonify({"error": message}), 500

# Additional routes to fetch the processed data

@app.route('/ttp/<id>', methods=['GET'])
def get_ttp(id):
    try:
        ttp = target_collection.find_one({"_id": ObjectId(id)})
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
    app.run(debug=True, port=5000)
