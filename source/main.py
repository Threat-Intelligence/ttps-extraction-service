import json
import openai
import time
from dotenv import load_dotenv
import os
import argparse
from pymongo import MongoClient


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

def extract_iocs(content):
    prompt = f"Extract all thge IOCs from the content:\n\n{content}\n\nIOCs:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

        
    return response.choices[0].message.content.strip().split('\n')


def map_iocs_to_ttps(iocs):
    # ttps = []
    # for ioc in iocs:
    prompt = f"List out all possible Tactics, Techniques, and Procedures related to the following IoC using MITRE ATTACK framework :\n\n{iocs}\n\nTTPs:"

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

        
    return response.choices[0].message.content.strip().split('\n')

def summary_extraction(iocs,ttp,content):
    # ttps = []
    # for ioc in iocs:
    prompt = f"Frame a detail executable summary of {iocs} and {ttp} of the following event: {content} "

    response = client.chat.completions.create(
        model="TTPmodel",  # Specify your desired model here
        messages=[
            {"role": "system", "content": prompt}
        ],
        # max_tokens=1500,
        stop=None,
        temperature=0.5,
    )

        
    return response.choices[0].message.content.strip().split('\n')

def process_osint_file(file_path, num_records):
    with open(file_path, 'r') as file:
        data = json.load(file)
        print(data[0])

    results = []
    for i, article in enumerate(data[:num_records]):
        # article_content = article.get('description', '')
        # content = [content['content'] for content in article.get('content', [])]
        content = article.get('content', '')
        # Parse the HTML content
        # soup = BeautifulSoup(content, 'lxml')
        # # Extract and join the text content
        # text_content = ' '.join(soup.stripped_strings)
        print(content)
        iocs = extract_iocs(content)
        print(iocs)
        ttp = map_iocs_to_ttps(iocs)
        summary = summary_extraction(iocs,ttp,content)
        results.append({
            'article_author': article.get('author'),
            'URL': article.get('URL', ''),
            'iocs': iocs,
            'ttp' : ttp,
            'summary' : summary
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