import json
from pymongo import MongoClient

# MongoDB connection string
connection_string = "mongodb+srv://Haritik:Proj%40123@tiacosmosdb.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000"
db_name = "Threat_Intelligence"
collection_name = "crawler_data"

def insert_json_to_mongodb(file_path, connection_string, db_name, collection_name):
    # Read JSON data from file
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    # Connect to MongoDB
    client = MongoClient(connection_string)
    db = client[db_name]
    collection = db[collection_name]
    
    # Insert each document into the collection
    inserted_ids = []
    for document in data:
        result = collection.insert_one(document)
        inserted_ids.append(result.inserted_id)
    
    print(f"Data inserted with record ids: {inserted_ids}")
    
    # Close MongoDB connection
    client.close()

if __name__ == "__main__":
    # Path to the JSON file containing the data to insert
    file_path = "/Users/swapnil/Documents/FinalProject/OpenAI TIA/TTPExtraction/data.json"
    
    # Insert data into MongoDB
    insert_json_to_mongodb(file_path, connection_string, db_name, collection_name)

