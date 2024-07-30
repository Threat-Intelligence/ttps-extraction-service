from flask import Flask
import openai
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import logging

from ioc_extraction_service import IocExtractionService
from ttp_extraction_service import TtpExtractionService
from actor_extraction_service import ActorExtractionService
from api_service import ApiService

# Load environment variables
load_dotenv()

# Initialize OpenAI API client
openai_client = openai.AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2024-02-01"
)

# MongoDB connection setup
connection_string = os.getenv('MONGODB_CONNECTION_STRING')
db_client = MongoClient(connection_string)

# Initialize services
ioc_service = IocExtractionService(openai_client)
ttp_service = TtpExtractionService(openai_client)
actor_service = ActorExtractionService(db_client[os.getenv('MONGODB_DATABASE')]["actors_data"])

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', handlers=[logging.FileHandler('flask_api.log'), logging.StreamHandler()])
logging.getLogger('http.client').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
# Suppress OpenAI logs
logging.getLogger('openai').setLevel(logging.WARNING)  # Suppress INFO logs for OpenAI
logging.getLogger("httpx").setLevel(logging.ERROR)
# Initialize and configure API service
api_service = ApiService(app, db_client, ioc_service, ttp_service, actor_service)

if __name__ == '__main__':
    app.run(debug=False, port=5000)
