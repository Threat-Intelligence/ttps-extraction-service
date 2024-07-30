import os
import json
import logging
from flask import Flask, jsonify, request
from pymongo import MongoClient
from collections import defaultdict

from ioc_extraction_service import IocExtractionService
from ttp_extraction_service import TtpExtractionService
from actor_extraction_service import ActorExtractionService

class ApiService:
    def __init__(self, app, db_client, ioc_service, ttp_service, actor_service):
        self.app = app
        self.db_client = db_client
        self.ioc_service = ioc_service
        self.ttp_service = ttp_service
        self.actor_service = actor_service
        self.db = db_client[os.getenv('MONGODB_DATABASE')]
        self.source_collection = self.db["crawler_data"]
        self.target_collection = self.db["ioc-ttp-collection"]
        self.actors_data_collection = self.db["actors_data"]

        self._setup_routes()

    def _setup_routes(self):
        @self.app.route('/', methods=['GET'])
        def index():
            return jsonify({"message": "Welcome to the IOC and TTP API"}), 200

        @self.app.route('/ioc-ttp-collections', methods=['GET'])
        def fetch_process_update_route():
            success, message = self.fetch_process_update()
            if success:
                return jsonify({"message": "Data fetched, processed, and saved to ioc-ttp-collection successfully for the first 50 documents."}), 200
            else:
                return jsonify({"error": message}), 500

        @self.app.route('/ttp/<id>', methods=['GET'])
        def get_ttp(id):
            try:
                ttp = self.target_collection.find_one({"article_id": id})
                if ttp:
                    return jsonify(self.serialize_doc(ttp)), 200
                else:
                    return jsonify({"error": "TTP not found"}), 404
            except Exception as e:
                logging.error(f"Error fetching TTP with ID {id}: {str(e)}")
                return jsonify({"error": str(e)}), 400

        @self.app.route('/ttps', methods=['GET'])
        def get_all_ttps():
            try:
                ttps = self.target_collection.find()
                ttps_list = [self.serialize_doc(doc) for doc in ttps]
                return jsonify(ttps_list), 200
            except Exception as e:
                logging.error(f"Error fetching all TTPs: {str(e)}")
                return jsonify({"error": str(e)}), 500

    def serialize_doc(self, doc):
        if "_id" in doc:
            doc['_id'] = str(doc['_id'])
        return doc

    def fetch_process_update(self):
        try:
            logging.info("Fetching data from the database.")
            documents = list(self.source_collection.find().limit(20))
            results = []
            for doc in documents:
                content = doc.get('content', '')
                article_id = str(doc.get('_id'))
                if not content:
                    logging.info(f"Skipping document with ID {article_id} due to empty content.")
                    continue
                logging.info(f"Extracting IOCs for article '{doc.get('URL', '')}'")
                iocs = {
                    'ip_addresses': self.ioc_service.extract_ip_addresses(content),
                    'file_hashes': self.ioc_service.extract_file_hashes(content),
                    'domain_names': self.ioc_service.extract_domain_names(content),
                    'email_addresses': self.ioc_service.extract_email_addresses(content),
                    'urls': self.ioc_service.extract_urls(content),
                    'registry_keys': self.ioc_service.extract_registry_keys(content)
                }
                if all(not iocs[key] for key in iocs):
                    logging.info(f"No IOCs found in the article '{doc.get('URL', '')}'. Skipping...")
                    continue

                logging.info(f"Collecting TTPs for article '{doc.get('URL', '')}'")
                ttp = self.ttp_service.map_iocs_to_ttps(iocs)
                ttp_data = self.ttp_service.parse_ttp_response(ttp)
                actors = self.actor_service.extract_actors(content)
                self.target_collection.insert_one({
                    'article_id': article_id,
                    'title': doc.get('title'),
                    'article_author': doc.get('author'),
                    'URL': doc.get('URL', ''),
                    'iocs': iocs,
                    'ttp': ttp_data,
                    'actors': actors
                })
                logging.info("Saved IoCs and TTPs to the database.")
                results.append({
                    'article_id': article_id,
                    'title': doc.get('title'),
                    'article_author': doc.get('author'),
                    'URL': doc.get('URL', ''),
                    'iocs': iocs,
                    'ttp': ttp_data,
                    'actors': actors
                })
                logging.info("Saved IoCs and TTPs to locally")
            with open('processed_results.json', 'w') as outfile:
                json.dump(results, outfile, indent=4)
            logging.info("Data processed and saved successfully.")
            return True, None
        except Exception as e:
            logging.error(f"Error in fetch_process_update: {str(e)}")
            return False, str(e)
