import ahocorasick
from collections import defaultdict
import logging

class ActorExtractionService:
    def __init__(self, actors_data_collection):
        self.actors_data_collection = actors_data_collection

    #Function to extract actors using Aho–Corasick algorithm
    def extract_actors(self, content):
        logging.info("Fetching actors list")
        known_actors = list(self.actors_data_collection.find())
        actors_present = defaultdict(lambda: {"id": "", "aliases": set()})
        automaton = ahocorasick.Automaton()

        for actor in known_actors:
            name = actor.get('name', '')
            actor_id = str(actor.get('_id', ''))
            aliases = actor.get('alias', '')
            if name and actor_id:
                automaton.add_word(name, (name, actor_id, name))
            if aliases:
                for alias in aliases.split(', '):
                    automaton.add_word(alias, (name, actor_id, alias))

        automaton.make_automaton()

        for _, (name, actor_id, alias) in automaton.iter(content):
            actors_present[name]["id"] = actor_id
            actors_present[name]["aliases"].add(alias)

        return [{'name': name, 'id': details["id"], 'aliases': list(details["aliases"])} for name, details in actors_present.items()]
