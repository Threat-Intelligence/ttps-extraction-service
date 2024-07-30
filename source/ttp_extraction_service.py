import re

class TtpExtractionService:
    def __init__(self, openai_client):
        self.openai_client = openai_client

    # Prompt to extract TTPs from the IoCs 
    def map_iocs_to_ttps(self, iocs):
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
            f"{iocs}\n\n"
            "Provide your response in the following structured format:\n\n"
            "### Tactics:\n"
            "- Tactic Name (TID): Description.\n\n"
            "### Techniques:\n"
            "- Technique Name (TID): Description.\n\n"
            "### Procedures:\n"
            "- Procedure Name: Description.\n\n"
        )

        response = self.openai_client.chat.completions.create(
            model="TTPmodel", # gpt-4-0125-Preview
            messages=[{"role": "system", "content": prompt}],
            temperature=0.5,
        )

        return response.choices[0].message.content.strip()
    
    #Function to categories prompt into Tactis, Techniques and Procedures.
    def parse_ttp_response(self, response_text):
        ttp_dict = {'Tactics': [], 'Techniques': [], 'Procedures': []}
        section_headers = {
            'Tactics': re.compile(r'^###\s*Tactics:', re.IGNORECASE),
            'Techniques': re.compile(r'^###\s*Techniques:', re.IGNORECASE),
            'Procedures': re.compile(r'^###\s*Procedures:', re.IGNORECASE)
        }
        current_section = None
        lines = response_text.strip().split('\n')

        for line in lines:
            line = line.strip()
            for section_name, pattern in section_headers.items():
                if pattern.match(line):
                    current_section = section_name
                    continue
            if current_section:
                if line.startswith('- **'):
                    ttp_dict[current_section].append(line)

        return ttp_dict
