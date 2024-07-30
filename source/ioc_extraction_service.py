import openai

class IocExtractionService:
    def __init__(self, openai_client):
        self.openai_client = openai_client


    # Prompt function to extract IP Addresses.
    def extract_ip_addresses(self,content):
        prompt = f"Extract all the IP Address from the content and if there are no IP addresses present return are 'No IP addresses are present.':\n\n{content}\n\nIP Addresses:(List of all the values as comma seperated)"

        response = self.openai_client.chat.completions.create(
            model="TTPmodel",  # gpt-4-0125-Preview
            messages=[
                {"role": "system", "content": prompt}
            ],
            stop=None,
            temperature=0.5,
        )
            
        result = response.choices[0].message.content.strip().split('\n')
        return result if "No IP addresses are present." not in result else []

    # Prompt function to extract File Hashes. 
    def extract_file_hashes(self,content):
        prompt = f"Extract all the file hashes (MD5, SHA-1, SHA-256) from the content and if there are no hash files are present return 'No file hashes are present.':\n\n{content}\n\nFile Hashes:(List of all the values as comma seperated)"

        response = self.openai_client.chat.completions.create(
            model="TTPmodel",  # gpt-4-0125-Preview
            messages=[
                {"role": "system", "content": prompt}
            ],
            stop=None,
            temperature=0.5,
        )

            
        result = response.choices[0].message.content.strip().split('\n')
        return result if "No file hashes are present." not in result else []

    # Prompt function to extract Domain Names. 
    def extract_domain_names(self,content):
        prompt = f"Extract all the domain names from the content and if there are no domain names are present return 'No domain names are present.':\n\n{content}\n\nDomain Names:(List of all the values as comma seperated)"

        response = self.openai_client.chat.completions.create(
            model="TTPmodel",  # gpt-4-0125-Preview
            messages=[
                {"role": "system", "content": prompt}
            ],
            stop=None,
            temperature=0.5,
        )
    
        result = response.choices[0].message.content.strip().split('\n')
        return result if "No domain names are present." not in result else []

    # Prompt function to extract Email Addresses.
    def extract_email_addresses(self,content):
        prompt = f"Extract all the email addresses from the content and if there are no email addresses are present return 'No email addresses are present.':\n\n{content}\n\nEmail Addresses:(List of all the values as comma seperated)"

        response = self.openai_client.chat.completions.create(
            model="TTPmodel",  # gpt-4-0125-Preview
            messages=[
                {"role": "system", "content": prompt}
            ],
            stop=None,
            temperature=0.5,
        )

            
        result = response.choices[0].message.content.strip().split('\n')
        return result if "No email addresses are present." not in result else []
    
    # Prompt function to extract URLs. 
    def extract_urls(self,content):
        prompt = f"Extract all the URLs from the content and if there are no URLs are present return 'No URLS are present.':\n\n{content}\n\nURLs:(List of all the values as comma seperated)"

        response = self.openai_client.chat.completions.create(
            model="TTPmodel",  # gpt-4-0125-Preview
            messages=[
                {"role": "system", "content": prompt}
            ],
            stop=None,
            temperature=0.5,
        )

        result = response.choices[0].message.content.strip().split('\n')
        return result if "No URLs are present." not in result else []

    # Prompt function to extract Registry Keys 
    def extract_registry_keys(self,content):
        prompt = f"Extract all the registry keys from the content and if there are no registry keys are present return 'No registry keys are present.':\n\n{content}\n\nRegistry Keys:(List of all the values as comma seperated)"

        response = self.openai_client.chat.completions.create(
            model="TTPmodel",  # gpt-4-0125-Preview
            messages=[
                {"role": "system", "content": prompt}
            ],
            stop=None,
            temperature=0.5,
        )

        result = response.choices[0].message.content.strip().split('\n')
        return result if "No registry keys are present." not in result else []