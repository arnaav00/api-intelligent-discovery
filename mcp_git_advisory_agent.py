import os
import requests
import json
from strands import Agent, tool
import time, os, json
import chromadb

def fetch_mcp_advisories():
    url = "https://api.github.com/advisories"

    response = requests.get(url)
    response.raise_for_status()
    advisories = response.json()

    filtered = [adv for adv in advisories if adv.get("description") and "MCP" in adv["description"]]
    print(f"Filtered advisories containing 'MCP': {len(filtered)}")
    return filtered

@tool
def write_to_chroma(response):
    """
    Write normalized vulnerability data to ChromaDB
    """
    try:
        chroma_client = chromadb.PersistentClient(path="./chroma_db")
        collection = chroma_client.get_or_create_collection(
            name="mcp_data",
            metadata={"description": "MCP-related vulnerability data from CVE and GitHub advisories"}
        )
        
        # Parse the response to extract vulnerability data
        if isinstance(response, str):
            try:
                # Try to parse as JSON if it's a string
                vulnerabilities = json.loads(response)
                if not isinstance(vulnerabilities, list):
                    vulnerabilities = [vulnerabilities]
            except json.JSONDecodeError:
                # If not JSON, assume it's a single vulnerability description
                vulnerabilities = [{"description": response, "id": f"temp_{int(time.time())}"}]
        elif isinstance(response, list):
            vulnerabilities = response
        else:
            vulnerabilities = [response]
        
        # Get existing IDs to prevent duplicates
        existing_records = collection.get()
        existing_ids = set(existing_records['ids']) if existing_records['ids'] else set()
        
        # Process each vulnerability
        documents = []
        metadatas = []
        ids = []
        duplicates_skipped = 0
        
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                # Extract data for ChromaDB
                vuln_id = vuln.get('id', f"unknown_{int(time.time())}")
                
                # Skip if ID already exists
                if vuln_id in existing_ids:
                    duplicates_skipped += 1
                    continue
                
                title = vuln.get('title', '')
                description = vuln.get('description', '')
                severity = vuln.get('severity', 'UNKNOWN')
                source = vuln.get('source', 'UNKNOWN')
                tags = vuln.get('tags', [])
                
                # Create document text for embedding
                doc_text = f"Title: {title}\nDescription: {description}\nSeverity: {severity}\nSource: {source}\nTags: {', '.join(tags) if tags else 'None'}"
                
                # Create metadata - ensure no None values
                cvss_score = vuln.get('cvss_score')
                if cvss_score is None:
                    cvss_score = 0.0
                
                published_date = vuln.get('published_date')
                if published_date is None:
                    published_date = ''
                
                mcp_relevant = vuln.get('mcp_relevant')
                
                exploit_available = vuln.get('exploit_available')
                if exploit_available is None:
                    exploit_available = False
                
                affected_components = vuln.get('affected_components', [])
                if affected_components is None:
                    affected_components = []
                
                poc_url = vuln.get('poc_url')
                if poc_url is None:
                    poc_url = ''
                
                metadata = {
                    "id": str(vuln_id),
                    "title": str(title) if title else '',
                    "severity": str(severity) if severity else 'UNKNOWN',
                    "source": str(source) if source else 'UNKNOWN',
                    "cvss_score": float(cvss_score),
                    "published_date": str(published_date),
                    "mcp_relevant": str(mcp_relevant),
                    "exploit_available": bool(exploit_available),
                    "affected_components": ', '.join(affected_components) if affected_components else '',
                    "tags": ', '.join(tags) if tags else '',
                    "poc_url": str(poc_url)
                }
                
                documents.append(doc_text)
                metadatas.append(metadata)
                ids.append(vuln_id)
                existing_ids.add(vuln_id)  # Add to set to prevent duplicates within this batch
        
        # Add to ChromaDB collection
        if documents:
            collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            print(f"Successfully added {len(documents)} vulnerabilities to ChromaDB (skipped {duplicates_skipped} duplicates)")
            return f"Successfully added {len(documents)} vulnerabilities to ChromaDB (skipped {duplicates_skipped} duplicates)"
        else:
            print(f"No new vulnerabilities to add (skipped {duplicates_skipped} duplicates)")
            return f"No new vulnerabilities to add (skipped {duplicates_skipped} duplicates)"
            
    except Exception as e:
        print(f"Error writing to ChromaDB: {e}")
        return f"Error writing to ChromaDB: {e}"


@tool    
def call_git_search():
    return fetch_mcp_advisories()

if __name__ == "__main__":

    start_time = time.time()
    git_agent = Agent(  
    name="gitadvisory_intelligence_agent",  
    system_prompt="""You are specialized Intelligence Gathering Agent that can
    1. Search NVD to pull some of the latest MCP-related vulnerabilities
    2. Normalize data into standard format 

    Based on each discovery data individually, ask yourself "Can this vulnerability be harvested in any other MCPs generically as well?" for each.
    ONLY if you STRONGLY feel it does, make _relevant 'true'. Do not output your reasoning for this step.

    Normalize and return each discovery in the following example JSON format:

    {
    "source": "NVD", 
    "id": "CVE-2024-XXXX",
    "title": "OS Command Injection via Shell Invocation in MCP Server Components",
    "severity": "HIGH|CRITICAL|MEDIUM|LOW",
    "cvss_score": 8.5,
    "description": "Detailed vulnerability description",
    "affected_components": ["REST", "GraphQL", "JSON"],
    "exploit_available": true,
    "poc_url": "https://github.com/...",
    "published_date": "YYYY-MM-DD",
    "mcp_relevant": <one sentence explanation of why vulnerability is MCP relevant>,
    "tags": ["injection", "authentication", "jwt"]
    },

    Write all the normalized JSONs into a chroma database. Do NOT provide a summary at the end.
    """,
    tools = [call_git_search, write_to_chroma],
    )

    response = git_agent("Fetch the latest CVE vulnerabilities")
    end_time = time.time()

    total_time = round(end_time - start_time, 2)
    print(f"\nInput tokens: {response.metrics.accumulated_usage.get('inputTokens', 0)}")
    print(f"Output tokens: {response.metrics.accumulated_usage.get('outputTokens', 0)}")
    print(f"Total tokens: {response.metrics.accumulated_usage.get('totalTokens', 0)}")
    print(f"Total time taken: {total_time}s\n")



