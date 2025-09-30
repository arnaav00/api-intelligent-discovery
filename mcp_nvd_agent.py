from strands import Agent, tool
import time, os, json
from datetime import timedelta, datetime
import requests
import chromadb
from chromadb.config import Settings

chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(
            name="mcp_data",
            metadata={"description": "MCP-related vulnerability data from CVE and GitHub advisories"}
        )
        
def search_latest_cves():
    """Search for latest CVE-2025 vulnerabilities"""

    # NVD API endpoint
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=MCP&pubStartDate=2025-09-15T00:00:00.000&pubEndDate=2025-09-16T00:00:00.000"

    try:
        response = requests.get(base_url, timeout=30)
        response.raise_for_status()
        data = response.json()
        count = len(data.get("vulnerabilities", []))
        print("Retrieved:", count)
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs: {e}")
        return None

@tool
def write_to_chroma(response):
    """
    Write normalized vulnerability data to ChromaDB
    """
    try:
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
                
                # Create metadata
                metadata = {
                    "id": vuln_id,
                    "title": title,
                    "severity": severity,
                    "source": source,
                    "cvss_score": vuln.get('cvss_score', 0.0),
                    "published_date": vuln.get('published_date', ''),
                    "mcp_relevant": vuln.get('mcp_relevant', False),
                    "exploit_available": vuln.get('exploit_available', False),
                    "affected_components": ', '.join(vuln.get('affected_components', [])),
                    "tags": ', '.join(tags) if tags else '',
                    "poc_url": vuln.get('poc_url', '')
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

# @tool
# def write_to_chromab(response):
#     write_to_chroma(response)

@tool    
def call_nvd_search():
    return search_latest_cves()

if __name__ == "__main__":

    start_time = time.time()
    nvd_agent = Agent(  
    name="nvd_intelligence_agent",  
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
    tools = [call_nvd_search, write_to_chroma],
    )
    response = nvd_agent("Fetch the latest CVE vulnerabilities")
    end_time = time.time()

    total_time = round(end_time - start_time, 2)
    print(f"\nInput tokens: {response.metrics.accumulated_usage.get('inputTokens', 0)}")
    print(f"Output tokens: {response.metrics.accumulated_usage.get('outputTokens', 0)}")
    print(f"Total tokens: {response.metrics.accumulated_usage.get('totalTokens', 0)}")
    print(f"Total time taken: {total_time}s\n")


