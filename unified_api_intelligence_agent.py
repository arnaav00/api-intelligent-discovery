from strands import Agent, tool
import time, os, json
from datetime import timedelta, datetime
import requests
import chromadb
from chromadb.config import Settings
from urllib.parse import urlencode 
from urllib.request import Request, urlopen
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

# Global counter for tracking vulnerabilities added by each agent
agent_vulnerability_counts = {}

# NVD Functions
def search_latest_cves():
    """Search for latest CVE-2025 vulnerabilities"""
    # Get today's date in the required format
    today = datetime.now().strftime("%Y-%m-%d")
    start_date = f"{today}T00:00:00.000"
    end_date = f"{today}T23:59:59.000"
    
    # NVD API endpoint
    base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=API&pubStartDate={start_date}&pubEndDate={end_date}"

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

# GitHub Advisory Functions
def fetch_api_advisories():
    url = "https://api.github.com/advisories"

    response = requests.get(url)
    response.raise_for_status()
    advisories = response.json()

    filtered = [adv for adv in advisories if adv.get("description") and "API" in adv["description"]]
    print(f"Filtered advisories containing 'API': {len(filtered)}")
    return filtered

# HackerOne Functions
# Generate dynamic dates for one week interval (today and 7 days ago)
today = datetime.now().strftime("%Y-%m-%d")
week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
hacktivity_url = (
    f"https://hackerone.com/hacktivity/overview?queryString=api+AND+disclosed%3Atrue+AND+disclosed_at%3A%3E%3D{week_ago}+AND+disclosed_at%3A%3C%3D{today}&sortField=disclosed_at&sortDirection=DESC&pageIndex=0"
)

page_loading_timeout = 10

def extract_reports(raw_reports):
    """Extract report URLs into structured dicts."""
    reports = []
    for raw_report in raw_reports:
        html = raw_report.get_attribute("href")
        if "/reports/" not in html:
            continue
        report = {"link": html}
        reports.append(report)
    return reports

def fetch_reports():
    """Fetch HackerOne reports matching the filter and return as list of dicts."""
    options = ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    driver = Chrome(options=options)

    all_reports = []

    try:
        driver.get(hacktivity_url)
        time.sleep(page_loading_timeout)

        # Initial scrape
        raw_reports = driver.find_elements(By.CLASS_NAME, "routerlink")
        all_reports.extend(extract_reports(raw_reports))

    except Exception as e:
        now = datetime.now().strftime("%Y-%m-%d")
        driver.get_screenshot_as_file(f"error-{now}.png")
        print(f"Error: {e}")
    finally:
        driver.quit()

    return all_reports

# VulDB Functions
def search_vuldb_cves():
    """Search for latest CVE-2025 vulnerabilities"""
    url = 'https://vuldb.com/?api'
    post_fields = { 'apikey': '01c29df14ce03e133c10d7b6ece9415b', 'search': 'API', 'limit':'5','fields': 'source_cve_nvd_summary,vulnerability_cvss3_nvd_basescore'}

    request = Request(url, urlencode(post_fields).encode())
    json_data = urlopen(request).read().decode()
    return json_data

# Zero Day Initiative Functions
def fetch_api_zdi_links():
    url = "https://www.zerodayinitiative.com/rss/published/2025/"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()

    root = ET.fromstring(resp.content)

    # Each <item> is an advisory entry
    items = root.findall(".//item")

    results = []
    for item in items:
        title = item.find("title").text or ""
        desc = item.find("description").text or ""
        link = item.find("link").text or ""
        
        if "API" in title or "API" in desc:
            results.append(link)

    return results

# API Security Functions
def get_latest_post_link():
    url = "https://apisecurity.io/"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    div = soup.find("div", class_="upl-post-title")
    if div and div.a:
        return div.a["href"]
    return None

# Shared write_to_chroma function
def write_to_chroma_internal(response, agent_name="Unknown"):
    """
    Internal function to write normalized vulnerability data to ChromaDB
    """
    try:
        chroma_client = chromadb.PersistentClient(path="./chroma_db")
        collection = chroma_client.get_or_create_collection(
            name="vulnerability_data",
            metadata={"description": "API-related vulnerability data from CVE and GitHub advisories"}
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
            vuln_id = str(vuln.get('id', f"temp_{int(time.time())}"))
            
            # Skip if ID already exists
            if vuln_id in existing_ids:
                duplicates_skipped += 1
                continue
            
            # Ensure all metadata values are properly formatted
            metadata = {
                'source': str(vuln.get('source', 'Unknown')),
                'id': vuln_id,
                'title': str(vuln.get('title', '')),
                'severity': str(vuln.get('severity', 'UNKNOWN')),
                'cvss_score': float(vuln.get('cvss_score', 0.0)),
                'description': str(vuln.get('description', '')),
                'affected_components': str(vuln.get('affected_components', [])),
                'exploit_available': bool(vuln.get('exploit_available', False)),
                'poc_url': str(vuln.get('poc_url', '')),
                'published_date': str(vuln.get('published_date', '')),
                'api_relevant': str(vuln.get('api_relevant', '')),
                'tags': str(vuln.get('tags', []))
            }
            
            # Create document content
            document = f"Source: {metadata['source']}\nID: {metadata['id']}\nTitle: {metadata['title']}\nSeverity: {metadata['severity']}\nCVSS Score: {metadata['cvss_score']}\nDescription: {metadata['description']}\nAffected Components: {metadata['affected_components']}\nExploit Available: {metadata['exploit_available']}\nPOC URL: {metadata['poc_url']}\nPublished Date: {metadata['published_date']}\nAPI Relevant: {metadata['api_relevant']}\nTags: {metadata['tags']}"
            
            documents.append(document)
            metadatas.append(metadata)
            ids.append(vuln_id)
            existing_ids.add(vuln_id)  # Add to set to prevent duplicates within this batch
        
        # Add to ChromaDB
        if documents:
            collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            # Update global counter
            agent_vulnerability_counts[agent_name] = len(documents)
            print(f"{agent_name} completed - {len(documents)} vulnerabilities added to ChromaDB (skipped {duplicates_skipped} duplicates)")
            return f"Successfully added {len(documents)} vulnerabilities to ChromaDB (skipped {duplicates_skipped} duplicates)"
        else:
            # Update global counter with 0
            agent_vulnerability_counts[agent_name] = 0
            print(f"{agent_name} completed - 0 vulnerabilities added (skipped {duplicates_skipped} duplicates)")
            return f"No new vulnerabilities to add (skipped {duplicates_skipped} duplicates)"
        
    except Exception as e:
        print(f"Error writing to ChromaDB: {e}")
        return f"Error writing to ChromaDB: {e}"

# Individual write_to_chroma functions for each agent
@tool
def write_to_chroma_nvd(response):
    return write_to_chroma_internal(response, "NVD Agent")

@tool
def write_to_chroma_git(response):
    return write_to_chroma_internal(response, "GitHub Advisory Agent")

@tool
def write_to_chroma_hackerone(response):
    return write_to_chroma_internal(response, "HackerOne Agent")

@tool
def write_to_chroma_vuldb(response):
    return write_to_chroma_internal(response, "VulDB Agent")

@tool
def write_to_chroma_zeroday(response):
    return write_to_chroma_internal(response, "Zero Day Initiative Agent")

@tool
def write_to_chroma_apisecurity(response):
    return write_to_chroma_internal(response, "API Security Agent")

# Tool functions for each source
@tool    
def call_nvd_search():
    return search_latest_cves()

@tool    
def call_git_search():
    return fetch_api_advisories()

@tool
def fetch_hackerone_links():
    reports = fetch_reports()
    links = []
    for report in reports:
        links.append(report["link"])
    return links

@tool    
def call_vuldb_search():
    return search_vuldb_cves()

@tool    
def call_zeroday_search():
    links = fetch_api_zdi_links()
    advisories = []
    for link in links:
        advisories.append({"link": link})
    return advisories

@tool
def get_apisecurity_content(url):
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    # get the date
    date_span = soup.find("span", class_="entry-date")
    date_text = date_span.get_text(strip=True) if date_span else ""

    # get the main content
    div = soup.find("div", class_="entry-content")
    content = div.get_text(separator="\n", strip=True) if div else ""

    # combine
    return f"{date_text}\n\n{content}"

if __name__ == "__main__":
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Unified API Intelligence Agent')
    parser.add_argument('--selected_sources', type=str, help='Comma-separated list of sources to run')
    args = parser.parse_args()
    
    # Parse selected sources
    selected_sources = []
    if args.selected_sources:
        selected_sources = [source.strip() for source in args.selected_sources.split(',')]
        print(f"Running selected sources: {selected_sources}")
    else:
        # Default to all sources if none specified
        selected_sources = ['NVD', 'GitHub Advisory', 'HackerOne', 'VulDB', 'Zero Day Initiative', 'API Security']
        print("No sources specified, running all sources")
    
    start_time = time.time()
    
    # NVD Agent
    if 'NVD' in selected_sources:
        print("Starting NVD Agent...")
        nvd_agent = Agent(  
        name="nvd_intelligence_agent",  
        system_prompt="""You are specialized Intelligence Gathering Agent that can
        1. Search NVD to pull some of the latest API-related vulnerabilities
        2. Normalize data into standard format 

        Based on each discovery data individually, ask yourself "Can this vulnerability be harvested in any other APIs generically as well?" for each.
        ONLY if you STRONGLY feel it does, in exactly one sentence, explain why in the 'api_relevant' field. If not, leave it blank.

        Normalize and return each discovery in the following example JSON format:

        {
        "source": "NVD", 
        "id": "CVE-2024-XXXX",
        "title": "SQL Injection in REST API endpoint",
        "severity": "HIGH|CRITICAL|MEDIUM|LOW",
        "cvss_score": 8.5,
        "description": "Detailed vulnerability description",
        "affected_components": ["REST", "GraphQL", "JSON"],
        "exploit_available": true,
        "poc_url": "https://github.com/...",
        "published_date": "YYYY-MM-DD",
        "api_relevant": "Any API exposing a mechanism to execute system-level instructions based on user input is at risk if it lacks proper sanitization.",
        "tags": ["injection", "authentication", "jwt"]
        },

        Write all the normalized JSONs into a chroma database. Write everything within the same tool call. Do NOT provide a summary at the end.
        """,
        tools = [call_nvd_search, write_to_chroma_nvd],
        )
        nvd_response = nvd_agent("Fetch the latest CVE vulnerabilities")
        print(f"NVD Agent completed - Input tokens: {nvd_response.metrics.accumulated_usage.get('inputTokens', 0)}, Output tokens: {nvd_response.metrics.accumulated_usage.get('outputTokens', 0)}")
    else:
        print("Skipping NVD Agent (not selected)")
        nvd_response = type('obj', (object,), {'metrics': type('obj', (object,), {'accumulated_usage': {'inputTokens': 0, 'outputTokens': 0}})()})()

    # GitHub Advisory Agent
    if 'GitHub Advisory' in selected_sources:
        print("Starting GitHub Advisory Agent...")
        git_agent = Agent(  
        name="gitadvisory_intelligence_agent",  
        system_prompt="""You are specialized Intelligence Gathering Agent that can
        1. Search Git Advisory to pull some of the latest API-related vulnerabilities
        2. Normalize data into standard format 

        Based on each discovery data individually, ask yourself "Can this vulnerability be harvested in any APIs generically?" for each.
        ONLY if you STRONGLY feel it does, in exactly one sentence, explain why in the 'api_relevant' field. If not, leave it blank.

        Normalize and return each discovery in the following example JSON format:

        {
        "source": "Git Advisory", 
        "id": "GHSA-XXXX-XXXX-XXXX",
        "title": "SQL Injection in REST API endpoint",
        "severity": "HIGH|CRITICAL|MEDIUM|LOW",
        "cvss_score": 8.5,
        "description": "Detailed vulnerability description",
        "affected_components": ["REST", "GraphQL", "JSON"],
        "exploit_available": true,
        "poc_url": "https://github.com/...",
        "published_date": "YYYY-MM-DD",
        "api_relevant": "Any API exposing a mechanism to execute system-level instructions based on user input is at risk if it lacks proper sanitization.",
        "tags": ["injection", "authentication", "jwt"]
        },

        Write all the normalized JSONs into a chroma database. Write everything within the same tool call.
        Do not output a summary at the end.
        """,
        tools = [call_git_search, write_to_chroma_git],
        )
        git_response = git_agent("Fetch the latest CVE vulnerabilities")
        print(f"GitHub Advisory Agent completed - Input tokens: {git_response.metrics.accumulated_usage.get('inputTokens', 0)}, Output tokens: {git_response.metrics.accumulated_usage.get('outputTokens', 0)}")
    else:
        print("Skipping GitHub Advisory Agent (not selected)")
        git_response = type('obj', (object,), {'metrics': type('obj', (object,), {'accumulated_usage': {'inputTokens': 0, 'outputTokens': 0}})()})()

    # HackerOne Agent
    if 'HackerOne' in selected_sources:
        print("Starting HackerOne Agent...")
        hackerone_agent = Agent(  
        name="hackerone_intelligence_agent",  
        system_prompt="""You are specialized Intelligence Gathering Agent that can
        1. Fetch the links from Hackerone latest API-related vulnerabilities. The tool call will return a list of links which you 
        should get data from individually by manually checking the link.
        2. Normalize data into standard format 
    

    Based on each discovery data individually, ask yourself "Can this vulnerability be harvested in any other APIs generically as well?" for each.
    ONLY if you STRONGLY feel it does, in exactly one sentence, explain why in the 'api_relevant' field. If not, leave it blank.

    Ignore it if it's not API-related or has the status 'Informative'. Normalize and return each discovery in the following example JSON format:

    {
    "source": "HackerOne", 
    "id": "3228011",
    "title": "SQL Injection in REST API endpoint",
    "severity": "HIGH|CRITICAL|MEDIUM|LOW",
    "cvss_score": 8.5 (assign one if you can't find it),
    "description": "Detailed vulnerability description",
    "affected_components": ["REST", "GraphQL", "JSON"],
    "exploit_available": true,
    "poc_url": "https://github.com/...",
    "published_date": "YYYY-MM-DD",
    "api_relevant": "Any API exposing a mechanism to execute system-level instructions based on user input is at risk if it lacks proper sanitization.",
    "tags": ["injection", "authentication", "jwt"]
    },

    Write all the normalized JSONs into a chroma database. Write everything within the same tool call. Do NOT provide a summary at the end.
    """,
        tools = [fetch_hackerone_links, write_to_chroma_hackerone],
        )
        hackerone_response = hackerone_agent("Fetch the latest Hackerone vulnerabilities")
        print(f"HackerOne Agent completed - Input tokens: {hackerone_response.metrics.accumulated_usage.get('inputTokens', 0)}, Output tokens: {hackerone_response.metrics.accumulated_usage.get('outputTokens', 0)}")
    else:
        print("Skipping HackerOne Agent (not selected)")
        hackerone_response = type('obj', (object,), {'metrics': type('obj', (object,), {'accumulated_usage': {'inputTokens': 0, 'outputTokens': 0}})()})()

    # VulDB Agent
    if 'VulDB' in selected_sources:
        print("Starting VulDB Agent...")
        vuldb_agent = Agent(  
        name="vuldb_intelligence_agent",  
        system_prompt="""You are specialized Intelligence Gathering Agent that can
        1. Search VulDB to pull some of the latest API-related vulnerabilities
        2. Normalize data into standard format 

        Based on each discovery data individually, ask yourself "Can this vulnerability be harvested in any other APIs generically as well?" for each.
        ONLY if you STRONGLY feel it does, in exactly one sentence, explain why in the 'api_relevant' field. If not, leave it blank.

        Normalize and return each discovery in the following example JSON format:

        {
        "source": "VulDB", 
        "id": "322434",
        "title": "SQL Injection in REST API endpoint",
        "severity": "HIGH|CRITICAL|MEDIUM|LOW",
        "cvss_score": 8.5,
        "description": "Detailed vulnerability description",
        "affected_components": ["REST", "GraphQL", "JSON"],
        "exploit_available": true,
        "poc_url": "https://github.com/...",
        "published_date": "YYYY-MM-DD",
        "api_relevant": "Any API exposing a mechanism to execute system-level instructions based on user input is at risk if it lacks proper sanitization.",
        "tags": ["injection", "authentication", "jwt"]
        },

        Write all the normalized JSONs into a chroma database. Write everything within the same tool call. Do NOT provide a summary at the end.
        """,
        tools = [call_vuldb_search, write_to_chroma_vuldb],
        )
        vuldb_response = vuldb_agent("Fetch the latest CVE vulnerabilities")
        print(f"VulDB Agent completed - Input tokens: {vuldb_response.metrics.accumulated_usage.get('inputTokens', 0)}, Output tokens: {vuldb_response.metrics.accumulated_usage.get('outputTokens', 0)}")
    else:
        print("Skipping VulDB Agent (not selected)")
        vuldb_response = type('obj', (object,), {'metrics': type('obj', (object,), {'accumulated_usage': {'inputTokens': 0, 'outputTokens': 0}})()})()

    # Zero Day Initiative Agent
    if 'Zero Day Initiative' in selected_sources:
        print("Starting Zero Day Initiative Agent...")
        zeroday_agent = Agent(  
        name="zeroday_intelligence_agent",  
        system_prompt="""You are specialized Intelligence Gathering Agent that can
        1. Search Zeroday Initiative to pull some of the latest API-related vulnerabilities
        2. Normalize data into standard format 

        Your search tool call will return a list of advisories which you should then get data from individually by manually scraping the links.
        Based on each discovery data individually, ask yourself "Can this vulnerability be harvested in any other APIs generically as well?" for each.
        ONLY if you STRONGLY feel it does, in exactly one sentence, explain why in the 'api_relevant' field. If not, leave it blank.

        Normalize and return each discovery in the following example JSON format:

        {
        "source": "Zeroday Initiative", 
        "id": "ZDI-CAN-25774",
        "title": "SQL Injection in REST API endpoint",
        "severity": "HIGH|CRITICAL|MEDIUM|LOW",
        "cvss_score": 8.5,
        "description": "Detailed vulnerability description",
        "affected_components": ["REST", "GraphQL", "JSON"],
        "exploit_available": true,
        "poc_url": "https://github.com/...",
        "published_date": "YYYY-MM-DD",
        "api_relevant": "Any API exposing a mechanism to execute system-level instructions based on user input is at risk if it lacks proper sanitization.",
        "tags": ["injection", "authentication", "jwt"]
        },

        Write all the normalized JSONs into a chroma database. Write everything within the same tool call. Do NOT provide a summary at the end.
        """,
        tools = [call_zeroday_search, write_to_chroma_zeroday],
        )
        zeroday_response = zeroday_agent("Fetch the latest Zeroday Initiative vulnerabilities")
        print(f"Zero Day Initiative Agent completed - Input tokens: {zeroday_response.metrics.accumulated_usage.get('inputTokens', 0)}, Output tokens: {zeroday_response.metrics.accumulated_usage.get('outputTokens', 0)}")
    else:
        print("Skipping Zero Day Initiative Agent (not selected)")
        zeroday_response = type('obj', (object,), {'metrics': type('obj', (object,), {'accumulated_usage': {'inputTokens': 0, 'outputTokens': 0}})()})()

    # API Security Agent
    if 'API Security' in selected_sources:
        print("Starting API Security Agent...")
        apisecurity_url = get_latest_post_link()
        apisecurity_agent = Agent(  
        name="apisecurity_intelligence_agent",  
        system_prompt=f"""You are specialized Intelligence Gathering Agent that can
        1. Search the latest biweekly post thread on Apisecurity.io via {apisecurity_url} to pull some of the latest API-related vulnerabilities
        2. Normalize data into standard format 

        Based on each discovery data individually, ask yourself "Can this vulnerability be harvested in any other APIs generically as well?" for each.
        ONLY if you STRONGLY feel it does, in exactly one sentence, explain why in the 'api_relevant' field. If not, leave it blank.

        Normalize and return each discovery in the following example JSON format:

        {{
        "source": "Apisecurity", 
        "id": "CVE-2024-XXXXX" or if not present, "unknown_{int(time.time())}",
        "title": "SQL Injection in REST API endpoint",
        "severity": "HIGH|CRITICAL|MEDIUM|LOW",
        "cvss_score": 8.5,
        "description": "Detailed vulnerability description",
        "affected_components": ["REST", "GraphQL", "JSON"],
        "exploit_available": true,
        "poc_url": "https://github.com/...",
        "published_date": "YYYY-MM-DD",
        "api_relevant": "Any API exposing a mechanism to execute system-level instructions based on user input is at risk if it lacks proper sanitization.",
        "tags": ["injection", "authentication", "jwt"]
        }},

        Write all the normalized JSONs into a chroma database. Write everything within the same tool call. Do NOT provide a summary at the end.
        """,
        tools = [get_apisecurity_content, write_to_chroma_apisecurity],
        )
        apisecurity_response = apisecurity_agent("Fetch this week's apisecurity.io vulnerabilities")
        print(f"API Security Agent completed - Input tokens: {apisecurity_response.metrics.accumulated_usage.get('inputTokens', 0)}, Output tokens: {apisecurity_response.metrics.accumulated_usage.get('outputTokens', 0)}")
    else:
        print("Skipping API Security Agent (not selected)")
        apisecurity_response = type('obj', (object,), {'metrics': type('obj', (object,), {'accumulated_usage': {'inputTokens': 0, 'outputTokens': 0}})()})()

    end_time = time.time()
    total_time = round(end_time - start_time, 2)
    
    # Calculate total tokens across all agents
    total_input_tokens = (nvd_response.metrics.accumulated_usage.get('inputTokens', 0) + 
                         git_response.metrics.accumulated_usage.get('inputTokens', 0) + 
                         hackerone_response.metrics.accumulated_usage.get('inputTokens', 0) + 
                         vuldb_response.metrics.accumulated_usage.get('inputTokens', 0) + 
                         zeroday_response.metrics.accumulated_usage.get('inputTokens', 0) + 
                         apisecurity_response.metrics.accumulated_usage.get('inputTokens', 0))
    
    total_output_tokens = (nvd_response.metrics.accumulated_usage.get('outputTokens', 0) + 
                          git_response.metrics.accumulated_usage.get('outputTokens', 0) + 
                          hackerone_response.metrics.accumulated_usage.get('outputTokens', 0) + 
                          vuldb_response.metrics.accumulated_usage.get('outputTokens', 0) + 
                          zeroday_response.metrics.accumulated_usage.get('outputTokens', 0) + 
                          apisecurity_response.metrics.accumulated_usage.get('outputTokens', 0))
    
    total_tokens = total_input_tokens + total_output_tokens
    
    # Calculate total vulnerabilities from global counter
    total_vulnerabilities = sum(agent_vulnerability_counts.values())
    
    print(f"\n=== UNIFIED API INTELLIGENCE GATHERING COMPLETED ===")
    print(f"Individual Agent Results:")
    for agent_name, count in agent_vulnerability_counts.items():
        print(f"  - {agent_name}: {count} vulnerabilities")
    print(f"Total vulnerabilities added: {total_vulnerabilities}")
    print(f"Total Input tokens: {total_input_tokens}")
    print(f"Total Output tokens: {total_output_tokens}")
    print(f"Total tokens: {total_tokens}")
    print(f"Total time taken: {total_time}s")
    print(f"All 6 agents completed successfully!")
