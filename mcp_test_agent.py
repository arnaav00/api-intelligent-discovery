import chromadb
from strands import Agent, tool
import time
import sys
import os

# Fix Unicode encoding issues on Windows
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())
    # Set environment variable for better Unicode support
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# @tool
def invoke_chroma(response):
    """
    Update existing vulnerability records in ChromaDB with category and tests information
    """
    try:
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_collection("mcp_data")
        
        # Parse the response to extract vulnerability data with categories and tests
        if isinstance(response, str):
            # Split by "## ID:" to get individual vulnerability sections
            sections = response.split("ID:")
            
            for section in sections:
                if not section.strip():
                    continue
                    
                lines = section.strip().split('\n')
                if not lines:
                    continue
                
                # Extract ID(s) from first line
                id_line = lines[0].strip()
                if not id_line:
                    continue
                
                # Handle multiple IDs (comma-separated)
                ids = [id.strip() for id in id_line.split(',')]
                
                # Extract category
                category = ""
                tests = ""
                current_section = ""
                
                for line in lines[1:]:
                    line = line.strip()
                    if line.startswith("Category:"):
                        category = line.replace("Category:", "").replace("**", "").strip()
                    elif line.startswith("Tests:"):
                        current_section = "tests"
                    elif line.startswith("```python"):
                        current_section = "tests"
                    elif line.startswith("```"):
                        current_section = ""
                    elif current_section == "tests":
                        tests += line + "\n"
                
                # Update each ID in the collection
                for vuln_id in ids:
                    try:
                        # Get existing record by ID
                        existing_records = collection.get(
                            where={"id": vuln_id}
                        )
                        
                        if existing_records['ids'] and len(existing_records['ids']) > 0:
                            # Update the existing record
                            existing_metadata = existing_records['metadatas'][0]
                            
                            # Add category and tests to metadata
                            updated_metadata = existing_metadata.copy()
                            updated_metadata['category'] = category
                            updated_metadata['tests'] = tests.strip()
                            
                            # Update the record
                            collection.update(
                                ids=[vuln_id],
                                metadatas=[updated_metadata]
                            )
                            
                            print(f"Updated record {vuln_id} with category: {category}")
                        else:
                            print(f"No existing record found for ID: {vuln_id}")
                            
                    except Exception as e:
                        print(f"Error updating record {vuln_id}: {e}")
                        continue
        
        return f"Successfully updated vulnerability records with categories and tests"
        
    except Exception as e:
        print(f"Error writing to ChromaDB: {e}")
        return f"Error writing to ChromaDB: {e}"

@tool
def write_to_chroma(response):
    print("calling invoke_chroma()")
    return invoke_chroma(response)


@tool
def import_from_chromadb():
    client = chromadb.PersistentClient(path="./chroma_db")
    collection = client.get_collection("mcp_data")
    # Get all records
    all_records = collection.get()
    
    # Filter out records where mcp_relevant is null, None, or empty
    if all_records['ids'] and len(all_records['ids']) > 0:
        filtered_ids = []
        filtered_metadatas = []
        filtered_documents = []
        
        for i, metadata in enumerate(all_records['metadatas']):
            mcp_relevant = metadata.get('mcp_relevant')
            if mcp_relevant:
                filtered_ids.append(all_records['ids'][i])
                filtered_metadatas.append(metadata)
                filtered_documents.append(all_records['documents'][i])
        
        return {
            'ids': filtered_ids,
            'metadatas': filtered_metadatas,
            'documents': filtered_documents
        }
    
    return all_records
    
if __name__=="__main__":    
    start_time = time.time()
    
    try:
        test_agent = Agent(  
        name="test_agent",  
        system_prompt="""You are a specialized MCP test-generating agent.
        Pull from chromadb and for each vulnerability record, perform the following:
        For each vulnerability record, generate a python test (with an appropriate test category name) that I can run against generic 
        MCPs to evaluate whether they're vulnerable to this specific problem. I want to do this at runtime by invoking the MCP. 
        Manipulate inputs as necessary. 
        Think about test generation this way. If a human were to manually write it, they would think:
        "How can the vulnerability be exploited if I were to construct a request to arbitrary endpoints? When I get a response, 
        is there anything in that response that indicates the vulnerability?"
        These are all individual vulnerability instances, I only need the functions and not the main. Do not skip any IDs.
        
        The format for your output for each one should look like:

        ID: <ID(s)>
        Category: <Test category name>
        Tests:
        <testss>
        ....
        and so on
        
        Write these to chroma db. Do not provide a summary at the end.
        """,
        tools = [import_from_chromadb, write_to_chroma],
        )

        response = test_agent("Fetch the latest CVE vulnerabilities")
        end_time = time.time()

        total_time = round(end_time - start_time, 2)
        print(f"\nInput tokens: {response.metrics.accumulated_usage.get('inputTokens', 0)}")
        print(f"Output tokens: {response.metrics.accumulated_usage.get('outputTokens', 0)}")
        print(f"Total tokens: {response.metrics.accumulated_usage.get('totalTokens', 0)}")
        print(f"Total time taken: {total_time}s\n")
        
    except UnicodeEncodeError as e:
        print(f"Unicode encoding error occurred: {e}")
        print("This is likely due to emoji characters in the output. The agent may have completed successfully despite this error.")
        end_time = time.time()
        total_time = round(end_time - start_time, 2)
        print(f"Test generation completed in {total_time} seconds")
    except Exception as e:
        print(f"Error during test generation: {e}")
        end_time = time.time()
        total_time = round(end_time - start_time, 2)
        print(f"Test generation failed after {total_time} seconds")



