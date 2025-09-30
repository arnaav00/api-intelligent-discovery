import time
import json
import chromadb
import sys
import os
from strands import Agent, tool

# Fix Unicode encoding issues on Windows
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())
    os.environ['PYTHONIOENCODING'] = 'utf-8'

@tool
def write_to_chroma(response):
    """
    Process vulnerability data and update ChromaDB with categories and tests
    """
    try:
        chroma_client = chromadb.PersistentClient(path="./chroma_db")
        collection = chroma_client.get_or_create_collection(
            name="vulnerability_data",
            metadata={"description": "API-related vulnerability data from CVE and GitHub advisories"}
        )

        # Parse the response to extract vulnerability data
        vulnerabilities = []
        
        if isinstance(response, str):
            # Parse the structured text format: id:, category:, test:
            lines = response.split('\n')
            current_vuln = {}
            current_test = ""
            in_test_section = False
            test_started = False
            
            for line in lines:
                # Don't strip the line completely - preserve indentation for Python code
                stripped_line = line.strip()
                
                if stripped_line.startswith('id:'):
                    # Save previous vulnerability if exists
                    if current_vuln.get('id'):
                        current_vuln['test'] = current_test.rstrip()
                        vulnerabilities.append(current_vuln)
                    
                    # Start new vulnerability
                    current_vuln = {'id': stripped_line.replace('id:', '').strip()}
                    current_test = ""
                    in_test_section = False
                    test_started = False
                elif stripped_line.startswith('category:'):
                    current_vuln['category'] = stripped_line.replace('category:', '').strip()
                elif stripped_line.startswith('test:'):
                    # Start of test section - get the function definition
                    test_line = line.replace('test:', '').strip()
                    current_test = test_line + '\n'
                    in_test_section = True
                    test_started = True
                elif in_test_section and test_started:
                    # In test section - preserve original line structure
                    if line.strip():  # Only add non-empty lines
                        current_test += line + '\n'
                    elif current_test.strip():  # Only add empty lines if we have content
                        current_test += line + '\n'
            
            # Don't forget the last vulnerability
            if current_vuln.get('id'):
                current_vuln['test'] = current_test.rstrip()
                vulnerabilities.append(current_vuln)
            
            print(f"Parsed {len(vulnerabilities)} vulnerabilities from response")
                
        elif isinstance(response, list):
            vulnerabilities = response
        else:
            vulnerabilities = [response]
        
        # Process each vulnerability
        for vuln in vulnerabilities:
            vuln_id = vuln.get('id', f"temp_{int(time.time())}")
            category = vuln.get('category', 'Unknown')
            test_code = vuln.get('test', '')
            
            print(f"Processing vulnerability {vuln_id} with category: {category}")
            print(f"Test code preview (first 200 chars): {test_code[:200]}...")
            # Update the existing record with category and tests
            try:
                collection.update(
                    ids=[vuln_id],
                    metadatas=[{
                        'category': category,
                        'tests': test_code
                    }]
                )
            except Exception as e:
                print(f"Error updating record {vuln_id}: {e}")
                continue
        
        return f"Successfully updated vulnerability records with categories and tests"
        
    except Exception as e:
        print(f"Error writing to ChromaDB: {e}")
        return f"Error writing to ChromaDB: {e}"

# @tool
# def write_to_chroma(response):
#     print("calling invoke_chroma()")
#     return invoke_chroma(response)


@tool
def import_from_chromadb(source_filter=None):
    client = chromadb.PersistentClient(path="./chroma_db")
    collection = client.get_collection("vulnerability_data")
    # Get all records
    all_records = collection.get()
    
    # Filter out records where api_relevant is null, None, or empty
    if all_records['ids'] and len(all_records['ids']) > 0:
        filtered_ids = []
        filtered_metadatas = []
        filtered_documents = []
        
        for i, metadata in enumerate(all_records['metadatas']):
            api_relevant = metadata.get('api_relevant')
            source = metadata.get('source', '').upper()
            
            # If source_filter is provided, only include records from that source
            if source_filter:
                source_match = source == source_filter.upper()
            else:
                source_match = True
                
            # Only include records that are API relevant AND match source filter
            if api_relevant and source_match:
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
    # Get source filter from command line argument if provided
    source_filter = None
    if len(sys.argv) > 1:
        source_filter = sys.argv[1]
    
    start_time = time.time()
    
    try:
        test_agent = Agent(  
        name="api_test_agent",  
        system_prompt=f"""
        You are an AI agent specialized in analyzing API vulnerabilities and generating comprehensive test cases.
        
        Your task is to import vulnerability data from ChromaDB using the tool {f' (filtering for source: {source_filter})' if source_filter else ''}
    For each vulnerability record, generate one python test function (with an appropriate test category name in Plain english) that I can run against generic
    APIs to evaluate whether they're vulnerable to this specific problem. I want to do this at runtime by invoking the API. Manipulate inputs as necessary.
    Think about test generation this way if a human were to manually write it, they would think:
    "How can the vulnerability be exploited if I were to construct a request to arbitrary endpoints? When I get a response, is there anything
    in that response that indicates the vulnerability?"
    These are all individual vulnerability instances so write them separately. Do not output your reasoning. Do not skip any IDs from the source. Do not provide any summary at the end.
    
    Each output should be in the format:
    id: <vulnerability_id>
    category: <test_category_name>
    test: <test_function_code>

    Write all the tests in the end with one write tool call to ChromaDB. Make sure to update the ChromaDB with the category as well as the test for each..
        """,
        tools=[import_from_chromadb, write_to_chroma]
        )
        
        # Generate categories and tests
        response = test_agent("Analyze the imported vulnerability data and generate categories and test cases for each vulnerability. Update the ChromaDB with the results.")
        
        end_time = time.time()
        print(f"Test generation completed in {end_time - start_time:.2f} seconds")
        print(f"\nInput tokens: {response.metrics.accumulated_usage.get('inputTokens', 0)}")
        print(f"Output tokens: {response.metrics.accumulated_usage.get('outputTokens', 0)}")
        print(f"Total tokens: {response.metrics.accumulated_usage.get('totalTokens', 0)}")
        print(f"Total time taken: {end_time - start_time}s\n")
        
    except UnicodeEncodeError as e:
        print(f"Unicode encoding error occurred: {e}")
        print("This is likely due to emoji characters in the output. The agent may have completed successfully despite this error.")
        end_time = time.time()
        print(f"Test generation completed in {end_time - start_time:.2f} seconds")
    except Exception as e:
        print(f"Error during test generation: {e}")
        end_time = time.time()
        print(f"Test generation failed after {end_time - start_time:.2f} seconds")

