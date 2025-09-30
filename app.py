#!/usr/bin/env python3
"""
Flask server for API Vulnerability Intelligence System UI
"""

from flask import Flask, render_template, request, jsonify
import subprocess
import json
import os
import sys
import time
from pathlib import Path

app = Flask(__name__)

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def run_agent_script(agent_name, source_filter=None, selected_sources=None):
    """Run the specified agent script and return results"""
    try:
        # Map agent names to script files
        agent_scripts = {
            'unified_api_agent': 'unified_api_intelligence_agent.py',
            'mcp_nvd_agent': 'mcp_nvd_agent.py',
            'mcp_gitadvisory_agent': 'mcp_git_advisory_agent.py',
            'api_test_agent': 'api_test_agent.py',
            'mcp_test_agent': 'mcp_test_agent.py'
        }
        
        script_path = agent_scripts.get(agent_name)
        if not script_path or not os.path.exists(script_path):
            return {"error": f"Agent script {agent_name} not found"}
        
        # Run the agent script
        try:
            cmd = [sys.executable, script_path]
            if source_filter and agent_name == 'api_test_agent':
                cmd.append(source_filter)
            if selected_sources and agent_name == 'unified_api_agent':
                cmd.extend(['--selected_sources', ','.join(selected_sources)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=current_dir,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                return {
                    "error": f"Agent execution failed: {result.stderr}",
                    "stdout": result.stdout,
                    "error_type": "execution_error"
                }
                
        except subprocess.TimeoutExpired as e:
            return {
                "error": f"Agent execution timed out after 5 minutes: {str(e)}",
                "error_type": "timeout"
            }
        except Exception as e:
            error_msg = str(e)
            error_type = "runtime_error"
            
            # Handle specific Strands exceptions
            if "EventLoopException" in error_msg:
                error_type = "strands_timeout"
                error_msg = f"Strands agent connection timeout: {error_msg}"
            elif "AWSHTTPSConnectionPool" in error_msg and "Read timed out" in error_msg:
                error_type = "aws_timeout"
                error_msg = f"AWS Bedrock connection timeout: {error_msg}"
            elif "timeout" in error_msg.lower():
                error_type = "timeout"
            
            return {
                "error": error_msg,
                "error_type": error_type
            }
        
        # Parse output for token information
        output_lines = result.stdout.split('\n')
        total_tokens = 0
        vulnerabilities = 0
        individual_counts = {}
        
        print(f"DEBUG: Parsing output for {agent_name}")
        for line in output_lines:
            if 'Total tokens:' in line:
                try:
                    total_tokens = int(line.split('Total tokens:')[1].strip())
                except:
                    pass
            elif 'Successfully added' in line and 'vulnerabilities' in line:
                try:
                    # Look for "Successfully added X vulnerabilities to ChromaDB"
                    print(f"DEBUG: Look for Successfully added X vulnerabilities to ChromaDB")
                    words = line.split()
                    for i, word in enumerate(words):
                        if word == 'added' and i + 1 < len(words):
                            vulnerabilities = int(words[i+1])
                            print(f"DEBUG: Found vulnerabilities count: {vulnerabilities} from line: {line}")
                            break
                except:
                    print(f"DEBUG: Error parsing Successfully added X vulnerabilities to ChromaDB")
                    pass
            elif 'vulnerabilities to ChromaDB' in line:
                try:
                    # Look for "X vulnerabilities to ChromaDB"
                    words = line.split()
                    for i, word in enumerate(words):
                        if word == 'vulnerabilities' and i > 0:
                            vulnerabilities = int(words[i-1])
                            print(f"DEBUG: Found vulnerabilities count: {vulnerabilities} from line: {line}")
                            break
                except:
                    pass
            # Parse individual agent counts for unified agent
            elif 'completed -' in line and 'vulnerabilities added to ChromaDB' in line:
                try:
                    # Extract agent name and count from lines like "NVD Agent completed - 5 vulnerabilities added to ChromaDB"
                    parts = line.split(' completed - ')
                    if len(parts) >= 2:
                        agent_name = parts[0].strip()
                        count_part = parts[1].split(' vulnerabilities')[0].strip()
                        count = int(count_part)
                        individual_counts[agent_name] = count
                        vulnerabilities += count
                        print(f"DEBUG: Found {agent_name}: {count} vulnerabilities")
                except:
                    pass
            elif 'Total vulnerabilities added:' in line:
                try:
                    # Override total with the final count from unified agent
                    vulnerabilities = int(line.split('Total vulnerabilities added:')[1].strip())
                    print(f"DEBUG: Found total vulnerabilities: {vulnerabilities}")
                except:
                    pass
        
        print(f"DEBUG: Final parsed values - Tokens: {total_tokens}, Vulnerabilities: {vulnerabilities}")
        print(f"DEBUG: Individual counts: {individual_counts}")
        
        return {
            "success": True,
            "totalTokens": total_tokens,
            "vulnerabilities": vulnerabilities,
            "individualCounts": individual_counts,
            "output": result.stdout,
            "logs": result.stdout.split('\n') if result.stdout else []
        }
        
    except subprocess.TimeoutExpired as e:
        return {"error": f"Agent execution timed out: {repr(e)}"}
    except Exception as e:
        return {"error": f"Error running agent: {repr(e)}"}

def get_chroma_data(collection_name="vulnerability_data"):
    """Get data from ChromaDB directly"""
    try:
        import chromadb
        
        # Connect to ChromaDB
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_collection(collection_name)
        
        # Get all records
        results = collection.get()
        
        vulnerabilities = []
        
        if results['ids'] and len(results['ids']) > 0:
            for i, vuln_id in enumerate(results['ids']):
                metadata = results['metadatas'][i] if results['metadatas'] and i < len(results['metadatas']) else {}
                document = results['documents'][i] if results['documents'] and i < len(results['documents']) else ""
                
                vulnerability = {
                    "id": vuln_id,
                    "metadata": metadata,
                    "document": document
                }
                vulnerabilities.append(vulnerability)
        
        return {"success": True, "vulnerabilities": vulnerabilities}
        
    except Exception as e:
        return {"error": f"Error getting ChromaDB data: {str(e)}"}

@app.route('/')
def index():
    """Serve the main UI"""
    return render_template('api_vulnerability_ui.html')

@app.route('/run_agent', methods=['POST'])
def run_agent():
    """Run a specific agent"""
    data = request.get_json()
    agent_name = data.get('agent')
    source_filter = data.get('source_filter')
    selected_sources = data.get('selectedSources')
    
    if not agent_name:
        return jsonify({"error": "No agent specified"}), 400
    
    result = run_agent_script(agent_name, source_filter, selected_sources)
    return jsonify(result)

@app.route('/get_chroma_data')
def get_chroma_data_endpoint():
    """Get ChromaDB data"""
    collection_name = request.args.get('collection', 'vulnerability_data')
    result = get_chroma_data(collection_name)
    return jsonify(result)

@app.route('/get_unique_sources')
def get_unique_sources():
    """Get unique sources from ChromaDB"""
    try:
        import chromadb
        
        collection_name = request.args.get('collection', 'vulnerability_data')
        
        # Connect to ChromaDB
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_collection(collection_name)
        
        # Get all records
        results = collection.get()
        
        sources = set()
        if results['metadatas']:
            for metadata in results['metadatas']:
                source = metadata.get('source', '').strip()
                if source:
                    sources.add(source)
        
        # Convert to sorted list
        unique_sources = sorted(list(sources))
        
        return jsonify({"success": True, "sources": unique_sources})
        
    except Exception as e:
        return jsonify({"error": f"Error getting unique sources: {str(e)}"})

@app.route('/clear_chroma_db', methods=['POST'])
def clear_chroma_db():
    """Force delete the ChromaDB root directory, with retries, and return detailed errors."""
    try:
        import shutil
        import time
        import gc
        
        chroma_db_path = current_dir / "chroma_db"

        # Best effort: free resources in current process
        try:
            import chromadb
            client = chromadb.PersistentClient(path=str(chroma_db_path))
            # Close references
            del client
        except Exception:
            pass
        gc.collect()

        # Retry direct delete of root dir
        last_err = None
        for attempt in range(2):
            try:
                if chroma_db_path.exists():
                    print(f"DEBUG: Deleting ChromaDB directory: {chroma_db_path}")
                    shutil.rmtree(chroma_db_path)
                return jsonify({
                    "success": True,
                    "message": "ChromaDB directory deleted successfully"
                })
            except Exception as e:
                last_err = e
                time.sleep(0.6)
        
        # If still failing, return full error
        return jsonify({
            "error": f"Failed to delete ChromaDB directory: {repr(last_err)}"
        }), 500
        
    except Exception as e:
        return jsonify({"error": f"Error clearing ChromaDB: {repr(e)}"}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": time.time()})

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = current_dir / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    # Move the HTML file to templates directory
    html_file = current_dir / 'api_vulnerability_ui.html'
    template_file = templates_dir / 'api_vulnerability_ui.html'
    
    if html_file.exists() and not template_file.exists():
        html_file.rename(template_file)
    
    print("Starting API Vulnerability Intelligence System...")
    print("Open your browser to: http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)
