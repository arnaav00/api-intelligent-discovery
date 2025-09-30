#!/usr/bin/env python3
"""
Simple script to check what's stored in the ChromaDB
"""

import chromadb
import json

def check_chroma_db():
    """Check what vulnerabilities are stored in ChromaDB"""
    try:
        # Connect to ChromaDB
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_collection("vulnerability_data")
        # Get all records
        results = collection.get()
        
        print(f"Total records in ChromaDB: {len(results['ids']) if results['ids'] else 0}")
        print("="*80)
        
        if results['ids'] and len(results['ids']) > 0:
            for i, vuln_id in enumerate(results['ids']):
                metadata = results['metadatas'][i] if results['metadatas'] and i < len(results['metadatas']) else {}
                document = results['documents'][i] if results['documents'] and i < len(results['documents']) else ""
                
                print(f"\nRecord {i+1}:")
                print(f"  ID: {vuln_id}")
                print(f"  Title: {metadata.get('title', 'N/A')}")
                print(f"  Severity: {metadata.get('severity', 'N/A')}")
                print(f"  Source: {metadata.get('source', 'N/A')}")
                print(f"  CVSS Score: {metadata.get('cvss_score', 'N/A')}")
                print(f"  Published: {metadata.get('published_date', 'N/A')}")
                print(f"  API Relevant: {metadata.get('api_relevant', 'N/A')}")
                print(f"  Exploit Available: {metadata.get('exploit_available', 'N/A')}")
                print(f"  Affected Components: {metadata.get('affected_components', 'N/A')}")
                print(f"  Tags: {metadata.get('tags', 'N/A')}")
                if metadata.get('poc_url'):
                    print(f"  PoC URL: {metadata.get('poc_url')}")
                
                # Show category and tests if available
                if metadata.get('category'):
                    print(f"  Category: {metadata.get('category')}")
                
                if metadata.get('tests'):
                    tests = metadata.get('tests')
                    print(f"  Tests:")
                    # Show first few lines of tests, truncate if too long
                    test_lines = tests.split('\n')[:10]  # Show first 10 lines
                    for line in test_lines:
                        if line.strip():
                            print(f"    {line}")
                    if len(tests.split('\n')) > 10:
                        print(f"    ... ({len(tests.split('\n')) - 10} more lines)")
                
                print(f"  Description Preview: {document[:150]}..." if document else "  No description")
                print("-" * 80)
        else:
            print("No records found in ChromaDB")
            
    except Exception as e:
        print(f"Error checking ChromaDB: {e}")
 
if __name__ == "__main__":
    check_chroma_db()
