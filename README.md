# Intelligent API Vulnerability Discovery System

## Overview

This is an AI-powered system that automatically discovers, analyzes, and generates security tests for API vulnerabilities. Think of it as a smart security researcher that can monitor multiple vulnerability databases and create practical tests.

## What This System Does

### **Intelligence Gathering**
The system acts like a team of specialized security researchers, each monitoring different sources:

- **NVD (National Vulnerability Database)** - Official government vulnerability database
- **GitHub Advisory** - Security advisories from GitHub's security team
- **HackerOne** - Real-world vulnerability reports from ethical hackers
- **VulDB** - Comprehensive vulnerability database
- **Zero Day Initiative** - Advanced threat intelligence
- **Apisecurity.io** - Specialized API security news and advisories

### **Test Generation**
- Automatically identifies which vulnerabilities are relevant to APIs or MCPs
- Categorizes vulnerabilities by type and severity
- Generates practical test cases that can be run against real applications

## How It Works

### 1. **Data Collection Phase**
```
User clicks "Start Intelligence Gathering" 
    ↓
AI agents connect to multiple vulnerability databases
    ↓
System fetches latest API/MCP-related vulnerabilities
    ↓
Data is stored in a local database (ChromaDB)
```

### 2. **Analysis Phase**
```
User selects a data source (e.g., NVD, GitHub)
    ↓
System generates test categories and executable code
    ↓
Results are stored in ChromaDB and displayed in the web interface
```

### 3. **Deployment Phase**
```
Generated tests can be deployed to production. We don't trust AI to validate the code so this can be manually implemented later on.
```


## Technical Architecture

### **Core Components**

1. **Flask Web Server** (`app.py`)
   - Provides the web interface
   - Manages agent execution
   - Handles data storage and retrieval

2. **AI Agents** (Multiple Python files)
   - `unified_api_intelligence_agent.py` - Main API vulnerability collector (all 6 sources)
   - `mcp_nvd_agent.py` - MCP-specific NVD collector
   - `mcp_git_advisory_agent.py` - MCP GitHub advisory collector
   - `api_test_agent.py` - API test generator
   - `mcp_test_agent.py` - MCP test generator

   NOTE: The application is not as robust for MCPs as it is for APIs. The MCP implementation was only for a PoC and can only fetch from NVD and Git Advisory for now.

3. **Data Storage** (ChromaDB)
   - Vector database for storing vulnerability information
   - Enables semantic search and similarity matching
   - Persistent storage across sessions

### **Technology Stack**
- **Strands Framework** - Powers the AI agents
- **ChromaDB** - Vector database for semantic storage
- **Flask** - Web framework for the user interface
- **Selenium** - Web scraping for dynamic content
- **BeautifulSoup** - HTML parsing for web content

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Internet connection (for fetching vulnerability data)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd vuln_multiagent
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the system**
   ```bash
   python app.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:5000`

### First Run

1. **Select your target** - Choose between API or MCP mode using the toggle switch
2. **Choose sources** - Select which vulnerability databases to monitor
3. **Start gathering** - Click "Start Intelligence Gathering" to begin data collection
4. **Generate tests** - After data collection, select a source and click "Generate Tests"
5. **Review results** - Examine the generated test categories and code
   
## Usage Example
```
1. Set mode to "API"
2. Select sources: NVD, GitHub Advisory, HackerOne
3. Start intelligence gathering
4. Wait for completion (usually 2-5 minutes)
5. Select "NVD" as source for test generation
6. Click "Generate Tests"
7. Review generated test categories like:
   - "SQL Injection in REST API endpoints"
   - "Authentication bypass in GraphQL APIs"
   - "Cross-site scripting in API responses"
```

### Common Issues

**"Agent execution timed out"**
- The AI agents have a 5-minute timeout
- Try running with fewer sources selected

**"No vulnerabilities found"**
- Ensure you've completed the intelligence gathering phase
- Check that your selected sources have recent API/MCP vulnerabilities
- Verify the source selection matches your mode (API vs MCP)
