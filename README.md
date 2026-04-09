# AI Powered Automated Pentesting Tool

An intelligent, asynchronous, full-stack penetration testing framework that automates the entire security assessment lifecycle—from reconnaissance to exploitation. It leverages **Google Gemini AI** to generate dynamic exploit commands and synthesize executive security reports.

## Prerequisites

This tool acts as an orchestrator. You must have the underlying security tools installed on your host operating system. Kali Linux is recommended.

### System Requirements

* Python 3.8+
* Node.js v16+
* npm

### OS-Level Security Tools

Ensure the following tools are installed and accessible via your system `PATH`:

* `nmap`
* `whatweb`
* `sublist3r`
* `gobuster`
* `wapiti`
* `skipfish`
* `sqlmap`
* `msfconsole` (Metasploit Framework)

## Installation & Setup Step-by-Step

### Step 1: Clone the Repository

```bash
git clone repo_link
cd automated-pentesting-tool
```

### Step 2: Setup the Backend (FastAPI)

The backend manages the orchestration, WebSockets, and AI integration.

1. Navigate to the backend directory:

   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure Environment Variables:

   Create a `.env` file in the root of the `backend/` directory and add your Google Gemini API Key:

   ```bash
   GEMINI_API_KEY="your_google_gemini_api_key_here"
   ```

5. Wordlists:

   Ensure any required wordlists for Gobuster or Sublist3r are present in the `backend/wordlists/` directory as referenced in the code.

### Step 3: Setup the Frontend (React)

The frontend is a React application that provides the UI and real-time dashboard.

1. Open a new terminal window/tab.

2. Navigate to the frontend directory:

   ```bash
   cd frontend
   ```

3. Install Node dependencies:

   ```bash
   npm install
   ```

4. Configure Environment Variables:

   Create a `.env` file in the `frontend/` directory and paste:

   ```bash
   REACT_APP_API_URL=http://localhost:8000
   ```

## Running the Application Locally

You need to run both the Backend and Frontend servers simultaneously in separate terminals.

### 1. Start the Backend Server

In your first terminal:

```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The backend will now be running and accepting API calls and WebSocket connections at `http://localhost:8000`.

### 2. Start the Frontend Server

In your second terminal:

```bash
cd frontend
npm start
```

The React application will automatically open in your default browser at `http://localhost:3000`.

## How to Use the Tool

Open `http://localhost:3000` in your web browser.

1. Enter the Target URL.
2. Select the Scan Type.
3. Click Start.
4. Watch the real-time progress bar update as the backend WebSocket streams the orchestrator's status.
5. Once complete, view the interactive dashboard, explore the AI Threat Analysis accordion, and click Download Report to export the findings as a PDF.
