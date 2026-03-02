# api/routes.py

from fastapi import APIRouter, HTTPException, WebSocket
import asyncio
import json
from pathlib import Path
import google.generativeai as genai

from core.state import active_scans
from core.config import SKIPFISH_ISSUE_DESCRIPTIONS_JSON_PATH
from models.schemas import ScanRequest, ScanResponse, ScanSummaryRequest, ScanType
from services.orchestrator import process_scan

router = APIRouter()

@router.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan_endpoint(request: ScanRequest):
    scan_id = request.scan_id
    active_scans[scan_id] = {"progress": 0, "status": "running", "step": "Initializing"}
    print(f"Received scan request with scan_id: {scan_id}")
    try:
        # Map string scan_type to ScanType enum
        scan_type_map = {
            "light_scan": ScanType.LIGHT,
            "deep_scan": ScanType.DEEP
        }
        scan_type = scan_type_map.get(request.scan_type)
        if not scan_type:
            raise ValueError(f"Invalid scan_type: {request.scan_type}")
            
        results = await process_scan(request.target, scan_type, scan_id)
        active_scans[scan_id]["status"] = "completed"
        return ScanResponse(**results)
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        print(f"Scan API Error for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.websocket("/ws/scan_progress")
async def scan_progress_websocket(websocket: WebSocket):
    await websocket.accept()
    print("WebSocket connection accepted")
    scan_id = None
    try:
        data = await websocket.receive_json()
        scan_id = data.get("scan_id")
        if not scan_id:
            await websocket.send_json({"error": "No scan_id provided"})
            await websocket.close()
            return
            
        print(f"WebSocket received scan_id: {scan_id}")
        while scan_id in active_scans and active_scans[scan_id]["status"] not in ["completed", "failed"]:
            try:
                await websocket.send_json({
                    "scan_id": scan_id,
                    "progress": active_scans[scan_id]["progress"],
                    "step": active_scans[scan_id]["step"],
                    "status": active_scans[scan_id]["status"],
                    "error": active_scans[scan_id].get("error", None)
                })
            except Exception as e:
                print(f"WebSocket send error for {scan_id}: {e}")
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = f"WebSocket communication error: {str(e)}"
                break
            await asyncio.sleep(1.0) 
            
        if scan_id in active_scans:
            try:
                await websocket.send_json({
                    "scan_id": scan_id,
                    "progress": active_scans[scan_id]["progress"],
                    "step": active_scans[scan_id]["step"],
                    "status": active_scans[scan_id]["status"],
                    "error": active_scans[scan_id].get("error", None)
                })
            except Exception as e:
                print(f"WebSocket send error on final update for {scan_id}: {e}")
    except Exception as e:
        print(f"WebSocket error for {scan_id}: {e}")
        try:
            await websocket.send_json({"error": f"WebSocket error: {str(e)}"})
        except Exception as close_error:
            print(f"Failed to send WebSocket error message for {scan_id}: {close_error}")
    finally:
        try:
            await websocket.close()
            print(f"WebSocket connection closed for {scan_id}")
        except Exception as e:
            print(f"Error closing WebSocket for {scan_id}: {e}")

@router.get("/api/v1/issues")
def get_issue_descriptions():
    try:
        path = Path(SKIPFISH_ISSUE_DESCRIPTIONS_JSON_PATH)
        if not path.exists() or path.stat().st_size == 0:
            return {"content": {}}
        with open(path, "r", encoding='utf-8') as f:
            issue_data = json.load(f)
        return {"content": issue_data}
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {path}: {e}")
        raise HTTPException(status_code=500, detail=f"Invalid JSON format in issue descriptions file: {e}")
    except Exception as e:
        print(f"Error in /api/v1/issues endpoint: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@router.post("/generate_pentest_response")
async def generate_pentest_response(request_data: ScanSummaryRequest):
    scan_summary = request_data.scanSummary
    if not scan_summary:
        raise HTTPException(status_code=400, detail="No scan summary provided.")
    summary_text = json.dumps(scan_summary, indent=2)
    prompt = f"""
    Provide me all the major possible threats which may occur due to the data in {summary_text}.Output should be in
    json format with fields in json being Vulnerability, Description, Impact, Remediation
    """
    try:
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = await model.generate_content_async(prompt)
        return {"aiResponse": response.text}
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error during AI generation: {str(e)}")