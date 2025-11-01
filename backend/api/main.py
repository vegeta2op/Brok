"""FastAPI application entry point"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Any
import asyncio
import uuid

from ..config import settings
from ..models import ScanRequest, ScanResult, ScanStatus
from ..agent import PentestAgent
from ..rag import KnowledgeBase, ScanHistory
from ..auth import AuthorizationManager

app = FastAPI(
    title="JimCrow API",
    description="Autonomous Penetration Testing Agent API",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
active_scans: Dict[str, Dict[str, Any]] = {}
websocket_connections: Dict[str, List[WebSocket]] = {}


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "JimCrow API",
        "version": "0.1.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/api/scans", response_model=dict)
async def create_scan(scan_request: ScanRequest):
    """Start a new penetration test scan"""
    
    # Validate authorization
    auth_manager = AuthorizationManager()
    if not auth_manager.is_authorized(scan_request.target_url):
        raise HTTPException(
            status_code=403,
            detail=f"Target {scan_request.target_url} is not authorized"
        )
    
    # Create scan ID
    scan_id = str(uuid.uuid4())
    
    # Store scan state
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": ScanStatus.PENDING,
        "target_url": scan_request.target_url,
        "mode": scan_request.mode,
        "progress": 0
    }
    
    # Start scan in background
    asyncio.create_task(run_scan(scan_id, scan_request))
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan has been initiated"
    }


async def run_scan(scan_id: str, scan_request: ScanRequest):
    """Run a scan in the background"""
    try:
        agent = PentestAgent()
        
        # Update status
        active_scans[scan_id]["status"] = ScanStatus.RUNNING
        await broadcast_scan_update(scan_id, {"status": "running"})
        
        # Execute scan
        result = await agent.scan(scan_request)
        
        # Save to history
        history = ScanHistory()
        await history.save_scan(result)
        
        # Update status
        active_scans[scan_id]["status"] = ScanStatus.COMPLETED
        active_scans[scan_id]["result"] = result
        
        await broadcast_scan_update(scan_id, {
            "status": "completed",
            "vulnerabilities": len(result.vulnerabilities)
        })
        
    except Exception as e:
        active_scans[scan_id]["status"] = ScanStatus.FAILED
        active_scans[scan_id]["error"] = str(e)
        
        await broadcast_scan_update(scan_id, {
            "status": "failed",
            "error": str(e)
        })


@app.get("/api/scans")
async def list_scans():
    """List all scans"""
    history = ScanHistory()
    scans = await history.get_recent_scans(limit=50)
    return {"scans": scans}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details"""
    history = ScanHistory()
    scan = await history.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan


@app.get("/api/scans/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get current scan status"""
    if scan_id in active_scans:
        return active_scans[scan_id]
    
    # Check history
    history = ScanHistory()
    scan = await history.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "completed": True
    }


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates"""
    await websocket.accept()
    
    # Register connection
    if scan_id not in websocket_connections:
        websocket_connections[scan_id] = []
    websocket_connections[scan_id].append(websocket)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        # Unregister connection
        websocket_connections[scan_id].remove(websocket)
        if not websocket_connections[scan_id]:
            del websocket_connections[scan_id]


async def broadcast_scan_update(scan_id: str, update: Dict[str, Any]):
    """Broadcast update to all connected WebSocket clients"""
    if scan_id in websocket_connections:
        for websocket in websocket_connections[scan_id]:
            try:
                await websocket.send_json(update)
            except:
                pass


@app.get("/api/targets")
async def list_targets():
    """List authorized targets"""
    auth_manager = AuthorizationManager()
    targets = auth_manager.get_authorized_targets()
    return {"targets": targets}


@app.post("/api/targets")
async def add_target(data: dict):
    """Add authorized target"""
    domain = data.get("domain")
    notes = data.get("notes", "")
    
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    
    auth_manager = AuthorizationManager()
    success = auth_manager.add_authorized_target(domain, notes=notes)
    
    if success:
        return {"message": f"Added {domain} to authorized targets"}
    else:
        raise HTTPException(status_code=400, detail="Domain already authorized")


@app.delete("/api/targets/{domain}")
async def remove_target(domain: str):
    """Remove authorized target"""
    auth_manager = AuthorizationManager()
    success = auth_manager.remove_authorized_target(domain)
    
    if success:
        return {"message": f"Removed {domain} from authorized targets"}
    else:
        raise HTTPException(status_code=404, detail="Domain not found")


@app.get("/api/knowledge-base/search")
async def search_knowledge_base(query: str, limit: int = 5):
    """Search knowledge base"""
    kb = KnowledgeBase()
    results = await kb.search(query, limit=limit)
    return {"results": results}


@app.get("/api/stats")
async def get_stats():
    """Get vulnerability statistics"""
    history = ScanHistory()
    stats = await history.get_vulnerability_stats()
    return stats


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.fastapi_host,
        port=settings.fastapi_port,
        log_level=settings.log_level.lower()
    )

