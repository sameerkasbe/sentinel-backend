from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from ..core.config import get_settings
from ..core.security import require_user
from ..schemas.common import UrlScanRequest, RepoScanRequest, AssistantRequest, ScanResponse, AssistantResponse
from ..services.url_scanner import scan_url
from ..services.repo_scanner import scan_repo
from ..services.file_scanner import scan_file
from ..services.assistant import answer

router=APIRouter(prefix="/api")

@router.get("/health")
async def health(): return {"status":"ok","service":"sentinel-backend"}

@router.post("/scan/url",response_model=ScanResponse)
async def url_scan(req:UrlScanRequest, user=Depends(require_user)):
    try: return await scan_url(str(req.url))
    except Exception as e: raise HTTPException(400,str(e))

@router.post("/scan/repository",response_model=ScanResponse)
async def repo_scan(req:RepoScanRequest,user=Depends(require_user)):
    try: return await scan_repo(str(req.repository_url),req.branch,get_settings().github_token)
    except Exception as e: raise HTTPException(400,str(e))

@router.post("/scan/file",response_model=ScanResponse)
async def file_scan(file:UploadFile=File(...),user=Depends(require_user)):
    try:
        data=await file.read()
        return await scan_file(file.filename or "uploaded-file",data)
    except Exception as e: raise HTTPException(400,str(e))

@router.post("/assistant",response_model=AssistantResponse)
async def assistant(req:AssistantRequest,user=Depends(require_user)):
    return answer(req.message,req.context)
