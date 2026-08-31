from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import get_settings
from .api.routes import router

settings=get_settings()
app=FastAPI(title="Sentinel Security API",version="1.0.0",description="Security analysis API for Sentinel")
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_list,allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
app.include_router(router)

@app.get("/")
async def root(): return {"name":"Sentinel Security API","status":"online","docs":"/docs"}
