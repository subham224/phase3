from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import google.generativeai as genai

from core.config import GEMINI_API_KEY
from api.routes import router

# Configure AI
genai.configure(api_key=GEMINI_API_KEY)

app = FastAPI(
    title="Pentesting Tool API with GenAI",
    description="Backend for automated pentesting workflows with integrated GenAI analysis.",
    version="0.1.0"
)

# Mount Static Files
app.mount("/scans", StaticFiles(directory="scans"), name="scans")

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router
app.include_router(router)

@app.get("/")
async def root():
    return {"message": "Welcome to the Pentesting Tool API with GenAI!"}