from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
# This imports your pipeline function from shield_cli.py
from shield_cli import shield_pipeline

# 1. Initialize FastAPI
app = FastAPI(title="Sentinel Shield API")

# 2. Define what the incoming request looks like
class ShieldRequest(BaseModel):
    user_prompt: str

# 3. Create the POST /shield endpoint
@app.post("/shield")
async def run_shield(request: ShieldRequest):
    try:
        # Pass the prompt to your existing logic
        result = shield_pipeline(request.user_prompt)
        
        # Return the dictionary (FastAPI converts this to JSON automatically)
        return result
    
    except Exception as e:
        # If your script crashes (e.g., DB connection issue), return a 500 error
        raise HTTPException(status_code=500, detail=str(e))

# Optional: Add a health check to make sure the server is up
@app.get("/")
def health_check():
    return {"status": "online", "model": "protectai/deberta-v3-base"}
