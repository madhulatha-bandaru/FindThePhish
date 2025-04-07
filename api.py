from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from feature_extraction import PredictURL
import validators

app = FastAPI()
classifier = PredictURL()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        return validators.url(url)
    except:
        return False

@app.get("/api")
async def check_url(url: str = ""):
    if not url:
        raise HTTPException(status_code=400, detail="URL parameter is required")
    
    if not is_valid_url(url):
        return {
            "msg": "Invalid URL format",
            "prediction": "invalid",
            "valid": False
        }
    
    try:
        result = classifier.predict(url)
        return {
            "msg": result,
            "prediction": "phishing" if "phishing" in result.lower() else "legitimate",
            "valid": True
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)