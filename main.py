from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import scan, logs, report

app = FastAPI(title="CloudMalScan API", version="1.0.0")

# Allow React frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router,   prefix="/api/scan")
app.include_router(logs.router,   prefix="/api/logs")
app.include_router(report.router, prefix="/api/report")

@app.get("/")
def root():
    return {"status": "CloudMalScan API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

