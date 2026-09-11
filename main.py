from fastapi import FastAPI, HTTPException,Body
import httpx
from typing import List
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates=Jinja2Templates(directory="templates")

GEO_API_URL = "https://ipapi.co/json/{ip}"  # or ipapi.com, ip-api.com, etc.

async def get_ip_location(ip: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(GEO_API_URL.format(ip=ip))
            resp.raise_for_status()
            data = resp.json()
            if data.get("error"):
                return None
            return {
                "ip": ip,
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country_name"),
                "lat": data.get("latitude"),
                "lon": data.get("longitude"),
                "org": data.get("org"),
            }
        except Exception as e:
            print(f"Geolocation failed for {ip}:{e}")
            return None
@app.get("/")
async def index():
    return templates.TemplateResponse("map.html",{"request":{}})

@app.post("/geolocate_ips")
async def geolocate_ips(ips: List[str]=Body(...)):
    results = []
    for ip in ips:
        info = await get_ip_location(ip)
        if info:
            results.append(info)
    return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
