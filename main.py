import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
import datetime
from typing import Optional
from fastapi import FastAPI, Request, Response, WebSocket, HTTPException, status, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import psutil
except ImportError:
    psutil = None

from app.config import (
    PORT, HOST, ADMIN_PASSWORD, SECRET_KEY, SERVER_DOMAIN,
    WS_PATH_VLESS, WS_PATH_TROJAN
)
from app.database import (
    init_db, get_all_users, get_user_by_uuid, get_user_by_username,
    create_user, delete_user, toggle_user_status
)
from app.proxy_engine import handle_vless_websocket, handle_trojan_websocket
from app.generator import (
    generate_vless_link, generate_trojan_link,
    generate_all_links_for_user, generate_base64_subscription,
    generate_clash_meta_yaml, generate_singbox_json, generate_xray_json
)

app = FastAPI(title="Milijon Proxy Worker", version="2.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = time.time()
templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.on_event("startup")
def on_startup():
    init_db()

def check_auth(request: Request):
    auth_header = request.headers.get("Authorization")
    auth_cookie = request.cookies.get("milijon_token")
    expected_token = f"Bearer {ADMIN_PASSWORD}"
    
    if auth_header and auth_header == expected_token:
        return True
    if auth_cookie and auth_cookie == ADMIN_PASSWORD:
        return True
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials")

def get_effective_domain(request: Request) -> str:
    if SERVER_DOMAIN and SERVER_DOMAIN.strip():
        return SERVER_DOMAIN.strip()
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    if ":" in host and ("railway.app" in host or host.startswith("localhost")):
        pass
    return host.split(":")[0] if "railway.app" in host else host

class UserCreateRequest(BaseModel):
    username: str
    uuid: Optional[str] = None
    password: Optional[str] = None
    notes: Optional[str] = ""

class LoginRequest(BaseModel):
    password: str

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    domain = get_effective_domain(request)
    html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "templates", "index.html")
    if os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            html = f.read()
        html = html.replace("{{ domain }}", domain)
        return HTMLResponse(content=html, media_type="text/html; charset=utf-8")
    return HTMLResponse("<h1>Milijon Proxy Worker Active</h1>", media_type="text/html; charset=utf-8")

@app.get("/health")
@app.get("/api/health")
@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "app": "Milijon",
        "version": "2.2.0",
        "uptime_seconds": int(time.time() - START_TIME)
    }

@app.post("/api/login")
@app.post("/api/v1/login")
async def login(req: LoginRequest, response: Response):
    if req.password == ADMIN_PASSWORD:
        response.set_cookie(
            key="milijon_token",
            value=ADMIN_PASSWORD,
            httponly=True,
            samesite="lax",
            max_age=86400 * 30
        )
        return {"success": True, "token": ADMIN_PASSWORD}
    raise HTTPException(status_code=401, detail="رمز عبور اشتباه است / Invalid password")

@app.get("/api/me")
async def check_admin(request: Request):
    check_auth(request)
    return {"authenticated": True}

@app.get("/api/stats")
@app.get("/api/v1/stats")
async def get_system_stats(request: Request):
    check_auth(request)
    uptime_sec = int(time.time() - START_TIME)
    uptime_str = str(datetime.timedelta(seconds=uptime_sec))
    
    users = get_all_users()
    total_users = len(users)
    active_users = sum(1 for u in users if u["is_active"] == 1)
    total_up = sum(u["upload_bytes"] for u in users)
    total_down = sum(u["download_bytes"] for u in users)

    mem, cpu = 0.0, 0.0
    if psutil:
        try:
            mem = psutil.virtual_memory().percent
            cpu = psutil.cpu_percent(interval=None)
        except Exception:
            pass

    return {
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "total_users": total_users,
        "active_users": active_users,
        "total_upload_bytes": total_up,
        "total_download_bytes": total_down,
        "memory_percent": mem,
        "cpu_percent": cpu,
        "server_domain": get_effective_domain(request),
        "vless_path": WS_PATH_VLESS,
        "trojan_path": WS_PATH_TROJAN
    }

@app.get("/api/users")
@app.get("/api/v1/users")
async def list_users(request: Request):
    check_auth(request)
    domain = get_effective_domain(request)
    users = get_all_users()
    result = []
    for u in users:
        u_dict = dict(u)
        u_dict["vless_link"] = generate_vless_link(u_dict, domain, early_data=False)
        u_dict["trojan_link"] = generate_trojan_link(u_dict, domain, early_data=False)
        u_dict["sub_url"] = f"{request.base_url}sub/{u_dict['uuid']}"
        u_dict["sub_url_singbox"] = f"{request.base_url}sub/{u_dict['uuid']}?type=singbox"
        u_dict["sub_url_clash"] = f"{request.base_url}sub/{u_dict['uuid']}?type=clash"
        u_dict["sub_url_xray"] = f"{request.base_url}sub/{u_dict['uuid']}?type=xray"
        u_dict["sub_url_b64"] = f"{request.base_url}sub/{u_dict['uuid']}"
        result.append(u_dict)
    return result

@app.post("/api/users")
async def add_user(req: UserCreateRequest, request: Request):
    check_auth(request)
    existing = get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="این نام کاربری از قبل وجود دارد / Username already exists")
    
    user = create_user(
        username=req.username,
        user_uuid=req.uuid,
        password=req.password,
        notes=req.notes or ""
    )
    return user

@app.post("/api/users/{user_id}/toggle")
async def toggle_user(user_id: int, request: Request):
    check_auth(request)
    new_status = toggle_user_status(user_id)
    if new_status is None:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد / User not found")
    return {"id": user_id, "is_active": new_status}

@app.delete("/api/users/{user_id}")
async def remove_user(user_id: int, request: Request):
    check_auth(request)
    success = delete_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد / User not found")
    return {"success": True}

@app.get("/api/users/{user_id}/links")
async def get_user_links(user_id: int, request: Request):
    check_auth(request)
    domain = get_effective_domain(request)
    users = get_all_users()
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    vless_direct = generate_vless_link(user, domain, early_data=False)
    vless_earlydata = generate_vless_link(user, domain, early_data=True)
    trojan_direct = generate_trojan_link(user, domain, early_data=False)
    trojan_earlydata = generate_trojan_link(user, domain, early_data=True)
    
    clash_yaml = generate_clash_meta_yaml(user, domain)
    singbox_json = generate_singbox_json(user, domain)
    xray_json = generate_xray_json(user, domain)
    sub_url = f"{request.base_url}sub/{user['uuid']}"

    return {
        "user": user,
        "vless_direct": vless_direct,
        "vless_earlydata": vless_earlydata,
        "trojan_direct": trojan_direct,
        "trojan_earlydata": trojan_earlydata,
        "sub_url": sub_url,
        "clash_yaml": clash_yaml,
        "singbox_json": singbox_json,
        "sub_url_xray": f"{request.base_url}sub/{user['uuid']}?type=xray",
        "xray_json": xray_json
    }

@app.get("/sub/{token}")
@app.get("/api/v1/sub/{token}")
async def get_subscription(
    token: str,
    request: Request,
    format: Optional[str] = Query(None, alias="type")
):
    token = token.strip()
    user = get_user_by_uuid(token)
    if not user:
        user = get_user_by_username(token)
    
    if not user or user["is_active"] != 1:
        raise HTTPException(status_code=404, detail="اشتراک یافت نشد یا غیرفعال است / Subscription not found or inactive")

    domain = get_effective_domain(request)
    req_format = (format or "").lower().strip()
    user_name = user.get("username", "user")

    headers = {
        "Profile-Update-Interval": "12",
        "Subscription-Userinfo": f"upload={user['upload_bytes']}; download={user['download_bytes']}; total=1073741824000; expire=0",
        "Cache-Control": "no-cache, no-store, must-revalidate"
    }

    if req_format in ["clash", "clashmeta", "meta"]:
        yaml_content = generate_clash_meta_yaml(user, domain)
        headers["Content-Disposition"] = f'attachment; filename="milijon_{user_name}_clash.yaml"'
        return Response(content=yaml_content, media_type="text/yaml; charset=utf-8", headers=headers)

    elif req_format in ["singbox", "sb"]:
        json_content = generate_singbox_json(user, domain)
        headers["Content-Disposition"] = f'attachment; filename="milijon_{user_name}_singbox.json"'
        return Response(content=json_content, media_type="application/json; charset=utf-8", headers=headers)

    elif req_format in ["xray", "v2ray-json", "json"]:
        json_content = generate_xray_json(user, domain)
        headers["Content-Disposition"] = f'attachment; filename="milijon_{user_name}_xray.json"'
        return Response(content=json_content, media_type="application/json; charset=utf-8", headers=headers)

    elif req_format in ["raw", "plain"]:
        links = generate_all_links_for_user(user, domain)
        return PlainTextResponse("\n".join(links), headers=headers)

    else:
        b64_content = generate_base64_subscription(user, domain)
        headers["Content-Disposition"] = f'inline; filename="Milijon_{user_name}.txt"'
        return PlainTextResponse(b64_content, headers=headers)

# WebSocket Proxy Handlers
@app.websocket(WS_PATH_VLESS)
async def websocket_endpoint_vless(websocket: WebSocket):
    await handle_vless_websocket(websocket)

@app.websocket(WS_PATH_TROJAN)
async def websocket_endpoint_trojan(websocket: WebSocket):
    await handle_trojan_websocket(websocket)
