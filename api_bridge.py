from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from typing import List, Optional
import uvicorn, os, logging, datetime
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


load_dotenv()

# ── Logging ─────────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/bridge.log")
    ]
)
log = logging.getLogger(__name__)

app = FastAPI(
    title="NetOps SSH Bridge v4",
    description="Dumb executor. Agent is the brain. Runs any command on any device.",
    version="4.0.0"
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


# ── Load ALL devices dynamically from .env ───────────────────────────────────
# .env format for each device:
#   <ID>_HOST, <ID>_TYPE, <ID>_USER, <ID>_PASS, <ID>_PORT, <ID>_NAME
#
# Device IDs are discovered from .env keys ending in _HOST
# Example: FGT_HOST → device_id = "fgt"
#          CORE_HOST → device_id = "core"
#          ACCESS_HOST → device_id = "access"
#          ARUBA_HOST → device_id = "aruba"

def load_devices_from_env():
    devices = {}
    for key, val in os.environ.items():
        if key.endswith("_HOST") and val.strip():
            prefix = key[:-5]  # e.g. FGT, CORE, ACCESS, ARUBA
            device_id = prefix.lower()
            devices[device_id] = {
                "device_type": os.getenv(f"{prefix}_TYPE", "cisco_ios"),
                "host":        val.strip(),
                "username":    os.getenv(f"{prefix}_USER", "admin"),
                "password":    os.getenv(f"{prefix}_PASS", ""),
                "port":        int(os.getenv(f"{prefix}_PORT", "22")),
                "name":        os.getenv(f"{prefix}_NAME", device_id.upper()),
                "timeout":     int(os.getenv(f"{prefix}_TIMEOUT", "30")),
            }
    return devices

DEVICES = load_devices_from_env()
log.info(f"Loaded {len(DEVICES)} devices from .env: {list(DEVICES.keys())}")


# ═══════════════════════════════════════════════════════════════════════════
# NEW — Cisco ISE REST API (ERS) config
# Separate from SSH devices above. Uses ISE_API_IP (NOT _HOST) so it is
# never auto-discovered as a phantom SSH device by load_devices_from_env().
# ═══════════════════════════════════════════════════════════════════════════
import requests as ext_requests
from requests.auth import HTTPBasicAuth
ext_requests.packages.urllib3.disable_warnings()

ISE_API_IP   = os.getenv("ISE_API_IP", "")
ISE_API_USER = os.getenv("ISE_API_USER", "")
ISE_API_PASS = os.getenv("ISE_API_PASS", "")
ISE_API_PORT = int(os.getenv("ISE_API_PORT", "9060"))

if ISE_API_IP:
    log.info(f"ISE ERS API configured: {ISE_API_IP}:{ISE_API_PORT}")
else:
    log.info("ISE ERS API not configured (ISE_API_IP not set in .env) — /ise/api will return an error if called")


# ── Helper: get netmiko params (strip non-netmiko keys) ──────────────────────
def netmiko_params(device_id: str) -> dict:
    dev = DEVICES.get(device_id.lower())
    if not dev:
        raise HTTPException(
            status_code=404,
            detail=f"Device '{device_id}' not found. Available: {list(DEVICES.keys())}"
        )
    return {
        "device_type": dev["device_type"],
        "host":        dev["host"],
        "username":    dev["username"],
        "password":    dev["password"],
        "port":        dev["port"],
        "timeout":     dev["timeout"],
    }

def device_info(device_id: str) -> dict:
    return DEVICES.get(device_id.lower(), {})


# ── Request Models ────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    device_id: str
    commands: List[str]
    # Optional: use_textfsm for structured output (default False)
    use_textfsm: Optional[bool] = False

class ConfigRequest(BaseModel):
    device_id: str
    commands: List[str]
    # Optional: run these show commands after config to verify
    verify_commands: Optional[List[str]] = []

class RawRequest(BaseModel):
    device_id: str
    # Raw multiline text sent directly to device (useful for FortiGate config blocks)
    raw_text: str
    expect_string: Optional[str] = None

# NEW — request model for Cisco ISE REST API (ERS) calls
class IseApiRequest(BaseModel):
    method: str                    # GET, POST, PUT, DELETE
    path: str                      # e.g. "/ers/config/networkdevice"
    body: Optional[dict] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Bridge health + list of all configured devices."""
    return {
        "status": "ok",
        "service": "NetOps SSH Bridge v4",
        "timestamp": datetime.datetime.now().isoformat(),
        "device_count": len(DEVICES),
        "devices": {
            did: {
                "name": d["name"],
                "host": d["host"],
                "type": d["device_type"],
                "port": d["port"]
            }
            for did, d in DEVICES.items()
        },
        "ise_api_configured": bool(ISE_API_IP),
        "aws_api_configured": bool(os.getenv("AWS_ACCESS_KEY_ID"))
    }


@app.get("/devices")
def list_devices():
    """List all devices loaded from .env."""
    return {
        "devices": {
            did: {
                "name":        d["name"],
                "host":        d["host"],
                "device_type": d["device_type"],
                "port":        d["port"]
            }
            for did, d in DEVICES.items()
        }
    }


@app.get("/ping/{device_id}")
def ping_device(device_id: str):
    """
    Test SSH connectivity only. No commands run.
    Agent uses this to quickly verify a device is reachable before investigation.
    """
    params = netmiko_params(device_id)
    dev = device_info(device_id)
    try:
        with ConnectHandler(**params) as conn:
            prompt = conn.find_prompt()
        return {
            "success": True,
            "device_id": device_id,
            "name": dev.get("name", device_id),
            "host": params["host"],
            "prompt": prompt,
            "message": f"SSH connection to {params['host']} successful"
        }
    except NetmikoTimeoutException:
        return {"success": False, "device_id": device_id,
                "error": f"Timeout — {params['host']} not reachable. Is device up?"}
    except NetmikoAuthenticationException:
        return {"success": False, "device_id": device_id,
                "error": "Authentication failed. Check .env credentials."}
    except Exception as e:
        return {"success": False, "device_id": device_id, "error": str(e)}


@app.post("/run")
def run_commands(req: RunRequest):
    """
    Run ANY show/exec commands on a device.
    Agent decides what commands to run — no pre-defined list.
    
    Examples:
      - show vlan brief
      - show ip route
      - show firewall policy
      - show interfaces gi0/1
      - get router info routing-table all
      - diagnose firewall iprope list 100004
      - show mac address-table
      - show spanning-tree detail
      - ANY valid CLI command for the device
    """
    params = netmiko_params(req.device_id)
    dev = device_info(req.device_id)
    log.info(f"[RUN] {dev.get('name','?')} ({params['host']}) — {len(req.commands)} commands")
    
    try:
        results = {}
        with ConnectHandler(**params) as conn:
            hostname = conn.find_prompt().strip().rstrip("#>%$")
            for cmd in req.commands:
                log.info(f"[RUN]   → {cmd}")
                results[cmd] = conn.send_command(
                    cmd,
                    use_textfsm=req.use_textfsm,
                    read_timeout=60
                )
        return {
            "success":   True,
            "device_id": req.device_id,
            "name":      dev.get("name", req.device_id),
            "host":      params["host"],
            "hostname":  hostname,
            "results":   results
        }
    except NetmikoTimeoutException:
        return {"success": False, "device_id": req.device_id,
                "error": f"Timeout — {params['host']} not reachable"}
    except NetmikoAuthenticationException:
        return {"success": False, "device_id": req.device_id,
                "error": "Authentication failed"}
    except Exception as e:
        log.error(f"[RUN] Error: {e}")
        return {"success": False, "device_id": req.device_id, "error": str(e)}


@app.post("/configure")
def configure_device(req: ConfigRequest):
    """
    Push ANY configuration commands to a device.
    Agent decides what to configure — no pre-defined templates.
    
    This handles EVERYTHING:
    - Fix a VLAN mismatch
    - Add a firewall policy (block Google for a host)
    - Allow specific traffic
    - Create NAT rules
    - Add/remove routes
    - Shut/no-shut interfaces
    - INJECT a failure for demo (agent can do this too!)
    - Anything valid on the device CLI
    
    For Cisco: wraps in config terminal / end + write memory automatically
    For FortiGate: sends as config block directly
    For Aruba: sends as config block
    
    verify_commands: optional show commands to run after config to confirm change
    """
    params = netmiko_params(req.device_id)
    dev = device_info(req.device_id)
    dev_type = params["device_type"]
    
    log.info(f"[CONFIG] {dev.get('name','?')} ({params['host']}) — {len(req.commands)} commands")
    for cmd in req.commands:
        log.info(f"[CONFIG]   → {cmd}")
    
    try:
        config_output = ""
        verify_output = {}
        
        with ConnectHandler(**params) as conn:
            hostname = conn.find_prompt().strip().rstrip("#>%$")
            
            if dev_type == "cisco_ios":
                conn.enable()
                config_output = conn.send_config_set(req.commands)
                save_out = conn.save_config()
                config_output += f"\n{save_out}"
                
            elif dev_type == "fortinet":
                # FortiGate: send commands directly (already in config context if needed)
                config_output = conn.send_config_set(req.commands)
                
            elif dev_type in ("aruba_osswitch", "aruba_cx"):
                config_output = conn.send_config_set(req.commands)
                
            else:
                # Generic fallback
                config_output = conn.send_config_set(req.commands)
            
            # Run verification commands if provided
            if req.verify_commands:
                for vcmd in req.verify_commands:
                    verify_output[vcmd] = conn.send_command(vcmd, read_timeout=30)
        
        return {
            "success":         True,
            "device_id":       req.device_id,
            "name":            dev.get("name", req.device_id),
            "host":            params["host"],
            "hostname":        hostname,
            "commands_sent":   req.commands,
            "config_output":   config_output,
            "verify_output":   verify_output,
            "timestamp":       datetime.datetime.now().isoformat()
        }
        
    except NetmikoTimeoutException:
        return {"success": False, "device_id": req.device_id,
                "error": f"Timeout — {params['host']} not reachable"}
    except NetmikoAuthenticationException:
        return {"success": False, "device_id": req.device_id,
                "error": "Authentication failed"}
    except Exception as e:
        log.error(f"[CONFIG] Error: {e}")
        return {"success": False, "device_id": req.device_id, "error": str(e)}


@app.post("/run_raw")
def run_raw(req: RawRequest):
    """
    Send raw text directly to device terminal.
    Used for complex multi-block FortiGate configs or
    when agent needs precise control over what is sent.
    
    raw_text: exact text to send line by line
    """
    params = netmiko_params(req.device_id)
    dev = device_info(req.device_id)
    log.info(f"[RAW] {dev.get('name','?')} ({params['host']})")
    
    try:
        with ConnectHandler(**params) as conn:
            if req.expect_string:
                output = conn.send_command(
                    req.raw_text,
                    expect_string=req.expect_string,
                    read_timeout=60
                )
            else:
                output = conn.send_config_set(req.raw_text.splitlines())
        return {
            "success":   True,
            "device_id": req.device_id,
            "name":      dev.get("name", req.device_id),
            "output":    output
        }
    except Exception as e:
        log.error(f"[RAW] Error: {e}")
        return {"success": False, "device_id": req.device_id, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════
# NEW — Cisco ISE REST API (ERS) proxy endpoint
# ISE has NO CLI for network devices / policy sets / endpoint groups —
# those can ONLY be configured via this REST API. This endpoint lets the
# agent call it through the bridge, keeping the same "dumb executor" model.
# Fully isolated — does not touch DEVICES, netmiko_params(), or any SSH logic.
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/ise/api")
def ise_api_call(req: IseApiRequest):
    """
    Proxy calls to Cisco ISE's REST API (ERS).
    Agent decides method/path/body — no pre-defined templates.

    Examples:
      GET  /ers/config/networkdevice        → list all network devices
      POST /ers/config/networkdevice        → add a network device (NAD)
      GET  /ers/config/endpoint             → list endpoints
      GET  /ers/config/internaluser         → list internal users
      GET  /ers/config/policy/authorization → list authorization policies (if enabled)
    """
    if not ISE_API_IP:
        return {"success": False, "error": "ISE_API_IP not configured in .env"}

    url = f"https://{ISE_API_IP}:{ISE_API_PORT}{req.path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
    log.info(f"[ISE-API] {req.method.upper()} {req.path}")

    try:
        resp = ext_requests.request(
            req.method.upper(), url,
            auth=HTTPBasicAuth(ISE_API_USER, ISE_API_PASS),
            headers=headers, json=req.body,
            verify=False, timeout=20
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return {"success": resp.ok, "status_code": resp.status_code, "body": body}
    except Exception as e:
        log.error(f"[ISE-API] Error: {e}")
        return {"success": False, "error": str(e)}

    ISE_OPENAPI_PORT = int(os.getenv("ISE_OPENAPI_PORT", "9070"))

@app.post("/ise/openapi")
def ise_openapi_call(req: IseApiRequest):
    """
    Proxy calls to Cisco ISE's newer Open API (port 9070) —
    the ONLY path for Policy Sets, AuthN/AuthZ rules, TACACS+ Policy.
    Same request model as /ise/api (method, path, body), just a
    different ISE port and endpoint namespace (/api/v1/... not /ers/...).
    """
    if not ISE_API_IP:
        return {"success": False, "error": "ISE_API_IP not configured in .env"}
    url = f"https://{ISE_API_IP}:{ISE_OPENAPI_PORT}{req.path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    log.info(f"[ISE-OPENAPI] {req.method.upper()} {req.path}")
    try:
        resp = ext_requests.request(
            req.method.upper(), url,
            auth=HTTPBasicAuth(ISE_API_USER, ISE_API_PASS),
            headers=headers, json=req.body,
            verify=False, timeout=20
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return {"success": resp.ok, "status_code": resp.status_code, "body": body}
    except Exception as e:
        log.error(f"[ISE-OPENAPI] {e}")
        return {"success": False, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════
# AWS API Proxy — generic boto3 executor
# Agent specifies: service (e.g. "ec2"), action (e.g. "create_vpc"),
# params (dict matching the boto3 method's kwargs).
# Bridge is still a DUMB executor — it has zero AWS-specific logic,
# it just calls getattr(boto3_client, action)(**params).
# Credentials come from .env → AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
# AWS_SESSION_TOKEN (boto3 reads these automatically, no code needed for that).
# ══════════════════════════════════════════════════════════════════════════

AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1"))

class AwsApiRequest(BaseModel):
    service: str                       # e.g. "ec2"
    action: str                        # e.g. "create_vpc", "describe_vpcs"
    params: Optional[dict] = {}        # kwargs for that boto3 method
    region: Optional[str] = None       # defaults to AWS_DEFAULT_REGION


@app.post("/aws/api")
def aws_api_call(req: AwsApiRequest):
    """
    Generic proxy to any boto3 AWS service/action.
    Example: {"service": "ec2", "action": "create_vpc", "params": {"CidrBlock": "10.99.0.0/16"}}
    """
    region = req.region or AWS_DEFAULT_REGION
    try:
        client = boto3.client(req.service, region_name=region)
        method = getattr(client, req.action, None)
        if method is None:
            return {"success": False, "error": f"Unknown action '{req.action}' for service '{req.service}'"}

        log.info(f"[AWS-API] {req.service}.{req.action} region={region}")
        response = method(**(req.params or {}))
        response.pop("ResponseMetadata", None)   # noise, not useful to the agent
        return {"success": True, "result": response}

    except NoCredentialsError:
        log.error("[AWS-API] No credentials found")
        return {"success": False, "error": "AWS credentials not found — check .env AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN"}
    except ClientError as e:
        log.error(f"[AWS-API] ClientError: {e}")
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.error(f"[AWS-API] {e}")
        return {"success": False, "error": str(e)}



# ── Well-known endpoints for platform connector compatibility ─────────────────
@app.get("/.well-known/openid-configuration")
def openid_config(): return {}
@app.get("/.well-known/oauth-protected-resource")
def oauth_protected(): return {}
@app.get("/.well-known/oauth-authorization-server")
def oauth_auth_server(): return {}
@app.post("/register")
def register(): return {}


# ── Startup ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    host = os.getenv("APP_BIND", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000"))
    log.info(f"╔══════════════════════════════════════════╗")
    log.info(f"║   NetOps SSH Bridge v4 — Dumb Executor  ║")
    log.info(f"╚══════════════════════════════════════════╝")
    log.info(f"Listening on {host}:{port}")
    log.info(f"Devices loaded: {list(DEVICES.keys())}")
    log.info(f"ISE ERS API: {'configured — ' + ISE_API_IP if ISE_API_IP else 'not configured'}")
    log.info(f"Agent is the brain. Bridge just executes.")
    uvicorn.run(app, host=host, port=port, log_level="info")
