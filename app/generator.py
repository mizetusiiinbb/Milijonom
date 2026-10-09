import base64
import json
import urllib.parse
from typing import List, Dict, Any
from app.config import WS_PATH_VLESS, WS_PATH_TROJAN

def generate_vless_link(user: Dict[str, Any], domain: str, early_data: bool = False) -> str:
    port = 443
    path = f"{WS_PATH_VLESS}?ed=2048" if early_data else WS_PATH_VLESS
    remark = f"Milijon-VLESS-{'EarlyData-Frag' if early_data else 'Direct-Frag'}-{user['username']}"
    
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2,http/1.1",
        "fragment": "100-200,10-20,tlshello"
    }

    query_str = urllib.parse.urlencode(params)
    return f"vless://{user['uuid']}@{domain}:{port}?{query_str}#{urllib.parse.quote(remark)}"

def generate_trojan_link(user: Dict[str, Any], domain: str, early_data: bool = False) -> str:
    port = 443
    path = f"{WS_PATH_TROJAN}?ed=2048" if early_data else WS_PATH_TROJAN
    remark = f"Milijon-Trojan-{'EarlyData-Frag' if early_data else 'Direct-Frag'}-{user['username']}"
    
    params = {
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2,http/1.1",
        "fragment": "100-200,10-20,tlshello"
    }

    query_str = urllib.parse.urlencode(params)
    return f"trojan://{user['password']}@{domain}:{port}?{query_str}#{urllib.parse.quote(remark)}"

def generate_all_links_for_user(user: Dict[str, Any], domain: str) -> List[str]:
    return [
        generate_vless_link(user, domain, early_data=True),
        generate_vless_link(user, domain, early_data=False),
        generate_trojan_link(user, domain, early_data=True),
        generate_trojan_link(user, domain, early_data=False)
    ]

def generate_base64_subscription(user: Dict[str, Any], domain: str) -> str:
    links = generate_all_links_for_user(user, domain)
    raw_sub = "\n".join(links)
    return base64.b64encode(raw_sub.encode('utf-8')).decode('utf-8')

def generate_clash_meta_yaml(user: Dict[str, Any], domain: str) -> str:
    yaml_content = f"""# Milijon Clash Meta / Mihomo Config for {user['username']}
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
mode: rule
log-level: info
ipv6: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 178.22.122.100

proxies:
  - name: "Milijon-VLESS-EarlyData"
    type: vless
    server: {domain}
    port: 443
    uuid: {user['uuid']}
    network: ws
    tls: true
    udp: true
    servername: {domain}
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    ws-opts:
      path: "{WS_PATH_VLESS}?ed=2048"
      headers:
        Host: {domain}

  - name: "Milijon-VLESS-Direct"
    type: vless
    server: {domain}
    port: 443
    uuid: {user['uuid']}
    network: ws
    tls: true
    udp: true
    servername: {domain}
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    ws-opts:
      path: "{WS_PATH_VLESS}"
      headers:
        Host: {domain}

  - name: "Milijon-Trojan-EarlyData"
    type: trojan
    server: {domain}
    port: 443
    password: {user['password']}
    network: ws
    tls: true
    udp: true
    sni: {domain}
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    ws-opts:
      path: "{WS_PATH_TROJAN}?ed=2048"
      headers:
        Host: {domain}

  - name: "Milijon-Trojan-Direct"
    type: trojan
    server: {domain}
    port: 443
    password: {user['password']}
    network: ws
    tls: true
    udp: true
    sni: {domain}
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    ws-opts:
      path: "{WS_PATH_TROJAN}"
      headers:
        Host: {domain}

proxy-groups:
  - name: "🚀 MILIJON"
    type: select
    proxies:
      - "⚡ AUTO-FASTEST"
      - "Milijon-VLESS-EarlyData"
      - "Milijon-VLESS-Direct"
      - "Milijon-Trojan-EarlyData"
      - "Milijon-Trojan-Direct"
      - DIRECT

  - name: "⚡ AUTO-FASTEST"
    type: url-test
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
    proxies:
      - "Milijon-VLESS-EarlyData"
      - "Milijon-VLESS-Direct"
      - "Milijon-Trojan-EarlyData"
      - "Milijon-Trojan-Direct"

rules:
  - DOMAIN-SUFFIX,ir,DIRECT
  - GEOIP,IR,DIRECT
  - MATCH,🚀 MILIJON
"""
    return yaml_content

def generate_singbox_json(user: Dict[str, Any], domain: str) -> str:
    singbox_config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns-remote", "address": "https://1.1.1.1/dns-query"},
                {"tag": "dns-direct", "address": "178.22.122.100", "detour": "direct"}
            ],
            "rules": [
                {"outbound": "any", "server": "dns-direct"},
                {"geosite": "ir", "server": "dns-direct"}
            ]
        },
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080, "sniff": True},
            {"type": "tun", "tag": "tun-in", "interface_name": "tun0", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "mtu": 1400, "stack": "system", "sniff": True}
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "🌐 Select Proxy",
                "outbounds": [
                    "⚡ Auto Fastest",
                    "vless-earlydata-fragment",
                    "vless-direct-fragment",
                    "trojan-earlydata-fragment",
                    "trojan-direct-fragment",
                    "direct"
                ]
            },
            {
                "type": "urltest",
                "tag": "⚡ Auto Fastest",
                "outbounds": [
                    "vless-earlydata-fragment",
                    "vless-direct-fragment",
                    "trojan-earlydata-fragment",
                    "trojan-direct-fragment"
                ],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50
            },
            {
                "type": "vless",
                "tag": "vless-earlydata-fragment",
                "server": domain,
                "server_port": 443,
                "uuid": user["uuid"],
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "fragment": {
                        "enabled": True,
                        "size": "100-200",
                        "sleep": "10-20"
                    },
                    "record_fragment": True
                },
                "transport": {
                    "type": "ws",
                    "path": f"{WS_PATH_VLESS}?ed=2048",
                    "headers": {"Host": domain}
                }
            },
            {
                "type": "vless",
                "tag": "vless-direct-fragment",
                "server": domain,
                "server_port": 443,
                "uuid": user["uuid"],
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "fragment": {
                        "enabled": True,
                        "size": "100-200",
                        "sleep": "10-20"
                    },
                    "record_fragment": True
                },
                "transport": {
                    "type": "ws",
                    "path": WS_PATH_VLESS,
                    "headers": {"Host": domain}
                }
            },
            {
                "type": "trojan",
                "tag": "trojan-earlydata-fragment",
                "server": domain,
                "server_port": 443,
                "password": user["password"],
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "fragment": {
                        "enabled": True,
                        "size": "100-200",
                        "sleep": "10-20"
                    },
                    "record_fragment": True
                },
                "transport": {
                    "type": "ws",
                    "path": f"{WS_PATH_TROJAN}?ed=2048",
                    "headers": {"Host": domain}
                }
            },
            {
                "type": "trojan",
                "tag": "trojan-direct-fragment",
                "server": domain,
                "server_port": 443,
                "password": user["password"],
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "fragment": {
                        "enabled": True,
                        "size": "100-200",
                        "sleep": "10-20"
                    },
                    "record_fragment": True
                },
                "transport": {
                    "type": "ws",
                    "path": WS_PATH_TROJAN,
                    "headers": {"Host": domain}
                }
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"clashing_mode": "Direct", "outbound": "direct"},
                {"clashing_mode": "Global", "outbound": "🌐 Select Proxy"},
                {"geoip": "ir", "outbound": "direct"},
                {"geosite": "ir", "outbound": "direct"}
            ],
            "auto_detect_interface": True
        }
    }
    return json.dumps(singbox_config, indent=2, ensure_ascii=False)

def generate_xray_json(user: Dict[str, Any], domain: str) -> str:
    """
    Generates a complete Xray JSON configuration for the user.
    Chains all proxy outbounds through dialerProxy: 'fragment'.
    Freedom fragment outbound handles Anti-DPI packet splitting (100-200, 10-20, tlshello).
    """
    xray_config = {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                "https://1.1.1.1/dns-query",
                "8.8.8.8",
                "1.1.1.1"
            ]
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            },
            {
                "tag": "http-in",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            }
        ],
        "outbounds": [
            {
                "tag": "Milijon-VLESS-EarlyData",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": domain,
                        "port": 443,
                        "users": [{
                            "id": user["uuid"],
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": domain,
                        "fingerprint": "chrome",
                        "alpn": ["h2", "http/1.1"]
                    },
                    "wsSettings": {
                        "path": f"{WS_PATH_VLESS}?ed=2048",
                        "headers": {"Host": domain}
                    },
                    "sockopt": {
                        "dialerProxy": "fragment"
                    }
                }
            },
            {
                "tag": "Milijon-VLESS-Direct",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": domain,
                        "port": 443,
                        "users": [{
                            "id": user["uuid"],
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": domain,
                        "fingerprint": "chrome",
                        "alpn": ["h2", "http/1.1"]
                    },
                    "wsSettings": {
                        "path": WS_PATH_VLESS,
                        "headers": {"Host": domain}
                    },
                    "sockopt": {
                        "dialerProxy": "fragment"
                    }
                }
            },
            {
                "tag": "Milijon-Trojan-EarlyData",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": domain,
                        "port": 443,
                        "password": user["password"]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": domain,
                        "fingerprint": "chrome",
                        "alpn": ["h2", "http/1.1"]
                    },
                    "wsSettings": {
                        "path": f"{WS_PATH_TROJAN}?ed=2048",
                        "headers": {"Host": domain}
                    },
                    "sockopt": {
                        "dialerProxy": "fragment"
                    }
                }
            },
            {
                "tag": "Milijon-Trojan-Direct",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": domain,
                        "port": 443,
                        "password": user["password"]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": domain,
                        "fingerprint": "chrome",
                        "alpn": ["h2", "http/1.1"]
                    },
                    "wsSettings": {
                        "path": WS_PATH_TROJAN,
                        "headers": {"Host": domain}
                    },
                    "sockopt": {
                        "dialerProxy": "fragment"
                    }
                }
            },
            {
                "tag": "fragment",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "AsIs",
                    "fragment": {
                        "packets": "tlshello",
                        "length": "100-200",
                        "interval": "10-20"
                    }
                },
                "streamSettings": {
                    "sockopt": {
                        "mark": 255
                    }
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIP"}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {"response": {"type": "none"}}
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "outboundTag": "direct", "ip": ["geoip:private", "geoip:ir"]},
                {"type": "field", "outboundTag": "direct", "domain": ["geosite:ir", "domain:ir"]}
            ]
        }
    }
    return json.dumps(xray_config, indent=2, ensure_ascii=False)
