import requests
import hashlib
import time
import os
import socket
import urllib3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from threading import Thread, Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Em ambiente serverless (Vercel), variáveis globais não persistem confiavelmente entre requisições.
# Usaremos flask.session para dados de autenticação e este cache global apenas para dados voláteis.
global_cache = {
    "area_mapping": {},
    "device_states": {},
    "recent_events": []
}
cache_lock = Lock()

def generate_signature(userName, password, realm, randomKey):
    """Gera a assinatura de autenticação em 5 passos (MD5)."""
    temp1 = hashlib.md5(password.encode()).hexdigest()
    temp2 = hashlib.md5((userName + temp1).encode()).hexdigest()
    temp3 = hashlib.md5(temp2.encode()).hexdigest()
    temp4 = hashlib.md5((userName + ":" + realm + ":" + temp3).encode()).hexdigest()
    signature = hashlib.md5((temp4 + ":" + randomKey).encode()).hexdigest()
    return signature, temp4

def generate_update_signature(temp4, token):
    """Gera a assinatura para a renovação do token."""
    return hashlib.md5((temp4 + ":" + token).encode()).hexdigest()

def identificar_tipo_dispositivo(category, type_code):
    """Identifica o tipo de dispositivo com base na categoria e código de tipo."""
    category = str(category)
    type_code = str(type_code)
    
    if category == "1":
        if type_code == "2": return "Câmera IP"
        if type_code == "6": return "NVR"
        if type_code == "1": return "DVR"
        if type_code == "43": return "IVSS"
    if category == "5" and type_code == "1": return "Câmera ANPR"
    if category == "21": return "Interfonia"
    return "Câmera"

def atualizar_mapa_areas(token):
    """Busca a árvore de organizações e cria um mapa código -> nome."""
    with cache_lock:
        if global_cache["area_mapping"]:
            return
        base_url = session.get("base_url")

    url = f"{base_url}/tree/deviceOrg"
    headers = {"X-Subject-Token": token}

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            data = response.json()
            departments = data.get('data', [])
            if isinstance(departments, dict):
                departments = departments.get('departments', [])
            
            mapping = {}
            for dept in departments:
                if 'code' in dept and 'name' in dept:
                    mapping[dept['code']] = dept['name']
            
            with cache_lock:
                global_cache["area_mapping"] = mapping
    except Exception as e:
        print(f"Erro ao atualizar mapa de áreas: {e}")

def contabilizar_cameras_por_area(token, filter_types=None):
    atualizar_mapa_areas(token)
    with cache_lock:
        area_map = global_cache["area_mapping"].copy()

    url = f"{session.get('base_url')}/tree/devices"
    headers = {"X-Subject-Token": token, "Content-Type": "application/json"}
    payload = {"orgCode": "", "deviceCodes": [], "categories": ["1", "5", "8", "21"]}

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=15)
        response.raise_for_status()
        devices = response.json().get('data', {}).get('devices', [])

        stats_por_area = {}
        
        updates_states = {}
        new_events = []
        processed_codes = set()

        for dev in devices:
            if dev.get('category') in ["1", "5", "8", "21"]:
                items_to_process = []
                units = dev.get('units', [])
                found_channels = False
                
                if units:
                    for unit in units:
                        channels = unit.get('channels', [])
                        for ch in channels:
                            found_channels = True
                            items_to_process.append({
                                "code": ch.get("channelCode", ch.get("cameraCode")),
                                "name": ch.get("name", ch.get("channelName", dev.get("deviceName"))),
                                "status": ch.get("status")
                            })
                
                if not found_channels:
                    items_to_process.append({
                        "code": dev.get("deviceCode"),
                        "name": dev.get("deviceName", "Desconhecido"),
                        "status": dev.get("status")
                    })

                area_code = dev.get('orgCode', 'Sem Area')
                area_name = area_map.get(area_code, dev.get('orgName', area_code))

                dev_type = identificar_tipo_dispositivo(dev.get('category'), dev.get('type'))
                include_in_stats = True
                if filter_types is not None and dev_type not in filter_types:
                    include_in_stats = False

                for item in items_to_process:
                    device_code = item["code"]
                    
                    if device_code in processed_codes:
                        continue
                    processed_codes.add(device_code)

                    device_name = item["name"]
                    status = item["status"]
                    status_str = "Online" if status == "1" else "Offline"

                    with cache_lock:
                        old_status = global_cache["device_states"].get(device_code)
                        if old_status and old_status != status_str:
                            new_events.append({
                                "time": datetime.now().strftime("%H:%M:%S"),
                                "name": device_name,
                                "status": status_str,
                                "area": area_name,
                                "ip": dev.get("deviceIp", "-")
                            })
                        global_cache["device_states"][device_code] = status_str

                    if include_in_stats:
                        if area_name not in stats_por_area:
                            stats_por_area[area_name] = {'online': 0, 'offline': 0}

                        if status == "1":
                            stats_por_area[area_name]['online'] += 1
                        else:
                            stats_por_area[area_name]['offline'] += 1
        
        if new_events:
            with cache_lock:
                global_cache["recent_events"] = (new_events + global_cache["recent_events"])[:5]

        return stats_por_area, None
    except requests.exceptions.RequestException as e:
        print(f"Erro ao buscar dados das câmeras: {e}")
        return None, str(e)
    except ValueError:
        return None, "Resposta JSON inválida do servidor"

def listar_cameras(token, filter_types=None):
    """Lista todas as câmeras com detalhes (Nome, IP, Área, Status)."""
    atualizar_mapa_areas(token)
    with cache_lock:
        area_map = global_cache["area_mapping"].copy()

    url = f"{session.get('base_url')}/tree/devices"
    headers = {"X-Subject-Token": token, "Content-Type": "application/json"}
    payload = {"orgCode": "", "deviceCodes": [], "categories": ["1", "5", "8", "21"]}

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=15)
        response.raise_for_status()
        devices = response.json().get('data', {}).get('devices', [])

        lista = []
        processed_codes = set()

        for dev in devices:
            if dev.get('category') in ["1", "5", "8", "21"]:
                items_to_process = []
                units = dev.get('units', [])
                found_channels = False
                
                if units:
                    for unit in units:
                        channels = unit.get('channels', [])
                        for ch in channels:
                            found_channels = True
                            items_to_process.append({
                                "code": ch.get("channelCode", ch.get("cameraCode")),
                                "name": ch.get("name", ch.get("channelName", dev.get("deviceName"))),
                                "status": ch.get("status")
                            })
                
                if not found_channels:
                    items_to_process.append({
                        "name": dev.get("deviceName", "Desconhecido"),
                        "code": dev.get("deviceCode"),
                        "status": dev.get("status")
                    })

                area_code = dev.get('orgCode')
                area_name = area_map.get(area_code, dev.get('orgName', dev.get('orgCode', "Sem Área")))
                
                device_type_label = identificar_tipo_dispositivo(dev.get('category'), dev.get('type'))

                if filter_types is not None and device_type_label not in filter_types:
                    continue

                for item in items_to_process:
                    if item.get("code") and item["code"] in processed_codes:
                        continue
                    if item.get("code"):
                        processed_codes.add(item["code"])

                    lista.append({
                        "name": item["name"],
                        "ip": dev.get("deviceIp", "-"),
                        "type": device_type_label,
                        "area": area_name,
                        "status": "Online" if item["status"] == "1" else "Offline"
                    })
        return lista, None
    except Exception as e:
        return None, str(e)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "chave_secreta_padrao_para_vercel")

@app.route('/')
def index():
    """Rota principal que serve a página de login."""
    if session.get("is_logged_in"):
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Rota para visualizar o dashboard (protegida)."""
    if not session.get("is_logged_in"):
        return redirect(url_for('index'))
    # Passa os tipos de dispositivos para o template para criar o select box
    return render_template('dashboard.html', device_types=["Câmera IP", "NVR", "DVR", "IVSS", "Câmera ANPR", "Interfonia", "Câmera"])

@app.route('/logout')
def logout():
    session.clear()
    with cache_lock:
        global_cache["area_mapping"] = {}
        global_cache["device_states"] = {}
        global_cache["recent_events"] = []
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    """Endpoint para autenticação. Recebe as credenciais e inicia a sessão."""
    if session.get("is_logged_in"):
        return jsonify({"message": "Já está logado."}), 200

    data = request.get_json()
    if not data:
        return jsonify({"error": "Corpo da requisição deve ser um JSON válido."}), 400

    server_address = data.get("server_address")
    server_port = data.get("server_port")
    userName = data.get("userName")
    password = data.get("password")
    protocol = data.get("protocol", "https")

    if not all([server_address, server_port, userName, password]):
        return jsonify({"error": "Campos obrigatórios ausentes: server_address, server_port, userName, password"}), 400

    client_ip = socket.gethostbyname('localhost')

    payload_first = {"userName": userName, "ipAddress": client_ip, "clientType": "WINPC_V2"}
    api_paths = ["/brms/api/v1.0", "/admin/API"]

    for api_path in api_paths:
        try:
            base_url = f"{protocol}://{server_address}:{server_port}{api_path}"
            url_auth = f"{base_url}/accounts/authorize"

            response_first = requests.post(url_auth, json=payload_first, timeout=5, verify=False)
            if response_first.status_code == 404:
                continue

            data_res = response_first.json()
            realm = data_res.get("realm")
            randomKey = data_res.get("randomKey")

            if not realm or not randomKey:
                continue

            signature, temp4 = generate_signature(userName, password, realm, randomKey)

            payload_second = {
                "mac": "C4:CB:E1:11:5A:BA", "signature": signature, "userName": userName,
                "randomKey": randomKey, "encryptType": "MD5", "ipAddress": client_ip,
                "clientType": "WINPC_V2", "userType": "0"
            }

            response_second = requests.post(url_auth, json=payload_second, timeout=10, verify=False)
            auth_data = response_second.json()

            if "token" in auth_data:
                session["token"] = auth_data["token"]
                session["temp4"] = temp4
                session["base_url"] = base_url
                session["is_logged_in"] = True
                # duration = auth_data.get("duration", 30) # Gerenciado pelo cliente agora

                return jsonify({"message": "Autenticação bem-sucedida!"}), 200
            else:
                if "code" in auth_data and auth_data["code"] != 1000:
                    return jsonify({"error": "Falha na autenticação", "details": auth_data}), 401

        except Exception as e:
            print(f"Erro ao tentar o caminho {api_path}: {e}")
            continue

    return jsonify({"error": "Falha ao autenticar em todos os caminhos configurados."}), 500

@app.route('/keep_alive', methods=['POST'])
def keep_alive():
    """Endpoint para renovar o token (chamado pelo frontend)."""
    if not session.get("is_logged_in"):
        return jsonify({"error": "Não logado"}), 401
    
    token = session.get("token")
    temp4 = session.get("temp4")
    base_url = session.get("base_url")
    
    url_update = f"{base_url}/accounts/updateToken"
    update_signature = generate_update_signature(temp4, token)
    payload_update = {"signature": update_signature}
    headers = {"X-Subject-Token": token}
    
    try:
        res = requests.post(url_update, json=payload_update, headers=headers, timeout=10, verify=False)
        if res.status_code == 200:
            data = res.json()
            if "data" in data and "token" in data["data"]:
                session["token"] = data["data"]["token"]
                return jsonify({"status": "renovado", "token": session["token"]}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": "Falha na renovação"}), 400

@app.route('/camera_stats', methods=['GET'])
def get_camera_stats():
    """Endpoint que retorna as estatísticas de câmeras online/offline por área."""
    if not session.get("is_logged_in"):
        return jsonify({"error": "Não autenticado. Faça login em /login primeiro."}), 401
    token = session.get("token")

    filter_types = request.args.getlist('types')
    if not filter_types:
        filter_types = None

    stats, error = contabilizar_cameras_por_area(token, filter_types)

    if error:
        return jsonify({"error": "Falha ao obter estatísticas das câmeras", "details": error}), 500

    return jsonify(stats), 200

@app.route('/events', methods=['GET'])
def get_events():
    """Retorna os últimos eventos de mudança de status."""
    with cache_lock:
        return jsonify(global_cache["recent_events"]), 200

@app.route('/devices', methods=['GET'])
def get_devices_list():
    """Endpoint que retorna a lista detalhada de câmeras."""
    if not session.get("is_logged_in"):
        return jsonify({"error": "Não autenticado."}), 401
    token = session.get("token")

    filter_types = request.args.getlist('types')
    if not filter_types:
        filter_types = None

    devices, error = listar_cameras(token, filter_types)
    if error:
        return jsonify({"error": "Falha ao listar dispositivos", "details": error}), 500
    return jsonify(devices), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)