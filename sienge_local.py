#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extrator de Notas -> Sienge — programa local
=============================================

Roda um servidor no SEU computador (nao precisa de internet alem de falar
com o Sienge). Todas as chamadas ao Sienge saem direto do Python, sem passar
por navegador nenhum — e por isso nunca esbarram em CORS, bloqueio de
navegador, ou nas restricoes do preview do Claude.

COMO USAR:
1. Precisa ter Python 3 instalado (a maioria dos Windows/Mac ja tem).
2. Da dois cliques no arquivo "iniciar.bat" (Windows) ou rode:
       python3 sienge_local.py
   no terminal, na mesma pasta deste arquivo.
3. Uma aba do navegador abre sozinha em http://localhost:8765
4. Na primeira vez, preencha subdominio / usuario / senha da API do Sienge
   e salve — fica guardado so neste computador, num arquivo texto na mesma
   pasta (sienge_config.json). Nunca sai daqui, nunca vai pra internet a
   nao ser direto pro Sienge.
5. Extraia os dados do PDF como sempre (pelo card do Claude), copie o
   "payload JSON" de cada nota, cole aqui e clique em Enviar.
"""

import json
import os
import re
import base64
import hashlib
import secrets
import datetime
import threading
import webbrowser
import urllib.request
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8765
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# PASTA COMPARTILHADA — preencha o caminho da pasta de rede da vex aqui pra
# que todo mundo que usar esse programa compartilhe as mesmas credenciais e o
# mesmo aprendizado (credores, centros de custo, histórico). Exemplos de
# caminho: r"\\SERVIDOR\Compartilhado\ExtratorSienge" ou r"Z:\ExtratorSienge"
# (letra de uma unidade de rede mapeada). Deixe como está (vazio) se cada
# pessoa for usar só na própria máquina, sem compartilhar nada.
# ---------------------------------------------------------------------------
SHARED_FOLDER = r""

DATA_DIR = SHARED_FOLDER if SHARED_FOLDER.strip() else BASE_DIR
os.makedirs(DATA_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(DATA_DIR, 'sienge_config.json')
CREDITOR_MAP_FILE = os.path.join(DATA_DIR, 'credores_memorizados.json')
DOC_TYPE_MAP_FILE = os.path.join(DATA_DIR, 'tipos_documento_memorizados.json')
HISTORY_FILE = os.path.join(DATA_DIR, 'historico_titulos.json')
PAGADOR_MAP_FILE = os.path.join(DATA_DIR, 'pagadores_memorizados.json')
USERS_FILE = os.path.join(DATA_DIR, 'usuarios.json')

# Senha mestre de administrador — usada só pra entrar como "admin" a primeira
# vez, antes de existir qualquer usuário aprovado (evita ficar trancado pra
# fora do próprio site). Configure isso na hospedagem (variável de ambiente
# SITE_PASSWORD); localmente, sem essa variável, o site não pede login.
MASTER_PASSWORD = os.environ.get('SITE_PASSWORD', '')
SESSIONS = {}  # token -> username (em memória — reinicia com o servidor)


# --------------------------------------------------------------------------
# Armazenamento local (arquivos texto simples na mesma pasta do programa)
# --------------------------------------------------------------------------

def load_json_file(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def save_json_file(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_config():
    return load_json_file(CONFIG_FILE, {
        'sub': 'vex', 'user': '', 'pass': '',
        'endpoint': 'bills', 'costCenterEndpoint': 'cost-centers',
        'companyEndpoint': 'companies', 'docType': 'NF', 'creditor': '',
        'anthropicApiKey': '',
        'issTaxId': '', 'irrfTaxId': '', 'inssTaxId': '', 'pisCofinsCsllTaxId': ''
    })


def get_creditor_map():
    return load_json_file(CREDITOR_MAP_FILE, {})


def get_doc_type_map():
    return load_json_file(DOC_TYPE_MAP_FILE, {})


def get_pagador_map():
    return load_json_file(PAGADOR_MAP_FILE, {})


def get_users():
    return load_json_file(USERS_FILE, {})


def save_users(users):
    save_json_file(USERS_FILE, users)


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000).hex()
    return salt, digest


def verify_password(password, salt, digest):
    _, check = hash_password(password, salt)
    return secrets.compare_digest(check, digest)


def register_user(username, password):
    username = (username or '').strip().lower()
    if not username or not password:
        return False, 'Preencha usuário e senha.'
    if len(password) < 4:
        return False, 'A senha precisa ter pelo menos 4 caracteres.'
    users = get_users()
    if username in users:
        return False, 'Esse usuário já existe.'
    salt, digest = hash_password(password)
    users[username] = {
        'salt': salt, 'passwordHash': digest,
        'approved': False, 'isAdmin': False,
        'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    save_users(users)
    return True, 'Conta criada — aguarde um administrador aprovar seu acesso.'


def authenticate(username, password):
    """Retorna (ok, is_admin, motivo_se_falhar)."""
    username = (username or '').strip().lower()
    if MASTER_PASSWORD and username == 'admin' and password == MASTER_PASSWORD:
        return True, True, None
    users = get_users()
    user = users.get(username)
    if not user:
        return False, False, 'Usuário ou senha incorretos.'
    if not verify_password(password, user['salt'], user['passwordHash']):
        return False, False, 'Usuário ou senha incorretos.'
    if not user.get('approved'):
        return False, False, 'Sua conta ainda não foi aprovada por um administrador.'
    return True, bool(user.get('isAdmin')), None


def create_session(username):
    token = secrets.token_hex(24)
    SESSIONS[token] = username
    return token


def get_session_user(handler):
    cookie_header = handler.headers.get('Cookie', '')
    token = None
    for part in cookie_header.split(';'):
        part = part.strip()
        if part.startswith('session='):
            token = part[len('session='):]
            break
    if not token or token not in SESSIONS:
        return None
    username = SESSIONS[token]
    if username == 'admin' and MASTER_PASSWORD:
        return {'username': 'admin', 'isAdmin': True}
    users = get_users()
    user = users.get(username)
    if not user or not user.get('approved'):
        return None
    return {'username': username, 'isAdmin': bool(user.get('isAdmin'))}


def get_history():
    return load_json_file(HISTORY_FILE, [])


def append_history(entry):
    history = get_history()
    history.append(entry)
    # mantém só os últimos 500 lançamentos, pra não crescer sem limite
    history = history[-500:]
    save_json_file(HISTORY_FILE, history)


def normalize_words(text):
    text = re.sub(r'[^a-zA-ZÀ-ÿ0-9 ]', ' ', (text or '').upper())
    return set(w for w in text.split() if len(w) > 3)


def find_similar_history(descricao, exclude_cnpj=None, limit=5):
    """Procura lançamentos anteriores com descrição parecida (por palavras em
    comum), pra sugerir centro de custo / plano financeiro mesmo quando é um
    fornecedor novo mas o tipo de despesa já apareceu antes."""
    words = normalize_words(descricao)
    if not words:
        return []
    history = get_history()
    scored = []
    for entry in reversed(history):  # mais recentes primeiro
        if exclude_cnpj and entry.get('cnpj') == exclude_cnpj:
            continue
        entry_words = normalize_words(entry.get('descricao', ''))
        common = words & entry_words
        if common:
            scored.append((len(common), entry))
    scored.sort(key=lambda x: -x[0])
    return [e for _, e in scored[:limit]]


# --------------------------------------------------------------------------
# Chamada ao Sienge (sem CORS, sem navegador — Python puro)
# --------------------------------------------------------------------------

def call_sienge(method, path, query='', body=None):
    cfg = get_config()
    if not cfg.get('sub') or not cfg.get('user') or not cfg.get('pass'):
        return 400, {'error': 'Preencha subdomínio, usuário e senha na Configuração antes de usar.'}

    url = f"https://api.sienge.com.br/{cfg['sub']}/public/api/v1/{path}"
    if query:
        url += ('&' if '?' in url else '?') + query

    auth = base64.b64encode(f"{cfg['user']}:{cfg['pass']}".encode('utf-8')).decode('ascii')
    headers = {'Authorization': f'Basic {auth}'}
    data = None
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            location = resp.headers.get('Location') or resp.headers.get('location')
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and location and 'id' not in parsed:
                    parsed['id'] = extract_id_from_location(location)
                    parsed['_location'] = location
                return resp.status, parsed
            except json.JSONDecodeError:
                result = {'raw': raw}
                if location:
                    result['location'] = location
                    extracted = extract_id_from_location(location)
                    if extracted is not None:
                        result['id'] = extracted
                return resp.status, result
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', errors='replace')
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {'error': raw}
    except Exception as e:
        return 502, {'error': f'Não consegui falar com o Sienge: {e}'}


def extract_id_from_location(location):
    """O cabeçalho Location costuma vir como '.../bills/12345' — pega o
    último pedaço numérico da URL, que é o ID do recurso recém-criado."""
    if not location:
        return None
    parts = [p for p in location.rstrip('/').split('/') if p]
    if parts and parts[-1].isdigit():
        return int(parts[-1])
    return None


def call_sienge_attachment(bill_id, description, filename, file_bytes):
    """Envia um arquivo como anexo de um título — multipart/form-data,
    formato exigido especificamente por esse endpoint (diferente do JSON
    usado em todo o resto da API)."""
    cfg = get_config()
    if not cfg.get('sub') or not cfg.get('user') or not cfg.get('pass'):
        return 400, {'error': 'Preencha subdomínio, usuário e senha na Configuração antes de usar.'}

    query = urllib.parse.urlencode({'description': description})
    url = f"https://api.sienge.com.br/{cfg['sub']}/public/api/v1/bills/{bill_id}/attachments?{query}"

    boundary = '----ExtratorSiengeBoundary7d8f3a'
    content_type_guess = 'application/pdf' if filename.lower().endswith('.pdf') else 'application/octet-stream'

    body = bytearray()
    body += f'--{boundary}\r\n'.encode('utf-8')
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode('utf-8')
    body += f'Content-Type: {content_type_guess}\r\n\r\n'.encode('utf-8')
    body += file_bytes
    body += f'\r\n--{boundary}--\r\n'.encode('utf-8')

    auth = base64.b64encode(f"{cfg['user']}:{cfg['pass']}".encode('utf-8')).decode('ascii')
    headers = {
        'Authorization': f'Basic {auth}',
        'Content-Type': f'multipart/form-data; boundary={boundary}',
    }

    req = urllib.request.Request(url, data=bytes(body), headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {'raw': raw}
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', errors='replace')
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {'error': raw}
    except Exception as e:
        return 502, {'error': f'Não consegui enviar o anexo: {e}'}


EXTRACTION_PROMPT = """Você é um extrator de dados de documentos fiscais e boletos brasileiros (notas fiscais de serviço/produto, faturas ou boletos bancários). Analise o PDF anexado e responda SOMENTE com um objeto JSON válido, sem markdown, sem crases, sem texto adicional, com exatamente estas chaves:
{
 "fornecedor_nome": string ou null,
 "fornecedor_cnpj": string ou null (apenas números),
 "pagador_nome": string ou null (o "Tomador"/"Pagador"/"Sacado" — quem contratou o serviço ou vai pagar, NÃO o fornecedor),
 "pagador_cnpj": string ou null (CNPJ do pagador/tomador, apenas números),
 "numero_documento": string ou null,
 "tipo_documento": string ou null (ex: "NFS-e", "NF-e", "Fatura", "Boleto"),
 "data_emissao": string "YYYY-MM-DD" ou null,
 "data_vencimento": string "YYYY-MM-DD" ou null,
 "valor_total": number ou null,
 "descricao": string curta (até 140 caracteres) resumindo o produto/serviço, ou null,
 "linha_digitavel": string ou null (SOMENTE para boletos bancários — a sequência longa de números agrupados por pontos, geralmente perto do código de barras, tipo "74891.12610 00363.908096 18400.971059 7 15550000020000". Mantenha os espaços e pontos exatamente como aparecem no documento. Para notas fiscais e faturas sem boleto, deixe null.),
 "iss_valor": number ou null (valor do ISSQN — some da nota mesmo se não for retido, costuma vir como "Vl. ISSQN" ou "Valor do ISS"),
 "iss_aliquota": number ou null (percentual do ISS, ex: 4.25 — costuma vir como "Alíquota"),
 "iss_retido": boolean (true se a nota indicar "Retido"/"Retenção" pro ISS, false se disser "Não Retido" ou não mencionar retenção),
 "irrf_valor": number ou null (valor retido de IRRF, se houver — costuma vir como "Vl. IRRF"; use null se a nota disser "Não Retido" ou "-"),
 "irrf_aliquota": number ou null (percentual do IRRF, se houver),
 "inss_valor": number ou null (valor retido de INSS/CP, se houver — costuma vir como "Vl. CP Retido" ou "Vl. INSS"; use null se não houver retenção),
 "inss_aliquota": number ou null (percentual do INSS, se houver),
 "pis_cofins_csll_valor": number ou null (soma dos valores retidos de PIS+COFINS+CSLL, se houver; use null se a nota disser "PIS/COFINS/CSLL Não Retidos"),
 "pis_cofins_csll_aliquota": number ou null (percentual retido de PIS+COFINS+CSLL somados, se houver),
 "base_calculo": number ou null (base de cálculo dos impostos, costuma vir como "Base de Cálculo" — se não achar, use o mesmo valor de valor_total),
 "municipio_ibge": string ou null (código IBGE do município de incidência do ISS, se aparecer na nota — geralmente 7 dígitos; se só tiver o nome da cidade sem o código, deixe null)
}
Atenção especial em boletos bancários: eles costumam ter DOIS CNPJs — o do "Beneficiário"/"Cedente" (quem vai RECEBER o pagamento — vai em fornecedor_nome/fornecedor_cnpj) e o do "Pagador"/"Sacado" (quem vai pagar — vai em pagador_nome/pagador_cnpj). Nunca troque os dois.
Em notas fiscais de serviço, o "Prestador" é o fornecedor (fornecedor_nome/fornecedor_cnpj) e o "Tomador" é o pagador (pagador_nome/pagador_cnpj).
Boletos frequentemente repetem o mesmo conjunto de campos mais de uma vez na mesma página (ex: "Recibo do Pagador" seguido de "Ficha de Compensação" com os mesmos dados) — isso é normal, use a primeira ocorrência completa. Ignore qualquer bloco de código PIX "copia e cola" (uma sequência longa de letras e números tipo "00020126...") — isso NÃO é a linha digitável, é um código diferente.
Se não encontrar um campo com confiança, use null. Não invente valores."""


def call_extraction(filename, file_bytes):
    cfg = get_config()
    api_key = cfg.get('anthropicApiKey', '').strip()
    if not api_key:
        return 400, {'error': 'Preencha a chave de API da Anthropic na Configuração antes de extrair PDFs.'}

    file_b64 = base64.b64encode(file_bytes).decode('ascii')
    payload = {
        'model': 'claude-haiku-4-5-20251001',
        'max_tokens': 1000,
        'messages': [{
            'role': 'user',
            'content': [
                {'type': 'document', 'source': {'type': 'base64', 'media_type': 'application/pdf', 'data': file_b64}},
                {'type': 'text', 'text': EXTRACTION_PROMPT}
            ]
        }]
    }
    data = json.dumps(payload).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': api_key,
        'anthropic-version': '2023-06-01',
    }
    req = urllib.request.Request('https://api.anthropic.com/v1/messages', data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        raw_text = e.read().decode('utf-8', errors='replace')
        try:
            return e.code, json.loads(raw_text)
        except json.JSONDecodeError:
            return e.code, {'error': raw_text}
    except Exception as e:
        return 502, {'error': f'Não consegui falar com a API da Anthropic: {e}'}

    text_blocks = [b.get('text', '') for b in raw.get('content', []) if b.get('type') == 'text']
    text = '\n'.join(text_blocks).strip()
    cleaned = text.replace('```json', '').replace('```', '').strip()
    try:
        fields = json.loads(cleaned)
    except json.JSONDecodeError:
        return 502, {'error': 'A IA respondeu, mas não veio um JSON válido: ' + text[:300]}
    return 200, fields


def send_boleto_payment_info(bill_id, linha_digitavel, payment_type_id=19, beneficiary_id=None):
    """Busca a primeira parcela do título e manda a linha digitável pro
    endpoint de informação de pagamento tipo boleto bancário. O identificador
    da parcela na URL é o installmentNumber. Campo confirmado na documentação:
    boletoBancarioManualBarCodeNumber (a versão digitada manualmente da linha
    digitável — existe também boletoBancarioBarCodeNumber, pro código de
    barras lido por leitor óptico, que não é o nosso caso). beneficiary_id
    é o boletoBancarioBeneficiaryId — usamos o mesmo creditorId já achado
    pelo CNPJ do beneficiário no PDF, já que é o mesmo credor."""
    status, data = call_sienge('GET', f'bills/{bill_id}/installments')
    if status < 200 or status >= 300:
        return status, {'step': 'buscar parcela', 'error': data}
    items = data.get('results') if isinstance(data, dict) else data
    if not items:
        return 404, {'step': 'buscar parcela', 'error': 'Nenhuma parcela encontrada para esse título.'}
    first = items[0]
    installment_id = first.get('id') or first.get('installmentId') or first.get('installmentNumber')
    if installment_id is None:
        return 404, {'step': 'buscar parcela', 'error': 'Parcela encontrada, mas sem ID identificável.', 'raw': first}

    linha_limpa = re.sub(r'\D', '', linha_digitavel)
    payment_body = {'boletoBancarioManualBarCodeNumber': linha_limpa}
    if payment_type_id is not None:
        payment_body['paymentTypeId'] = payment_type_id
    if beneficiary_id is not None:
        payment_body['boletoBancarioBeneficiaryId'] = beneficiary_id
    status2, data2 = call_sienge(
        'PATCH',
        f'bills/{bill_id}/installments/{installment_id}/payment-information/boleto-bancario',
        body=payment_body
    )
    return status2, {'step': 'enviar linha digitável', 'installmentId': installment_id, 'linhaEnviada': linha_limpa, 'response': data2}


# --------------------------------------------------------------------------
# Interface (servida localmente — mesma origem do backend, sem CORS)
# --------------------------------------------------------------------------

LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entrar — Extrator de Notas</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&family=Barlow:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
  :root{ --ink:#18160F; --paper:#FAF8F3; --panel:#FFFFFF; --line:#E7E2D5; --copper:#F2A400; --ink-soft:#6B6558; --red:#B23A3A; --red-dim:#F6E4E4; --green:#3F7D53; --green-dim:#E4EFE7; }
  *{box-sizing:border-box;}
  body{margin:0;background:var(--paper);font-family:'Barlow',sans-serif;color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:32px 28px;max-width:360px;width:100%;}
  .brand{display:flex;align-items:center;gap:10px;margin-bottom:22px;}
  .brand svg{width:32px;height:28px;}
  .brand .word{font-family:'Barlow Condensed',sans-serif;font-weight:700;font-size:20px;letter-spacing:.01em;text-transform:uppercase;}
  h1{font-family:'Barlow Condensed',sans-serif;font-weight:700;font-size:22px;margin:0 0 4px;}
  p.sub{color:var(--ink-soft);font-size:13px;margin:0 0 20px;}
  .field{margin-bottom:12px;}
  .field label{display:block;font-size:11.5px;color:var(--ink-soft);margin-bottom:4px;}
  .field input{width:100%;font-family:'JetBrains Mono',monospace;font-size:13px;padding:9px 10px;border:1px solid var(--line);border-radius:2px;background:#FCFBF8;color:var(--ink);}
  button{width:100%;font-family:'Barlow',sans-serif;font-size:14px;font-weight:600;padding:10px;border-radius:2px;border:1px solid var(--ink);background:var(--ink);color:#fff;cursor:pointer;margin-top:6px;}
  button.copper{background:var(--copper);border-color:var(--copper);color:#1A1200;}
  .switch{text-align:center;margin-top:16px;font-size:12.5px;color:var(--ink-soft);}
  .switch a{color:var(--ink);cursor:pointer;text-decoration:underline;}
  .msg{margin-top:14px;padding:10px 12px;border-radius:2px;font-size:12.5px;}
  .msg.bad{background:var(--red-dim);color:var(--red);border:1px solid var(--red);}
  .msg.ok{background:var(--green-dim);color:var(--green);border:1px solid var(--green);}
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <svg viewBox="0 0 120 100" xmlns="http://www.w3.org/2000/svg">
      <path d="M8 38 L45 78 L112 8" stroke="#18160F" stroke-width="24" fill="none" stroke-linecap="square"/>
      <rect x="36" y="0" width="32" height="32" fill="#F2A400" transform="rotate(45 52 16)"/>
    </svg>
    <div class="word">vex</div>
  </div>

  <div id="loginForm">
    <h1>Entrar</h1>
    <p class="sub">Acesse com seu usuário e senha aprovados.</p>
    <div class="field"><label>Usuário</label><input id="lUser" autocomplete="username"></div>
    <div class="field"><label>Senha</label><input id="lPass" type="password" autocomplete="current-password"></div>
    <button class="copper" onclick="doLogin()">Entrar</button>
    <div id="loginMsg"></div>
    <div class="switch">Ainda não tem conta? <a onclick="showRegister()">Solicitar acesso</a></div>
  </div>

  <div id="registerForm" style="display:none;">
    <h1>Solicitar acesso</h1>
    <p class="sub">Escolha um usuário e senha — um administrador precisa aprovar antes de você conseguir entrar.</p>
    <div class="field"><label>Usuário</label><input id="rUser" autocomplete="username"></div>
    <div class="field"><label>Senha</label><input id="rPass" type="password" autocomplete="new-password"></div>
    <button onclick="doRegister()">Solicitar acesso</button>
    <div id="registerMsg"></div>
    <div class="switch">Já tem conta? <a onclick="showLogin()">Entrar</a></div>
  </div>
</div>
<script>
function showRegister(){ document.getElementById('loginForm').style.display='none'; document.getElementById('registerForm').style.display='block'; }
function showLogin(){ document.getElementById('registerForm').style.display='none'; document.getElementById('loginForm').style.display='block'; }
function msg(id, type, text){ document.getElementById(id).innerHTML = `<div class="msg ${type}">${text}</div>`; }

async function doLogin(){
  const r = await fetch('/api/login', { method:'POST', body: JSON.stringify({ username:lUser.value, password:lPass.value }) });
  const data = await r.json();
  if(r.status === 200){ location.reload(); }
  else { msg('loginMsg','bad', data.error || 'Não foi possível entrar.'); }
}
async function doRegister(){
  const r = await fetch('/api/register', { method:'POST', body: JSON.stringify({ username:rUser.value, password:rPass.value }) });
  const data = await r.json();
  msg('registerMsg', data.ok ? 'ok' : 'bad', data.message);
  if(data.ok){ rUser.value=''; rPass.value=''; }
}
lPass?.addEventListener('keydown', e => { if(e.key === 'Enter') doLogin(); });
rPass?.addEventListener('keydown', e => { if(e.key === 'Enter') doRegister(); });
</script>
</body>
</html>
"""

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Extrator de Notas → Sienge</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&family=Barlow:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');
  :root{
    --paper:#FAF8F3; --panel:#FFFFFF; --ink:#18160F; --ink-soft:#6B6558;
    --line:#E7E2D5; --blue:#2E5C86; --blue-dim:#EAF1F7; --copper:#F2A400;
    --copper-dim:#FCEACB; --green:#3F7D53; --green-dim:#E4EFE7; --red:#B23A3A; --red-dim:#F6E4E4;
    --sidebar-w:230px;
  }
  *{box-sizing:border-box;}
  body{margin:0;background:var(--paper);font-family:'Barlow',sans-serif;color:var(--ink);}
  .app{display:flex;min-height:100vh;}

  .sidebar{
    width:var(--sidebar-w);flex:0 0 var(--sidebar-w);background:var(--ink);color:#EDEAE1;
    display:flex;flex-direction:column;padding:20px 14px;position:sticky;top:0;height:100vh;overflow-y:auto;
  }
  .brand{display:flex;align-items:center;gap:10px;padding:4px 6px 18px;margin-bottom:10px;border-bottom:1px solid rgba(255,255,255,.12);}
  .brand svg{width:30px;height:26px;flex:0 0 auto;}
  .brand .word{font-family:'Barlow Condensed',sans-serif;font-weight:700;font-size:18px;letter-spacing:.01em;line-height:1.1;color:#fff;text-transform:uppercase;}
  .brand .word small{display:block;font-family:'JetBrains Mono',monospace;font-weight:400;font-size:10px;letter-spacing:.03em;color:#B8B2A2;}

  nav{display:flex;flex-direction:column;gap:2px;flex:1;}
  .navgroup-label{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.06em;color:#8B8574;margin:16px 10px 4px;}
  .navitem{
    text-align:left;background:transparent;border:none;color:#D8D3C6;font-family:'Barlow',sans-serif;
    font-size:13.5px;font-weight:500;padding:9px 10px;border-radius:3px;cursor:pointer;margin:0;
  }
  .navitem:hover{background:rgba(255,255,255,.06);}
  .navitem.active{background:var(--copper);color:#1A1200;font-weight:600;}
  .sidebar-foot{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#8B8574;padding:14px 10px 4px;border-top:1px solid rgba(255,255,255,.12);margin-top:12px;}
  .sidebar-foot .dot{color:var(--green);}

  .content{flex:1;min-width:0;padding:34px 40px 100px;max-width:920px;}
  .view h2{font-family:'Barlow Condensed',sans-serif;font-weight:700;font-size:26px;letter-spacing:.01em;margin:0 0 4px;}
  .view > .sub{color:var(--ink-soft);font-size:13px;margin:0 0 20px;max-width:62ch;line-height:1.5;}

  .panel{background:var(--panel);border:1px solid var(--line);border-radius:3px;margin-bottom:20px;padding:16px;}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
  .field{display:flex;flex-direction:column;gap:4px;margin-bottom:10px;}
  .field label{font-size:11.5px;color:var(--ink-soft);}
  input,textarea,select{font-family:'JetBrains Mono',monospace;font-size:13px;padding:8px 10px;border:1px solid var(--line);border-radius:2px;background:#FCFBF8;color:var(--ink);width:100%;}
  textarea{min-height:140px;}
  button{font-family:'Barlow',sans-serif;font-size:13px;font-weight:600;padding:9px 16px;border-radius:2px;border:1px solid var(--ink);background:var(--ink);color:#fff;cursor:pointer;margin-right:8px;margin-top:6px;}
  button.secondary{background:var(--panel);color:var(--ink);}
  button.copper{background:var(--copper);border-color:var(--copper);color:#1A1200;}
  .msg{margin-top:10px;padding:10px 12px;border-radius:2px;font-size:12.5px;font-family:'JetBrains Mono',monospace;white-space:pre-wrap;}
  .msg.ok{background:var(--green-dim);color:var(--green);border:1px solid var(--green);}
  .msg.bad{background:var(--red-dim);color:var(--red);border:1px solid var(--red);}
  .msg.info{background:var(--blue-dim);color:var(--blue);border:1px solid var(--blue);}
  .row{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);font-size:12.5px;}
  .row:last-child{border-bottom:none;}
  .row .id{font-family:'JetBrains Mono',monospace;color:var(--blue);}

  .menubtn{display:none;}
  @media (max-width: 820px){
    .app{flex-direction:column;}
    .sidebar{
      width:100%;flex:0 0 auto;height:auto;position:sticky;top:0;z-index:20;
      flex-direction:row;align-items:center;padding:12px 14px;
    }
    .brand{border-bottom:none;padding:0;margin:0;flex:1;}
    nav{position:fixed;top:58px;left:0;right:0;bottom:0;background:var(--ink);flex-direction:column;
        padding:10px 14px 30px;overflow-y:auto;display:none;}
    nav.open{display:flex;}
    .menubtn{display:block;background:transparent;border:1px solid #55503F;color:#EDEAE1;padding:7px 10px;}
    .sidebar-foot{display:none;}
    .content{padding:22px 18px 80px;}
  }
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <svg viewBox="0 0 120 100" xmlns="http://www.w3.org/2000/svg">
        <path d="M8 38 L45 78 L112 8" stroke="#18160F" stroke-width="24" fill="none" stroke-linecap="square"/>
        <rect x="36" y="0" width="32" height="32" fill="#F2A400" transform="rotate(45 52 16)"/>
      </svg>
      <div class="word">vex<small>extrator de notas</small></div>
    </div>
    <button class="menubtn" onclick="document.getElementById('navlist').classList.toggle('open')">Menu ▾</button>
    <nav id="navlist">
      <button class="navitem active" id="nav-extrair" onclick="showView('extrair')">Nota → Sienge</button>
      <div class="navgroup-label">Cadastros</div>
      <button class="navitem" id="nav-credores" onclick="showView('credores')">Credores</button>
      <button class="navitem" id="nav-pagadores" onclick="showView('pagadores')">Pagadores</button>
      <div class="navgroup-label">Ferramentas</div>
      <button class="navitem" id="nav-historico" onclick="showView('historico')">Histórico</button>
      <button class="navitem" id="nav-anexo" onclick="showView('anexo')">Anexar avulso</button>
      <button class="navitem" id="nav-cfg" onclick="showView('cfg')" style="display:none;">Configuração</button>
      <button class="navitem" id="nav-admin" onclick="showView('admin')" style="display:none;">Administração</button>
    </nav>
    <button class="navitem" id="logoutBtn" onclick="doLogout()" style="display:none;margin-top:auto;border-top:1px solid rgba(255,255,255,.12);border-radius:0;padding-top:14px;">Sair</button>
  </aside>

  <main class="content">

    <section class="view" id="view-extrair">
      <h2>Nota → Sienge</h2>
      <p class="sub">Escolha um ou vários PDFs, extraia, confira/complete os campos, e clique em enviar — cria o título e anexa o mesmo PDF automaticamente. Selecionando vários, o programa processa um de cada vez e já carrega o próximo depois de cada envio. Precisa da chave de API preenchida em Configuração.</p>
      <div class="field"><label>Arquivo(s) PDF</label><input id="xFile" type="file" accept="application/pdf" multiple onchange="prepararFila()"></div>
      <div id="filaMsg"></div>
      <button onclick="extrairPdf()">Extrair dados</button>
      <div id="extrairMsg"></div>
      <div id="extrairFields" style="display:none;margin-top:12px;">
        <div style="display:flex;gap:6px;margin-bottom:12px;border-bottom:1px solid var(--line);">
          <button type="button" class="tabbtn" id="tabBtnDados" onclick="mostrarAba('dados')" style="border:none;border-bottom:2px solid var(--ink);background:transparent;color:var(--ink);font-weight:600;padding:8px 4px;margin:0;border-radius:0;">Dados</button>
          <button type="button" class="tabbtn" id="tabBtnImpostos" onclick="mostrarAba('impostos')" style="border:none;border-bottom:2px solid transparent;background:transparent;color:var(--ink-soft);font-weight:600;padding:8px 4px;margin:0;border-radius:0;">Impostos</button>
        </div>

        <div id="abaDados">
        <div class="grid">
          <div class="field"><label>Fornecedor</label><input id="xNome"></div>
          <div class="field"><label>CNPJ</label><input id="xCnpj"></div>
          <div class="field"><label>Tipo (identificado no PDF)</label><input id="xTipoExtraido" readonly style="background:#EFEDE6;color:var(--ink-soft);"></div>
          <div class="field"><label>Número do documento</label><input id="xNumero"></div>
          <div class="field"><label>Data de emissão</label><input id="xEmissao" placeholder="YYYY-MM-DD"></div>
          <div class="field"><label>Data de vencimento</label><input id="xVencimento" placeholder="YYYY-MM-DD"></div>
          <div class="field"><label>Valor total</label><input id="xValor"></div>
          <div class="field" style="grid-column:1/-1;"><label>Descrição</label><input id="xDescricao"></div>
          <div class="field" style="grid-column:1/-1;">
            <label>Anexo a enviar pro Sienge (opcional — se vazio, usa o mesmo PDF extraído acima)</label>
            <input id="xAttachFile" type="file" accept="application/pdf">
            <button type="button" class="secondary" style="margin-top:6px;font-size:11.5px;padding:4px 8px;" onclick="extrairLinhaDoAnexo()">Ler esse anexo e preencher linha digitável (só se for boleto)</button>
          </div>
          <div id="xAttachMsg" style="grid-column:1/-1;"></div>
          <div class="field" style="grid-column:1/-1;"><label>Linha digitável (só se for boleto)</label><input id="xLinhaDigitavel" placeholder="ex: 74891.12610 00363.908096 18400.971059 7 15550000020000"></div>
          <div class="field"><label>Pagador/Tomador (quem contratou)</label><input id="xPagadorNome"></div>
          <div class="field"><label>CNPJ do pagador</label><input id="xPagadorCnpj"></div>
        </div>
        <div id="xCredMsg"></div>
        <div id="xPagadorMsg"></div>
        <div class="grid" style="margin-top:10px;">
          <div class="field"><label>ID do credor (creditorId)</label><input id="xCreditorId"></div>
          <div class="field"><label>Centro de custo (costCenterId)</label><input id="xCostCenter" onchange="atualizarEmpresaCalculada()"></div>
          <div class="field">
            <label>Empresa (debtorId) <span style="font-weight:400;color:var(--ink-soft);">— calculado, pode ajustar</span></label>
            <input id="xDebtorId">
          </div>
          <div class="field"><label>Conta do plano financeiro</label><input id="xPaymentCat"></div>
          <div class="field"><label>Unidade construtiva (buildingUnitId — opcional)</label><input id="xBuildingUnit" placeholder="deixe em branco se não usar"></div>
          <div class="field"><label>Item do orçamento (costEstimationSheetId — opcional)</label><input id="xCostEstimationSheet" placeholder="deixe em branco se não usar"></div>
          <div class="field">
            <label>Tipo de documento (código no Sienge)</label>
            <input id="xDocType" value="NF">
            <button type="button" class="secondary" style="margin-top:6px;font-size:11.5px;padding:4px 8px;" onclick="verificarTipoDoc()">Verificar código no Sienge</button>
          </div>
        </div>
        <div id="xDocTypeMsg"></div>
        </div>

        <div id="abaImpostos" style="display:none;">
        <div class="group-label" style="font-size:11px;color:var(--ink-soft);margin-top:4px;margin-bottom:6px;">Impostos (opcional — deixe em branco os que não se aplicam)</div>
        <div class="grid">
          <div class="field"><label>Código IBGE do município</label><input id="xMunicipioIbge" placeholder="ex: 1600303"></div>
          <div class="field"><label>Base de cálculo dos impostos</label><input id="xBaseCalculo" placeholder="geralmente o valor do serviço"></div>
        </div>
        <div class="grid" style="margin-top:6px;">
          <div class="field"><label>Valor do ISS</label><input id="xIss" placeholder="ex: 8.50"></div>
          <div class="field"><label>Alíquota ISS (%)</label><input id="xIssAliquota" placeholder="ex: 4.25"></div>
          <div class="field"><label>ISS retido?</label>
            <select id="xIssRetido"><option value="">— não sei —</option><option value="sim">Sim</option><option value="nao">Não</option></select>
          </div>
        </div>
        <div class="grid" style="margin-top:6px;">
          <div class="field"><label>Valor IRRF retido</label><input id="xIrrf" placeholder="deixe em branco se não houver"></div>
          <div class="field"><label>Alíquota IRRF (%)</label><input id="xIrrfAliquota" placeholder="ex: 1.5"></div>
        </div>
        <div class="grid" style="margin-top:6px;">
          <div class="field"><label>Valor INSS retido</label><input id="xInss" placeholder="deixe em branco se não houver"></div>
          <div class="field"><label>Alíquota INSS (%)</label><input id="xInssAliquota" placeholder="ex: 11"></div>
        </div>
        <div class="grid" style="margin-top:6px;">
          <div class="field"><label>Valor PIS/COFINS/CSLL retido</label><input id="xPisCofinsCsll" placeholder="deixe em branco se não houver"></div>
          <div class="field"><label>Alíquota PIS/COFINS/CSLL (%)</label><input id="xPisCofinsCsllAliquota" placeholder="ex: 4.65"></div>
        </div>
        </div>

        <button class="secondary" onclick="toggleJsonPreview()" style="margin-top:10px;">Ver/editar payload JSON</button>
        <textarea id="payload" style="display:none;margin-top:8px;"></textarea>
        <button class="copper" onclick="enviarTitulo()" style="margin-top:10px;">Enviar para o Sienge (e anexar o PDF)</button>
        <div id="envioMsg"></div>
      </div>
    </section>

    <section class="view" id="view-credores" style="display:none;">
      <h2>Credores memorizados</h2>
      <p class="sub">Relação entre o CNPJ do fornecedor e o credor correspondente no Sienge.</p>
      <div class="panel"><div id="credList"></div></div>
    </section>

    <section class="view" id="view-pagadores" style="display:none;">
      <h2>Pagadores memorizados</h2>
      <p class="sub">Centro de custo, plano financeiro, unidade construtiva e item do orçamento dependem de quem está sendo pago (o Tomador da nota), não do fornecedor — já que o mesmo fornecedor pode atender obras diferentes.</p>
      <div class="panel"><div id="pagadorList"></div></div>
    </section>

    <section class="view" id="view-historico" style="display:none;">
      <h2>Histórico de lançamentos</h2>
      <p class="sub">Últimos títulos lançados por aqui — usado pra sugerir campos em notas com descrição parecida, mesmo de fornecedores diferentes.</p>
      <div class="panel"><div id="historyList"></div></div>
    </section>

    <section class="view" id="view-cfg" style="display:none;">
      <h2>Configuração</h2>
      <p class="sub">Credenciais e endpoints do Sienge, chave de IA e códigos de imposto.</p>
      <div class="panel">
        <div class="grid">
          <div class="field"><label>Subdomínio (tenant)</label><input id="cSub"></div>
          <div class="field"><label>Usuário de API</label><input id="cUser"></div>
          <div class="field"><label>Senha de API</label><input id="cPass" type="password"></div>
          <div class="field"><label>Endpoint de títulos</label><input id="cEndpoint"></div>
          <div class="field"><label>Endpoint de centros de custo</label><input id="cCC"></div>
          <div class="field"><label>Endpoint de empresas</label><input id="cComp"></div>
          <div class="field" style="grid-column:1/-1;"><label>Chave de API da Anthropic (opcional — habilita extrair PDF aqui dentro)</label><input id="cApiKey" type="password" placeholder="sk-ant-..."></div>
          <div class="field"><label>Código do imposto ISS (taxId)</label><input id="cIssTaxId" placeholder='ex: "ISS" (confirme — ainda não testado)'></div>
          <div class="field"><label>Código do imposto INSS (taxId)</label><input id="cInssTaxId" placeholder='ex: "INSS" (confirme — ainda não testado)'></div>
          <p style="grid-column:1/-1;font-size:11.5px;color:var(--ink-soft);margin:0;">IRRF (código "IR") e PIS/COFINS/CSLL (código "PIS/CSLL") já vêm fixos no programa — não precisa preencher.</p>
        </div>
        <button onclick="saveConfig()">Salvar configuração</button>
        <div id="cfgMsg"></div>
      </div>
    </section>

    <section class="view" id="view-anexo" style="display:none;">
      <h2>Anexar PDF a um título já existente</h2>
      <p class="sub">Use isso só se precisar anexar um arquivo depois, num título que já foi criado antes (o fluxo normal de "Nota → Sienge" já anexa sozinho).</p>
      <div class="panel">
        <div class="field"><label>ID do título (billId)</label><input id="aBillId2" placeholder="ex: 4521"></div>
        <div class="field"><label>Descrição do anexo</label><input id="aDesc2" placeholder="ex: NFS-e 1060 + boleto"></div>
        <div class="field"><label>Arquivo PDF</label><input id="aFile2" type="file" accept="application/pdf"></div>
        <button class="secondary" onclick="anexarPdfAvulso()">Enviar anexo</button>
        <div id="anexoMsg2"></div>
      </div>
    </section>

    <section class="view" id="view-admin" style="display:none;">
      <h2>Administração</h2>
      <p class="sub">Aprove, recuse ou remova o acesso de cada pessoa que solicitou entrar.</p>
      <div class="panel"><div id="usersList"></div></div>
    </section>

  </main>
</div>

<script>
function showView(name){
  document.querySelectorAll('.view').forEach(v => v.style.display = 'none');
  document.getElementById('view-' + name).style.display = 'block';
  document.querySelectorAll('.navitem').forEach(b => b.classList.remove('active'));
  document.getElementById('nav-' + name).classList.add('active');
  const nl = document.getElementById('navlist');
  if(nl.classList.contains('open')) nl.classList.remove('open');
}
function mostrarAba(nome){
  const abas = { dados: 'abaDados', impostos: 'abaImpostos' };
  Object.entries(abas).forEach(([key, elId]) => {
    document.getElementById(elId).style.display = (key === nome) ? 'block' : 'none';
    const btn = document.getElementById('tabBtn' + key.charAt(0).toUpperCase() + key.slice(1));
    btn.style.borderBottomColor = (key === nome) ? 'var(--ink)' : 'transparent';
    btn.style.color = (key === nome) ? 'var(--ink)' : 'var(--ink-soft)';
  });
}
function showMsg(elId, type, text){
  document.getElementById(elId).innerHTML = `<div class="msg ${type}">${escapeHtml(text)}</div>`;
}
function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }

let currentConfig = {};

async function loadConfig(){
  const r = await fetch('/api/config'); const c = await r.json();
  currentConfig = c;
  cSub.value = c.sub || ''; cUser.value = c.user || ''; cPass.value = c.pass || '';
  cEndpoint.value = c.endpoint || 'bills'; cCC.value = c.costCenterEndpoint || 'cost-centers';
  cComp.value = c.companyEndpoint || 'companies';
  cApiKey.value = c.anthropicApiKey || '';
  cIssTaxId.value = c.issTaxId || ''; cInssTaxId.value = c.inssTaxId || '';
}
async function saveConfig(){
  const body = { sub:cSub.value.trim(), user:cUser.value, pass:cPass.value,
    endpoint:cEndpoint.value.trim()||'bills', costCenterEndpoint:cCC.value.trim()||'cost-centers',
    companyEndpoint:cComp.value.trim()||'companies', anthropicApiKey:cApiKey.value.trim(),
    issTaxId:cIssTaxId.value.trim(), inssTaxId:cInssTaxId.value.trim() };
  currentConfig = body;
  await fetch('/api/config', {method:'POST', body: JSON.stringify(body)});
  showMsg('cfgMsg','ok','Configuração salva neste computador.');
}


async function learn(cnpj, creditorId, name){
  const r = await fetch('/api/creditor-map'); const map = await r.json();
  const prev = map[cnpj] || {};
  map[cnpj] = {
    creditorId: String(creditorId),
    name: name || prev.name || ''
  };
  await fetch('/api/creditor-map', { method:'POST', body: JSON.stringify(map) });
  renderCredList();
}

async function learnPagador(cnpjPagador, nomePagador){
  if(!cnpjPagador) return;
  const r = await fetch('/api/pagador-map'); const map = await r.json();
  const prev = map[cnpjPagador] || {};
  map[cnpjPagador] = {
    nome: nomePagador || prev.nome || '',
    costCenterId: xCostCenter.value.trim() || prev.costCenterId || '',
    paymentCategoriesId: xPaymentCat.value.trim() || prev.paymentCategoriesId || '',
    buildingUnitId: xBuildingUnit.value.trim() || prev.buildingUnitId || '',
    costEstimationSheetId: xCostEstimationSheet.value.trim() || prev.costEstimationSheetId || ''
  };
  await fetch('/api/pagador-map', { method:'POST', body: JSON.stringify(map) });
  renderPagadorList();
  renderCredList();
}
async function renderCredList(){
  const r = await fetch('/api/creditor-map'); const map = await r.json();
  const entries = Object.entries(map);
  document.getElementById('credList').innerHTML = entries.length
    ? entries.map(([cnpj,v]) => `<div class="row"><span>${escapeHtml(cnpj)}</span><span>${escapeHtml(v.name||'')}</span><span class="id">ID ${escapeHtml(v.creditorId)}</span></div>`).join('')
    : '<p>Nenhum credor memorizado ainda.</p>';
}

async function renderPagadorList(){
  const r = await fetch('/api/pagador-map'); const map = await r.json();
  const entries = Object.entries(map);
  document.getElementById('pagadorList').innerHTML = entries.length
    ? entries.map(([cnpj,v]) => `<div class="row" style="flex-direction:column;align-items:flex-start;">
        <span><b>${escapeHtml(v.nome||'')}</b> — ${escapeHtml(cnpj)}</span>
        <span class="id">CC ${escapeHtml(v.costCenterId||'—')} · plano ${escapeHtml(v.paymentCategoriesId||'—')} · unidade ${escapeHtml(v.buildingUnitId||'—')} · item orç. ${escapeHtml(v.costEstimationSheetId||'—')}</span>
      </div>`).join('')
    : '<p>Nenhum pagador memorizado ainda.</p>';
}

async function renderHistoryList(){
  const r = await fetch('/api/history'); const history = await r.json();
  const recent = history.slice(-15).reverse();
  document.getElementById('historyList').innerHTML = recent.length
    ? recent.map(h => `<div class="row" style="flex-direction:column;align-items:flex-start;">
        <span><b>${escapeHtml(h.fornecedor||'')}</b> — doc ${escapeHtml(h.documentNumber||'')} — R$ ${escapeHtml(h.valor||'')}</span>
        <span style="font-size:11px;color:var(--ink-soft);">${escapeHtml(h.descricao||'')}</span>
        <span class="id">CC ${escapeHtml(h.costCenterId||'—')} · plano ${escapeHtml(h.paymentCategoriesId||'—')} · billId ${escapeHtml(h.billId||'—')}</span>
      </div>`).join('')
    : '<p>Nenhum título lançado ainda por aqui.</p>';
}

function fileToBase64(file){
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result.split(',')[1]);
    r.onerror = () => reject(new Error('Falha ao ler o arquivo'));
    r.readAsDataURL(file);
  });
}

async function enviarAnexo(billId, description, file){
  const fileBase64 = await fileToBase64(file);
  const r = await fetch('/api/attach', {
    method:'POST',
    body: JSON.stringify({ billId, description, filename: file.name, fileBase64 })
  });
  const data = await r.json();
  return { ok: r.status >= 200 && r.status < 300, status: r.status, data };
}

// Códigos de imposto confirmados via consulta ao título 295957 do Sienge —
// fixos aqui, não precisam ser preenchidos na Configuração.
const FIXED_TAX_IDS = {
  irrfTaxId: 'IR',
  pisCofinsCsllTaxId: 'PIS/CSLL'
};

function buildTaxes(){
  const ibge = xMunicipioIbge.value.trim();
  const baseCalculo = xBaseCalculo.value.trim() || xValor.value.trim();
  const taxes = [];
  const addTax = (taxIdConfig, valorCampo, aliquotaCampo, label) => {
    const taxId = (FIXED_TAX_IDS[taxIdConfig] || currentConfig[taxIdConfig] || '').trim();
    const valor = valorCampo.value.trim();
    if(!valor) return; // sem valor extraído/preenchido, não lança esse imposto
    if(!taxId){
      taxes.push({ _missingConfig: label }); // marcador pra avisar na hora de enviar
      return;
    }
    if(!ibge){
      taxes.push({ _missingConfig: label + ' (falta o código IBGE do município)' });
      return;
    }
    taxes.push({
      taxId: taxId,
      ibgeCityId: ibge,
      rate: aliquotaCampo.value.trim() ? Number(aliquotaCampo.value.trim()) : 0,
      amount: Number(valor),
      taxableBaseAmount: baseCalculo ? Number(baseCalculo) : Number(valor),
      taxRateMarker: 100,
      usesIncomeTaxTable: false
    });
  };
  addTax('issTaxId', xIss, xIssAliquota, 'ISS');
  addTax('irrfTaxId', xIrrf, xIrrfAliquota, 'IRRF');
  addTax('inssTaxId', xInss, xInssAliquota, 'INSS');
  addTax('pisCofinsCsllTaxId', xPisCofinsCsll, xPisCofinsCsllAliquota, 'PIS/COFINS/CSLL');
  return taxes;
}

function buildPayloadFromFields(){
  const costCenterId = xCostCenter.value.trim();
  const debtorId = xDebtorId.value.trim();
  const taxes = buildTaxes().filter(t => !t._missingConfig);
  return {
    debtorId: debtorId ? Number(debtorId) : null,
    creditorId: xCreditorId.value ? Number(xCreditorId.value) : null,
    documentIdentificationId: xDocType.value.trim() || 'NF',
    documentNumber: xNumero.value.trim() || null,
    issueDate: xEmissao.value.trim() || null,
    installmentsNumber: 1,
    indexId: 0,
    baseDate: xEmissao.value.trim() || null,
    dueDate: xVencimento.value.trim() || xEmissao.value.trim() || null,
    billDate: xEmissao.value.trim() || null,
    totalInvoiceAmount: xValor.value === '' ? null : Number(xValor.value),
    discount: 0,
    notes: xDescricao.value.trim() || null,
    budgetCategories: (costCenterId && xPaymentCat.value.trim()) ? [{
      costCenterId: Number(costCenterId),
      paymentCategoriesId: xPaymentCat.value.trim().replace(/\./g,''),
      percentage: 100
    }] : [],
    // O Sienge exige buildingUnitId sempre que se manda apropriação de obra —
    // então só incluímos o bloco inteiro quando a unidade estiver preenchida
    // (nem todo título precisa de apropriação de obra).
    buildingsCost: (costCenterId && xBuildingUnit.value.trim()) ? [{
      buildingId: Number(costCenterId),
      buildingUnitId: Number(xBuildingUnit.value.trim()),
      percentage: 100,
      ...(xCostEstimationSheet.value.trim() ? { costEstimationSheetId: xCostEstimationSheet.value.trim() } : {})
    }] : [],
    taxes: taxes
  };
}

function atualizarEmpresaCalculada(){
  const digits = xCostCenter.value.trim().replace(/\D/g,'');
  xDebtorId.value = digits.length >= 2 ? digits.slice(0,2) : '';
}

function toggleJsonPreview(){
  const box = document.getElementById('payload');
  const showing = box.style.display !== 'none';
  if(showing){
    box.style.display = 'none';
  } else {
    if(!box.value.trim()){
      box.value = JSON.stringify(buildPayloadFromFields(), null, 2);
    }
    box.style.display = 'block';
  }
}

async function enviarTitulo(){
  const jsonBox = document.getElementById('payload');
  const usingManualJson = jsonBox.style.display !== 'none' && jsonBox.value.trim();
  let body;
  if(usingManualJson){
    try{ body = JSON.parse(jsonBox.value); }
    catch(e){ showMsg('envioMsg','bad','JSON inválido: ' + e.message); return; }
  } else {
    const missingTaxes = buildTaxes().filter(t => t._missingConfig).map(t => t._missingConfig);
    if(missingTaxes.length){
      showMsg('envioMsg','bad','Tem valor de ' + missingTaxes.join(', ') + ' preenchido, mas falta o código (taxId) na Configuração — preencha lá antes de enviar, ou apague o valor desse imposto se não for pra lançar.');
      return;
    }
    body = buildPayloadFromFields();
  }

  const extractionFile = currentQueueFile || document.getElementById('xFile').files[0];
  const attachFile = document.getElementById('xAttachFile').files[0];
  const filesToSend = [];
  if(extractionFile) filesToSend.push({ file: extractionFile, label: 'documento usado na extração' });
  if(attachFile && (!extractionFile || attachFile.name !== extractionFile.name || attachFile.size !== extractionFile.size)){
    filesToSend.push({ file: attachFile, label: 'anexo adicional' });
  }
  const linhaDigitavel = xLinhaDigitavel.value.trim();
  const description = xDescricao.value.trim() ||
    (body.documentNumber ? ('Documento ' + body.documentNumber) : 'Nota/boleto');

  showMsg('envioMsg','info','Enviando título...');
  const r = await fetch('/api/config'); const c = await r.json();
  const r2 = await fetch('/api/sienge/' + c.endpoint, { method:'POST', body: JSON.stringify(body) });
  const data = await r2.json();

  if(r2.status < 200 || r2.status >= 300){
    showMsg('envioMsg','bad','Sienge respondeu ' + r2.status + ': ' + JSON.stringify(data).slice(0,400));
    return;
  }

  const billId = data.id ?? data.billId ?? data.number ?? data.codigo ?? null;
  if(billId === null){
    showMsg('envioMsg','bad','Título criado, mas não consegui identificar o ID dele na resposta do Sienge — confira o campo certo abaixo e use no painel de anexo manual.\n\nResposta completa: ' + JSON.stringify(data));
    return;
  }

  // Deu certo — memoriza o credor pelo CNPJ do fornecedor, e a apropriação
  // (centro de custo, plano financeiro, obra) pelo CNPJ do pagador.
  const cnpjLimpo = xCnpj.value.replace(/\D/g,'');
  if(cnpjLimpo && xCreditorId.value){
    await learn(cnpjLimpo, xCreditorId.value, xNome.value.trim());
  }
  const pagadorCnpjLimpo = xPagadorCnpj.value.replace(/\D/g,'');
  if(pagadorCnpjLimpo){
    await learnPagador(pagadorCnpjLimpo, xPagadorNome.value.trim());
  }

  // Guarda no histórico geral, pra poder sugerir em notas parecidas de
  // outros fornecedores/pagadores no futuro.
  await fetch('/api/history', { method:'POST', body: JSON.stringify({
    timestamp: new Date().toISOString(),
    billId, cnpj: cnpjLimpo, fornecedor: xNome.value.trim(),
    pagadorCnpj: pagadorCnpjLimpo, pagadorNome: xPagadorNome.value.trim(),
    descricao: xDescricao.value.trim(), documentNumber: xNumero.value.trim(),
    valor: xValor.value, creditorId: xCreditorId.value,
    costCenterId: xCostCenter.value.trim(), paymentCategoriesId: xPaymentCat.value.trim(),
    buildingUnitId: xBuildingUnit.value.trim(), costEstimationSheetId: xCostEstimationSheet.value.trim(),
    documentIdentificationId: xDocType.value.trim()
  })});
  renderHistoryList();

  const summary = ['Título criado com sucesso (ID ' + billId + ')!'];
  let hadError = false;

  if(filesToSend.length){
    for(const item of filesToSend){
      showMsg('envioMsg','info','Título criado (ID ' + billId + ')! Anexando ' + item.label + '...');
      try{
        const anexo = await enviarAnexo(billId, description + ' (' + item.label + ')', item.file);
        if(anexo.ok){
          summary.push('Anexado: ' + item.file.name + '.');
        } else {
          hadError = true;
          summary.push('Falha ao anexar ' + item.file.name + ' — Sienge respondeu ' + anexo.status + ': ' + JSON.stringify(anexo.data).slice(0,300) + ' (tente de novo no painel "Anexar PDF a um título já existente", ID ' + billId + ').');
        }
      }catch(e){
        hadError = true;
        summary.push('Erro ao anexar ' + item.file.name + ': ' + e.message);
      }
    }
  } else {
    summary.push('Nenhum PDF selecionado, então não anexei nada.');
  }

  if(linhaDigitavel){
    showMsg('envioMsg','info', summary.join(' ') + '\n\nEnviando a linha digitável do boleto...');
    try{
      const beneficiaryId = xCreditorId.value ? Number(xCreditorId.value) : null;
      const r3 = await fetch('/api/boleto-payment', { method:'POST', body: JSON.stringify({ billId, linhaDigitavel, beneficiaryId }) });
      const t3 = await r3.text();
      let d3; try{ d3 = JSON.parse(t3); }catch(e){ d3 = { raw: t3 }; }
      if(r3.status >= 200 && r3.status < 300){
        summary.push('Linha digitável enviada com sucesso.');
      } else {
        hadError = true;
        summary.push('Falha ao enviar a linha digitável (' + (d3.step||'') + '): ' + JSON.stringify(d3).slice(0,300));
      }
    }catch(e){
      hadError = true;
      summary.push('Erro ao enviar a linha digitável: ' + e.message);
    }
  }

  showMsg('envioMsg', hadError ? 'bad' : 'ok', summary.join('\n'));

  // Se veio de uma fila com mais documentos, avança sozinho pro próximo
  // depois de um envio sem erro — sem precisar escolher o arquivo de novo.
  if(!hadError && queue.length > 1 && queueIndex < queue.length - 1){
    setTimeout(avancarFila, 1200);
  }
}

async function anexarPdfAvulso(){
  const billId = aBillId2.value.trim();
  const description = aDesc2.value.trim();
  const file = document.getElementById('aFile2').files[0];
  if(!billId){ showMsg('anexoMsg2','bad','Preencha o ID do título.'); return; }
  if(!file){ showMsg('anexoMsg2','bad','Escolha um arquivo PDF.'); return; }
  showMsg('anexoMsg2','info','Enviando anexo...');
  try{
    const anexo = await enviarAnexo(billId, description, file);
    if(anexo.ok){
      showMsg('anexoMsg2','ok','Anexo enviado com sucesso! Resposta: ' + JSON.stringify(anexo.data).slice(0,300));
    } else {
      showMsg('anexoMsg2','bad','Sienge respondeu ' + anexo.status + ': ' + JSON.stringify(anexo.data).slice(0,400));
    }
  }catch(e){
    showMsg('anexoMsg2','bad','Erro ao ler ou enviar o arquivo: ' + e.message);
  }
}

let extractedCache = { cnpj: '', costCenterName: '' };
let queue = [];
let queueIndex = 0;
let currentQueueFile = null;
let queueCache = {}; // index -> Promise<{ok,status,data}>, pra ler o próximo em segundo plano

function runExtraction(file){
  return (async () => {
    try{
      const fileBase64 = await fileToBase64(file);
      const r = await fetch('/api/extract', { method:'POST', body: JSON.stringify({ filename:file.name, fileBase64 }) });
      const data = await r.json();
      return { ok: r.status >= 200 && r.status < 300, status: r.status, data };
    }catch(e){
      return { ok:false, status:0, data:{ error: e.message } };
    }
  })();
}

function startExtraction(index){
  if(index < 0 || index >= queue.length) return null;
  if(!queueCache[index]) queueCache[index] = runExtraction(queue[index]);
  return queueCache[index];
}

function prepararFila(){
  const files = Array.from(document.getElementById('xFile').files);
  queue = files;
  queueIndex = 0;
  queueCache = {};
  renderFilaStatus();
  if(queue.length){
    startExtraction(0); // já começa a ler o primeiro assim que os arquivos são escolhidos
  }
}

function renderFilaStatus(){
  const el = document.getElementById('filaMsg');
  if(queue.length <= 1){ el.innerHTML = ''; return; }
  const items = queue.map((f, i) => {
    const marker = i < queueIndex ? '✓' : (i === queueIndex ? '▸' : (queueCache[i] ? '⋯' : '·'));
    return `${marker} ${escapeHtml(f.name)}`;
  }).join('<br>');
  el.innerHTML = `<div class="msg info">Fila (${queueIndex+1} de ${queue.length}) — ⋯ = já sendo lido em segundo plano:<br>${items}</div>`;
}

async function avancarFila(){
  queueIndex++;
  renderFilaStatus();
  if(queueIndex < queue.length){
    await extrairPdf(queue[queueIndex]);
  } else {
    showMsg('envioMsg', 'ok', document.getElementById('envioMsg').textContent + '\n\nFila concluída — todos os documentos foram processados.');
  }
}


async function extrairLinhaDoAnexo(){
  const file = document.getElementById('xAttachFile').files[0];
  if(!file){ showMsg('xAttachMsg','bad','Escolha um arquivo no campo de anexo primeiro.'); return; }
  showMsg('xAttachMsg','info','Lendo o anexo...');
  try{
    const fileBase64 = await fileToBase64(file);
    const r = await fetch('/api/extract', { method:'POST', body: JSON.stringify({ filename:file.name, fileBase64 }) });
    const data = await r.json();
    if(r.status < 200 || r.status >= 300){
      showMsg('xAttachMsg','bad','Erro ao ler o anexo: ' + JSON.stringify(data).slice(0,300));
      return;
    }
    const tipo = (data.tipo_documento || '').toLowerCase();
    if(tipo.includes('boleto')){
      xLinhaDigitavel.value = data.linha_digitavel || '';
      showMsg('xAttachMsg','ok','Esse anexo é um boleto — linha digitável preenchida.' + (!data.linha_digitavel ? ' (não consegui identificar o número, confira manualmente)' : ''));
    } else {
      showMsg('xAttachMsg','info','Esse anexo não parece ser um boleto (identifiquei como "' + (data.tipo_documento||'desconhecido') + '") — não preenchi a linha digitável.');
    }
  }catch(e){
    showMsg('xAttachMsg','bad','Erro ao ler o anexo: ' + e.message);
  }
}

async function extrairPdf(fileOverride){
  const file = fileOverride || document.getElementById('xFile').files[0];
  if(!file){ showMsg('extrairMsg','bad','Escolha um arquivo PDF.'); return; }
  currentQueueFile = file;
  const idx = queue.indexOf(file);
  showMsg('extrairMsg','info','Lendo o PDF com a IA... (pode levar alguns segundos)' + (queue.length > 1 ? ` — documento ${queueIndex+1} de ${queue.length}` : ''));
  document.getElementById('extrairFields').style.display = 'none';
  document.getElementById('payload').style.display = 'none';
  document.getElementById('payload').value = '';
  document.getElementById('xAttachFile').value = '';
  mostrarAba('dados');
  document.getElementById('xAttachMsg').innerHTML = '';
  try{
    // Já dispara a leitura do PRÓXIMO da fila em paralelo, sem esperar o
    // atual terminar — assim, quando você acabar de revisar este, o próximo
    // já está pronto ou quase.
    if(idx >= 0 && idx + 1 < queue.length){ startExtraction(idx + 1); renderFilaStatus(); }

    // Se esse arquivo já estava sendo lido em segundo plano (fila), só espera
    // terminar em vez de começar tudo de novo do zero.
    const result = idx >= 0 ? await startExtraction(idx) : await runExtraction(file);
    if(!result.ok){
      showMsg('extrairMsg','bad','Erro na extração: ' + JSON.stringify(result.data).slice(0,400));
      return;
    }
    const data = result.data;
    xNome.value = data.fornecedor_nome || '';
    xCnpj.value = data.fornecedor_cnpj || '';
    xTipoExtraido.value = data.tipo_documento || '';
    xNumero.value = data.numero_documento || '';
    xEmissao.value = data.data_emissao || '';
    xVencimento.value = data.data_vencimento || '';
    xValor.value = data.valor_total ?? '';
    xDescricao.value = data.descricao || '';
    xLinhaDigitavel.value = data.linha_digitavel || '';
    xPagadorNome.value = data.pagador_nome || '';
    xPagadorCnpj.value = data.pagador_cnpj || '';
    xIss.value = data.iss_valor ?? '';
    xIssAliquota.value = data.iss_aliquota ?? '';
    xIssRetido.value = data.iss_retido === true ? 'sim' : (data.iss_retido === false ? 'nao' : '');
    xIrrf.value = data.irrf_valor ?? '';
    xIrrfAliquota.value = data.irrf_aliquota ?? '';
    xInss.value = data.inss_valor ?? '';
    xInssAliquota.value = data.inss_aliquota ?? '';
    xPisCofinsCsll.value = data.pis_cofins_csll_valor ?? '';
    xPisCofinsCsllAliquota.value = data.pis_cofins_csll_aliquota ?? '';
    xMunicipioIbge.value = data.municipio_ibge || '';
    xBaseCalculo.value = data.base_calculo ?? data.valor_total ?? '';
    extractedCache.cnpj = data.fornecedor_cnpj || '';
    document.getElementById('extrairFields').style.display = 'block';
    showMsg('extrairMsg','ok','Extraído! Confira os campos abaixo e clique em enviar quando estiver tudo certo.');

    // Credor (quem recebe o pagamento) — memorizado pelo CNPJ do fornecedor
    const cr = await fetch('/api/creditor-map'); const map = await cr.json();
    const known = map[(data.fornecedor_cnpj||'').replace(/\D/g,'')];
    if(known){
      xCreditorId.value = known.creditorId || '';
      showMsg('xCredMsg','ok','Credor já memorizado: ' + (known.name||'') + ' (ID ' + known.creditorId + ')');
    } else if(data.fornecedor_cnpj){
      await buscarCredorExtracao();
    }

    // Apropriação (centro de custo, plano financeiro, obra) — memorizada pelo
    // CNPJ do PAGADOR, não do fornecedor, já que o mesmo fornecedor pode
    // atender obras/empresas diferentes.
    const pagadorCnpjLimpo = (data.pagador_cnpj||'').replace(/\D/g,'');
    const pr = await fetch('/api/pagador-map'); const pagadorMap = await pr.json();
    const knownPagador = pagadorMap[pagadorCnpjLimpo];
    if(knownPagador){
      if(knownPagador.costCenterId) xCostCenter.value = knownPagador.costCenterId;
      if(knownPagador.paymentCategoriesId) xPaymentCat.value = knownPagador.paymentCategoriesId;
      if(knownPagador.buildingUnitId) xBuildingUnit.value = knownPagador.buildingUnitId;
      if(knownPagador.costEstimationSheetId) xCostEstimationSheet.value = knownPagador.costEstimationSheetId;
      showMsg('xPagadorMsg','ok','Apropriação já memorizada pra "' + (knownPagador.nome||data.pagador_nome||'') + '" — centro de custo ' + (knownPagador.costCenterId||'—') + '.');
    } else if(data.descricao){
      // Pagador novo — procura lançamentos anteriores com descrição
      // parecida (mesmo de outros pagadores) e sugere, deixando claro que
      // é sugestão pra revisar, não aplicação automática.
      const sr = await fetch('/api/similar-history', { method:'POST', body: JSON.stringify({ descricao: data.descricao, excludeCnpj: pagadorCnpjLimpo }) });
      const similares = await sr.json();
      if(similares && similares.length){
        const s = similares[0];
        if(s.costCenterId) xCostCenter.value = s.costCenterId;
        if(s.paymentCategoriesId) xPaymentCat.value = s.paymentCategoriesId;
        if(s.buildingUnitId) xBuildingUnit.value = s.buildingUnitId;
        if(s.costEstimationSheetId) xCostEstimationSheet.value = s.costEstimationSheetId;
        showMsg('xPagadorMsg','info','Sugestão baseada em lançamento parecido (centro de custo ' + (s.costCenterId||'—') + ') — confira antes de enviar.');
      }
    }

    // Aplica o código de tipo de documento memorizado, se já soubermos esse tipo
    if(data.tipo_documento){
      const dt = await fetch('/api/doctype-map'); const docMap = await dt.json();
      const key = data.tipo_documento.trim().toLowerCase();
      if(docMap[key]){
        xDocType.value = docMap[key];
        showMsg('xDocTypeMsg','ok','Código memorizado pra "' + data.tipo_documento + '": ' + docMap[key]);
      } else {
        showMsg('xDocTypeMsg','info','Não tenho o código do Sienge pra "' + data.tipo_documento + '" ainda — confira/preencha e clique em "Verificar código no Sienge" pra eu memorizar.');
      }
    }
    atualizarEmpresaCalculada();
  }catch(e){
    showMsg('extrairMsg','bad','Erro ao extrair: ' + e.message);
  }
}

async function buscarCredorExtracao(){
  const cnpj = xCnpj.value.replace(/\D/g,'');
  if(!cnpj){ showMsg('xCredMsg','bad','Sem CNPJ pra buscar.'); return; }
  showMsg('xCredMsg','info','Buscando credor no Sienge...');
  const r = await fetch('/api/sienge/creditors?cnpj=' + cnpj);
  const data = await r.json();
  const items = data.results || (Array.isArray(data) ? data : []);
  const match = items.find(it => (it.cpfCnpj||it.cnpj||'').replace(/\D/g,'') === cnpj);
  if(!match){ showMsg('xCredMsg','bad','Não encontrei credor com esse CNPJ — preencha o ID manualmente abaixo.'); return; }
  xCreditorId.value = match.id || match.creditorId;
  showMsg('xCredMsg','ok','Credor encontrado: ' + (match.name||'') + ' (ID ' + xCreditorId.value + ')');
  await learn(cnpj, xCreditorId.value, match.name || '');
}

async function verificarTipoDoc(){
  const codigo = xDocType.value.trim();
  if(!codigo){ showMsg('xDocTypeMsg','bad','Preencha um código pra verificar.'); return; }
  showMsg('xDocTypeMsg','info','Verificando no Sienge...');
  const r = await fetch('/api/sienge/document-identifications/' + encodeURIComponent(codigo));
  const data = await r.json();
  if(r.status < 200 || r.status >= 300){
    showMsg('xDocTypeMsg','bad','Esse código não existe no Sienge — Sienge respondeu ' + r.status + ': ' + JSON.stringify(data).slice(0,300));
    return;
  }
  showMsg('xDocTypeMsg','ok','Código confirmado: ' + (data.name || codigo) + ' (' + codigo + ').');
  // memoriza a relação tipo extraído -> código, pra próxima vez preencher sozinho
  const tipoExtraido = xTipoExtraido.value.trim();
  if(tipoExtraido){
    const dt = await fetch('/api/doctype-map'); const docMap = await dt.json();
    docMap[tipoExtraido.toLowerCase()] = codigo;
    await fetch('/api/doctype-map', { method:'POST', body: JSON.stringify(docMap) });
  }
}

async function doLogout(){
  await fetch('/api/logout', { method:'POST', body: '{}' });
  location.reload();
}

async function checkMe(){
  try{
    const r = await fetch('/api/me');
    if(r.status !== 200) return;
    const me = await r.json();
    if(me.username !== 'local'){
      document.getElementById('logoutBtn').style.display = 'block';
    }
    if(me.isAdmin){
      document.getElementById('nav-admin').style.display = 'block';
      document.getElementById('nav-cfg').style.display = 'block';
      renderUsersList();
    }
  }catch(e){ /* segue sem admin */ }
}

async function renderUsersList(){
  const r = await fetch('/api/users');
  if(r.status !== 200) return;
  const users = await r.json();
  const entries = Object.entries(users);
  document.getElementById('usersList').innerHTML = entries.length ? entries.map(([username, u]) => `
    <div class="row" style="flex-direction:column;align-items:flex-start;">
      <span style="width:100%;display:flex;justify-content:space-between;align-items:center;">
        <b>${escapeHtml(username)}</b>
        <span class="id">${u.approved ? (u.isAdmin ? 'admin' : 'aprovado') : 'pendente'}</span>
      </span>
      <div style="margin-top:6px;">
        ${!u.approved ? `<button onclick="userAction('approve','${escapeHtml(username)}')">Aprovar</button>
                          <button class="secondary" onclick="userAction('reject','${escapeHtml(username)}')">Recusar</button>` : `
        <button class="secondary" onclick="userAction('toggle-admin','${escapeHtml(username)}')">${u.isAdmin ? 'Tirar admin' : 'Tornar admin'}</button>
        <button class="secondary" onclick="userAction('delete','${escapeHtml(username)}')">Remover acesso</button>`}
      </div>
    </div>
  `).join('') : '<p>Nenhum pedido de acesso ainda.</p>';
}

async function userAction(action, username){
  await fetch('/api/users/' + action, { method:'POST', body: JSON.stringify({ username }) });
  renderUsersList();
}

loadConfig();
renderCredList();
renderPagadorList();
renderHistoryList();
checkMe();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Servidor HTTP local
# --------------------------------------------------------------------------

SITE_PASSWORD = os.environ.get('SITE_PASSWORD', '')  # defina isso na hospedagem — sem senha, o site fica aberto pra qualquer um com o link


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silencia o log padrão no terminal

    def _current_user(self):
        if not MASTER_PASSWORD:
            return {'username': 'local', 'isAdmin': True}  # sem senha mestre configurada = uso local, sem login
        return get_session_user(self)

    def _require_login_json(self):
        self.send_response(401)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        body = json.dumps({'error': 'not_authenticated'}).encode('utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _set_session_cookie(self, token):
        self.send_header('Set-Cookie', f'session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000')

    def _send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path, query = parsed.path, parsed.query

        if path == '/':
            user = self._current_user()
            self._send_html(HTML_PAGE if user else LOGIN_PAGE)
            return

        if path.startswith('/api/') and path not in ('/api/login', '/api/register'):
            if not self._current_user():
                self._require_login_json()
                return
        try:
            self._route_get(path, query)
        except Exception as e:
            try:
                self._send_json(500, {'error': f'Erro interno no programa local: {e}'})
            except Exception:
                pass

    def _route_get(self, path, query):
        if path == '/api/config':
            cfg = get_config()
            user = self._current_user()
            if not (user and user.get('isAdmin')):
                cfg = dict(cfg)
                cfg['pass'] = ''
                cfg['user'] = ''
                cfg['anthropicApiKey'] = ''
            self._send_json(200, cfg)
        elif path == '/api/creditor-map':
            self._send_json(200, get_creditor_map())
        elif path == '/api/doctype-map':
            self._send_json(200, get_doc_type_map())
        elif path == '/api/pagador-map':
            self._send_json(200, get_pagador_map())
        elif path == '/api/history':
            self._send_json(200, get_history())
        elif path == '/api/me':
            self._send_json(200, self._current_user())
        elif path == '/api/users':
            user = self._current_user()
            if not user or not user.get('isAdmin'):
                self._send_json(403, {'error': 'Só administradores podem ver isso.'})
                return
            users = get_users()
            safe = {u: {'approved': v.get('approved', False), 'isAdmin': v.get('isAdmin', False), 'createdAt': v.get('createdAt', '')} for u, v in users.items()}
            self._send_json(200, safe)
        elif path.startswith('/api/sienge/'):
            sienge_path = path[len('/api/sienge/'):]
            status, data = call_sienge('GET', sienge_path, query=query)
            self._send_json(status, data)
        else:
            self._send_json(404, {'error': 'not found'})

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path, query = parsed.path, parsed.query

        if path not in ('/api/login', '/api/register') and not self._current_user():
            self._require_login_json()
            return

        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length else b''
        try:
            body = json.loads(raw.decode('utf-8')) if raw else {}
        except json.JSONDecodeError:
            self._send_json(400, {'error': 'JSON inválido no corpo da requisição'})
            return

        try:
            self._route_post(path, query, body)
        except Exception as e:
            # Nunca deixa a conexão terminar sem resposta — sem isso, o
            # navegador via "Unexpected end of JSON input" sem explicação nenhuma.
            try:
                self._send_json(500, {'error': f'Erro interno no programa local: {e}'})
            except Exception:
                pass  # conexão já pode ter caído; não tem mais o que fazer

    def _route_post(self, path, query, body):
        if path == '/api/login':
            ok, is_admin, err = authenticate(body.get('username', ''), body.get('password', ''))
            if not ok:
                self._send_json(401, {'error': err or 'Não foi possível entrar.'})
                return
            username = (body.get('username') or '').strip().lower()
            token = create_session(username)
            self._send_json(200, {'ok': True, 'isAdmin': is_admin}, extra_headers={
                'Set-Cookie': f'session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000'
            })
        elif path == '/api/register':
            ok, msg = register_user(body.get('username', ''), body.get('password', ''))
            self._send_json(200 if ok else 400, {'ok': ok, 'message': msg})
        elif path == '/api/logout':
            cookie_header = self.headers.get('Cookie', '')
            for part in cookie_header.split(';'):
                part = part.strip()
                if part.startswith('session='):
                    SESSIONS.pop(part[len('session='):], None)
            self._send_json(200, {'ok': True}, extra_headers={
                'Set-Cookie': 'session=; Path=/; HttpOnly; Max-Age=0'
            })
        elif path.startswith('/api/users/'):
            user = self._current_user()
            if not user or not user.get('isAdmin'):
                self._send_json(403, {'error': 'Só administradores podem fazer isso.'})
                return
            action = path[len('/api/users/'):]
            target = (body.get('username') or '').strip().lower()
            users = get_users()
            if target not in users:
                self._send_json(404, {'error': 'Usuário não encontrado.'})
                return
            if action == 'approve':
                users[target]['approved'] = True
            elif action == 'reject' or action == 'delete':
                del users[target]
            elif action == 'toggle-admin':
                users[target]['isAdmin'] = not users[target].get('isAdmin', False)
            else:
                self._send_json(404, {'error': 'Ação desconhecida.'})
                return
            save_users(users)
            self._send_json(200, {'ok': True})
        elif path == '/api/config':
            user = self._current_user()
            if not (user and user.get('isAdmin')):
                self._send_json(403, {'error': 'Só administradores podem alterar a configuração.'})
                return
            save_json_file(CONFIG_FILE, body)
            self._send_json(200, {'ok': True})
        elif path == '/api/creditor-map':
            save_json_file(CREDITOR_MAP_FILE, body)
            self._send_json(200, {'ok': True})
        elif path == '/api/doctype-map':
            save_json_file(DOC_TYPE_MAP_FILE, body)
            self._send_json(200, {'ok': True})
        elif path == '/api/pagador-map':
            save_json_file(PAGADOR_MAP_FILE, body)
            self._send_json(200, {'ok': True})
        elif path == '/api/history':
            append_history(body)
            self._send_json(200, {'ok': True})
        elif path == '/api/similar-history':
            matches = find_similar_history(body.get('descricao', ''), exclude_cnpj=body.get('excludeCnpj'))
            self._send_json(200, matches)
        elif path.startswith('/api/sienge/'):
            sienge_path = path[len('/api/sienge/'):]
            status, data = call_sienge('POST', sienge_path, query=query, body=body)
            self._send_json(status, data)
        elif path == '/api/attach':
            bill_id = body.get('billId')
            description = body.get('description', '')
            filename = body.get('filename', 'documento.pdf')
            file_b64 = body.get('fileBase64', '')
            if not bill_id or not file_b64:
                self._send_json(400, {'error': 'Faltam billId ou o arquivo.'})
                return
            try:
                file_bytes = base64.b64decode(file_b64)
            except Exception:
                self._send_json(400, {'error': 'Arquivo em base64 inválido.'})
                return
            status, data = call_sienge_attachment(bill_id, description, filename, file_bytes)
            self._send_json(status, data)
        elif path == '/api/extract':
            filename = body.get('filename', 'documento.pdf')
            file_b64 = body.get('fileBase64', '')
            if not file_b64:
                self._send_json(400, {'error': 'Falta o arquivo.'})
                return
            try:
                file_bytes = base64.b64decode(file_b64)
            except Exception:
                self._send_json(400, {'error': 'Arquivo em base64 inválido.'})
                return
            status, data = call_extraction(filename, file_bytes)
            self._send_json(status, data)
        elif path == '/api/boleto-payment':
            bill_id = body.get('billId')
            linha_digitavel = body.get('linhaDigitavel', '').strip()
            payment_type_id = body.get('paymentTypeId', 19)
            beneficiary_id = body.get('beneficiaryId')
            if not bill_id or not linha_digitavel:
                self._send_json(400, {'error': 'Faltam billId ou a linha digitável.'})
                return
            status, data = send_boleto_payment_info(bill_id, linha_digitavel, payment_type_id, beneficiary_id)
            self._send_json(status, data)
        else:
            self._send_json(404, {'error': 'not found'})


def main():
    port = int(os.environ.get('PORT', PORT))
    is_cloud = 'PORT' in os.environ  # a Render (e a maioria dos serviços de nuvem) define isso sozinha
    host = '0.0.0.0' if is_cloud else '127.0.0.1'
    server = ThreadingHTTPServer((host, port), Handler)
    if is_cloud:
        print(f'Servidor rodando na nuvem, porta {port}')
    else:
        url = f'http://localhost:{port}'
        print(f'Servidor rodando em {url}')
        print('Deixe esta janela aberta enquanto usar a ferramenta.')
        print('Para parar, feche esta janela ou aperte Ctrl+C.')
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
