import sqlite3
import socket
import threading
import webview
import sys
import os
import logging
import json
import csv
import io
import shutil
import traceback
from flask import Flask, jsonify, request, send_from_directory, send_file, Response
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
import time
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

# ============================================
# 🔒 CACHE GLOBAL COM LOCK SEGURO
# ============================================
DADOS_TV_CACHE = []
CACHE_LOCK = threading.RLock()  # 🔧 Mudado para RLock (permite re-entrada)
ULTIMA_ATUALIZACAO = datetime.now()
USER_CACHE_RAM = {}
# ============================================
# 🔧 LOCK GLOBAL PARA OPERAÇÕES DE ESCRITA
# ============================================
DB_WRITE_LOCK = threading.RLock()

# --- CONFIGURAÇÃO DE PASTAS (UNIFICADA) ---
# 🔥 SEMPRE USA AppData (desenvolvimento E produção)
app_data = os.getenv("APPDATA")
if not app_data:
    app_data = os.path.expanduser("~/.clinicasys")

DATA_DIR = os.path.join(app_data, "ClinicaSysPro")

if getattr(sys, "frozen", False):
    # Se estiver rodando como EXE, os arquivos HTML estão na pasta temporária interna
    BASE_DIR = sys._MEIPASS
    # O log de erros vai para a pasta de dados (AppData) para não perder
    sys.stderr = open(os.path.join(DATA_DIR, "debug_erro.txt"), "w")
else:
    # Modo desenvolvimento
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if not os.path.exists(DATA_DIR):
    try:
        os.makedirs(DATA_DIR)
    except:
        pass

UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__, static_folder=BASE_DIR, template_folder=BASE_DIR)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = "chave-secreta-clinica-v9-fix"

# 🔒 CONFIGURAÇÃO DE SESSÃO ESTÁVEL
# Define que o login dura 1 ano (365 dias)
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=365)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)

# Configurações do Cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_NAME"] = "clinicasys_session"

CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:5000", "http://127.0.0.1:5000"],
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_error"
login_manager.session_protection = None  # 🔥 Desativa proteção de sessão
login_manager.refresh_view = None


def atualizar_cache_tv():
    """
    🔒 Atualiza o cache da TV com proteção total contra race conditions.
    """
    global DADOS_TV_CACHE, ULTIMA_ATUALIZACAO

    # Timeout de 5 segundos para evitar deadlock
    if not CACHE_LOCK.acquire(timeout=5):
        print("⚠️ Cache já está sendo atualizado, pulando...")
        return

    try:
        # 🔒 Usa conexão READ-ONLY para evitar conflitos
        conn_string = f"file:{db.db_path}?mode=ro"
        conn = sqlite3.connect(conn_string, uri=True, timeout=30)
        conn.row_factory = sqlite3.Row

        ini = datetime.now().strftime("%Y-%m-%d 00:00:00")
        fim = datetime.now().strftime("%Y-%m-%d 23:59:59")

        query = """
            SELECT a.*, p.nome as paciente_nome, p.telefone_principal as paciente_tel, 
            pr.nome as profissional_nome, s.nome as sala_nome 
            FROM agendamentos a 
            JOIN pacientes p ON a.paciente_id=p.id 
            LEFT JOIN profissionais pr ON a.profissional_id=pr.id 
            LEFT JOIN salas s ON a.sala_id=s.id 
            WHERE a.data_hora_inicio BETWEEN ? AND ?
            ORDER BY a.data_hora_inicio ASC
        """
        r = [dict(x) for x in conn.execute(query, (ini, fim)).fetchall()]

        DADOS_TV_CACHE = r
        ULTIMA_ATUALIZACAO = datetime.now()
        conn.close()
        print(f"✅ Cache atualizado: {len(r)} agendamentos")
    except Exception as e:
        print(f"❌ Erro ao atualizar cache: {e}")
        traceback.print_exc()
    finally:
        CACHE_LOCK.release()


def obter_ip_rede():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return f"http://{ip}:5000"
    except:
        return "http://127.0.0.1:5000"


class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = str(id)  # 🔥 Força conversão para String (Requisito do Flask-Login)
        self.username = username
        self.role = role

    def get_id(self):  # 🔥 Implementação explícita
        return self.id


class Database:
    def __init__(self, db_name="clinica.db"):
        self.db_path = os.path.join(DATA_DIR, db_name)
        self.init_db()

    def conectar(self, read_only=False):
        """
        🔒 Conexão segura com suporte a modo READ-ONLY
        """
        if read_only:
            # Conexão somente leitura (não trava o banco)
            conn_string = f"file:{self.db_path}?mode=ro"
            conn = sqlite3.connect(
                conn_string, uri=True, timeout=30, check_same_thread=False
            )
        else:
            # Conexão normal com timeout alto
            conn = sqlite3.connect(self.db_path, timeout=60, check_same_thread=False)

        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.conectar()
        c = conn.cursor()

        # Ativa WAL mode
        try:
            c.execute("PRAGMA journal_mode=WAL;")
            c.execute("PRAGMA synchronous = NORMAL;")
            c.execute("PRAGMA temp_store = MEMORY;")
            c.execute("PRAGMA busy_timeout = 60000;")  # 60 segundos de espera
        except Exception as e:
            print("Aviso: Não foi possível ativar otimizações SQLite:", e)

        # Criação das tabelas
        # NOTA: Adicionei permissoes TEXT aqui no CREATE para instalações novas
        c.execute(
            "CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT, permissoes TEXT)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS configuracoes (id INTEGER PRIMARY KEY, nome_clinica TEXT, endereco TEXT, telefone TEXT, cnpj TEXT)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS pacientes (id INTEGER PRIMARY KEY, nome TEXT, cpf TEXT, rg TEXT, data_nascimento DATE, sexo TEXT, telefone_principal TEXT, telefone_secundario TEXT, email TEXT, endereco TEXT, convenio_id INTEGER, observacoes_medicas TEXT, medicamentos_em_uso TEXT, responsavel TEXT, foto TEXT, ativo INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS profissionais (id INTEGER PRIMARY KEY, nome TEXT, crm TEXT, cpf TEXT, data_nascimento DATE, especialidade_id INTEGER, email TEXT, telefone TEXT, endereco TEXT, dados_bancarios TEXT, cor_agenda TEXT, comissao REAL, bio TEXT, disponibilidade TEXT, ativo INTEGER DEFAULT 1)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS agendamentos (id INTEGER PRIMARY KEY, paciente_id INTEGER, profissional_id INTEGER, data_hora_inicio DATETIME, duracao_minutos INTEGER, data_hora_fim DATETIME, status TEXT, tipo TEXT, motivo_cancelamento TEXT, usuario_cancelou TEXT, observacoes TEXT, sala_id INTEGER, retorno_de_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS convenios (id INTEGER PRIMARY KEY, nome TEXT, registro_ans TEXT, cnpj TEXT, prazo_pagamento INTEGER, telefone TEXT, email TEXT, site TEXT, tabela_precos TEXT)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS prontuarios (id INTEGER PRIMARY KEY, paciente_id INTEGER, profissional_id INTEGER, data_atendimento DATETIME, evolucao_clinica TEXT, diagnostico TEXT, prescricao TEXT, exames_solicitados TEXT, anexos TEXT)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS contas_receber (id INTEGER PRIMARY KEY, paciente_id INTEGER, descricao TEXT, valor_total REAL, valor_pago REAL DEFAULT 0, parcelas INTEGER DEFAULT 1, parcela_atual INTEGER DEFAULT 1, status TEXT DEFAULT 'Pendente', data_vencimento DATE, data_pagamento DATE, forma_pagamento TEXT, categoria TEXT, centro_custo TEXT, observacoes TEXT, comprovante TEXT)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS contas_pagar (id INTEGER PRIMARY KEY, fornecedor TEXT, descricao TEXT, valor_total REAL, valor_pago REAL DEFAULT 0, parcelas INTEGER DEFAULT 1, parcela_atual INTEGER DEFAULT 1, status TEXT DEFAULT 'Pendente', data_vencimento DATE, data_pagamento DATE, forma_pagamento TEXT, categoria TEXT, centro_custo TEXT, observacoes TEXT, comprovante TEXT)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS caixa (id INTEGER PRIMARY KEY, data_hora DATETIME DEFAULT CURRENT_TIMESTAMP, tipo TEXT, valor REAL, descricao TEXT, usuario TEXT, referencia_id INTEGER)"
        )

        for t in ["especialidades", "salas", "procedimentos"]:
            c.execute(
                f"CREATE TABLE IF NOT EXISTS {t} (id INTEGER PRIMARY KEY, nome TEXT)"
            )

        # --- CORREÇÃO IMPORTANTE AQUI ---
        # Tenta criar a coluna permissoes ANTES de inserir ou atualizar o admin
        try:
            c.execute("ALTER TABLE usuarios ADD COLUMN permissoes TEXT")
        except:
            pass
        # --------------------------------

        try:
            c.execute("ALTER TABLE agendamentos ADD COLUMN data_chamada DATETIME")
        except:
            pass
        try:
            c.execute(
                "ALTER TABLE profissionais ADD COLUMN valor_padrao REAL DEFAULT 0"
            )
            c.execute("ALTER TABLE agendamentos ADD COLUMN valor REAL DEFAULT 0")
            c.execute(
                "ALTER TABLE agendamentos ADD COLUMN financeiro_gerado INTEGER DEFAULT 0"
            )
        except:
            pass
        try:
            c.execute("ALTER TABLE prontuarios ADD COLUMN peso REAL")
            c.execute("ALTER TABLE prontuarios ADD COLUMN altura REAL")
            c.execute("ALTER TABLE prontuarios ADD COLUMN pressao TEXT")
            c.execute("ALTER TABLE prontuarios ADD COLUMN temp REAL")
            c.execute("ALTER TABLE prontuarios ADD COLUMN saturacao INTEGER")
            c.execute("ALTER TABLE pacientes ADD COLUMN alergias TEXT")
        except:
            pass

        # Cria admin se não existir
        if not c.execute("SELECT * FROM usuarios WHERE username='admin'").fetchone():
            c.execute(
                "INSERT OR IGNORE INTO usuarios (id, username, password_hash, role, permissoes) VALUES (1, 'admin', ?, 'admin', '[]')",
                (generate_password_hash("admin123"),),
            )

        # Agora é seguro atualizar, pois a coluna permissoes já existe (criada no CREATE ou no ALTER acima)
        c.execute(
            "UPDATE usuarios SET role='admin', permissoes='[]' WHERE username='admin'"
        )

        if not c.execute("SELECT * FROM configuracoes WHERE id=1").fetchone():
            c.execute(
                "INSERT INTO configuracoes (id, nome_clinica, endereco, telefone) VALUES (1, 'Minha Clínica', 'Rua Exemplo, 123', '(11) 9999-9999')"
            )
        try:
            c.execute("ALTER TABLE configuracoes ADD COLUMN mensagem_tv TEXT")
        except:
            pass

        c.execute(
            "UPDATE agendamentos SET status='Agendado' WHERE status IS NULL OR status = 'null'"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS modelos_documentos (id INTEGER PRIMARY KEY, tipo TEXT, nome TEXT, conteudo TEXT)"
        )

        try:
            c.execute("ALTER TABLE profissionais ADD COLUMN assinatura_path TEXT")
        except:
            pass

        try:
            c.execute("ALTER TABLE prontuarios ADD COLUMN anexos TEXT")
        except:
            pass
        try:
            # Tabela de ligação: Preço do Procedimento x Convênio
            c.execute(
                "CREATE TABLE IF NOT EXISTS procedimento_precos (id INTEGER PRIMARY KEY, procedimento_id INTEGER, convenio_id INTEGER, valor REAL)"
            )

            # Colunas extras para Procedimentos
            c.execute(
                "ALTER TABLE procedimentos ADD COLUMN tempo_padrao INTEGER DEFAULT 30"
            )
            c.execute(
                "ALTER TABLE procedimentos ADD COLUMN valor_padrao REAL DEFAULT 0"
            )
            c.execute("ALTER TABLE procedimentos ADD COLUMN repasse REAL DEFAULT 0")
            c.execute("ALTER TABLE procedimentos ADD COLUMN codigo_tuss TEXT")
        except:
            pass

        try:
            # Tabela de arquivo do convênio
            c.execute("ALTER TABLE convenios ADD COLUMN arquivo_tabela TEXT")
        except:
            pass

        try:
            c.execute("ALTER TABLE prontuarios ADD COLUMN queixa_principal TEXT")
            c.execute("ALTER TABLE prontuarios ADD COLUMN subjetivo TEXT")
            c.execute("ALTER TABLE prontuarios ADD COLUMN objetivo TEXT")
            c.execute("ALTER TABLE prontuarios ADD COLUMN avaliacao TEXT")
            c.execute("ALTER TABLE prontuarios ADD COLUMN plano TEXT")
            c.execute("ALTER TABLE prontuarios ADD COLUMN conduta TEXT")
            c.execute("ALTER TABLE prontuarios ADD COLUMN retorno TEXT")
        except:
            pass
        try:
            c.execute("ALTER TABLE prontuarios ADD COLUMN retificacao TEXT")
        except:
            pass
        try:
            c.execute("ALTER TABLE profissionais ADD COLUMN foto TEXT")
        except:
            pass

        conn.commit()
        conn.close()


db = Database()


@login_manager.user_loader
def load_user(user_id):
    # --- CORREÇÃO 1: LOGIN BLINDADO ---
    # Se o ID for "1" (Admin), ACEITA IMEDIATAMENTE.
    # Não consulta banco, não confere cache, não dá erro.
    # Isso garante que o sistema NUNCA deslogue o Admin localmente.
    if str(user_id) == "1":
        return User(1, "admin", "admin")

    # Código normal apenas para outros usuários (se houver)
    try:
        conn = db.conectar(read_only=True)
        u = conn.execute("SELECT * FROM usuarios WHERE id=?", (user_id,)).fetchone()
        conn.close()
        if u:
            return User(u["id"], u["username"], u["role"])
    except:
        pass
    return None


@login_manager.unauthorized_handler
def login_error():
    return jsonify({"erro": "Acesso negado"}), 401


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "sistema.html")


@app.route("/api/login", methods=["POST"])
def login():
    try:
        d = request.json
        conn = db.conectar(read_only=True)
        u = conn.execute(
            "SELECT * FROM usuarios WHERE username=?", (d["username"],)
        ).fetchone()
        conn.close()

        if u and check_password_hash(u["password_hash"], d["password"]):
            user_obj = User(u["id"], u["username"], u["role"])
            USER_CACHE_RAM[u["id"]] = user_obj

            # --- CORREÇÃO AQUI ---
            from flask import session

            # 🔥 ESTA É A LINHA QUE FALTAVA:
            login_user(user_obj)
            # ---------------------------

            session.permanent = True
            session.modified = True

            # Faz o login e define a duração
            perms = (
                u["permissoes"]
                if "permissoes" in u.keys() and u["permissoes"]
                else "[]"
            )
            return jsonify(
                {
                    "msg": "Logado",
                    "user": u["username"],
                    "role": u["role"],
                    "perms": perms,
                }
            )

        return jsonify({"erro": "Dados inválidos"}), 401
    except Exception as e:
        print(f"❌ Erro no login: {e}")
        traceback.print_exc()
        return jsonify({"erro": str(e)}), 500


@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    # ADICIONE ESTA LINHA:
    USER_CACHE_RAM.pop(current_user.id, None)

    logout_user()
    return jsonify({"msg": "Saiu"})


@app.route("/api/procedimentos/detalhes/<int:id>", methods=["GET"])
@login_required
def get_proc_detalhes(id):
    conn = db.conectar(read_only=True)
    # Pega dados básicos
    proc = conn.execute("SELECT * FROM procedimentos WHERE id=?", (id,)).fetchone()
    # Pega preços por convênio
    precos = conn.execute(
        """
        SELECT c.id as convenio_id, c.nome as convenio_nome, pp.valor 
        FROM convenios c 
        LEFT JOIN procedimento_precos pp ON pp.convenio_id = c.id AND pp.procedimento_id = ?
        ORDER BY c.nome
    """,
        (id,),
    ).fetchall()
    conn.close()
    return jsonify({"dados": dict(proc), "precos": [dict(p) for p in precos]})


@app.route("/api/procedimentos/salvar_completo", methods=["POST"])
@login_required
def save_proc_completo():
    d = request.json
    with DB_WRITE_LOCK:
        conn = db.conectar()

        # 1. Salva/Cria o Procedimento Base
        if d.get("id"):
            conn.execute(
                "UPDATE procedimentos SET nome=?, tempo_padrao=?, valor_padrao=?, repasse=?, codigo_tuss=? WHERE id=?",
                (
                    d["nome"],
                    d.get("tempo", 30),
                    d.get("valor", 0),
                    d.get("repasse", 0),
                    d.get("codigo", ""),
                    d["id"],
                ),
            )
            proc_id = d["id"]
        else:
            cursor = conn.execute(
                "INSERT INTO procedimentos (nome, tempo_padrao, valor_padrao, repasse, codigo_tuss) VALUES (?,?,?,?,?)",
                (
                    d["nome"],
                    d.get("tempo", 30),
                    d.get("valor", 0),
                    d.get("repasse", 0),
                    d.get("codigo", ""),
                ),
            )
            proc_id = cursor.lastrowid

        # 2. Salva a Tabela de Preços por Convênio
        precos = d.get(
            "precos_lista", []
        )  # Espera lista: [{convenio_id: 1, valor: 100}, ...]

        # Limpa preços antigos desse procedimento para regravar (mais fácil que update um por um)
        conn.execute(
            "DELETE FROM procedimento_precos WHERE procedimento_id=?", (proc_id,)
        )

        for p in precos:
            if p.get("valor") and float(p["valor"]) > 0:
                conn.execute(
                    "INSERT INTO procedimento_precos (procedimento_id, convenio_id, valor) VALUES (?,?,?)",
                    (proc_id, p["convenio_id"], p["valor"]),
                )

        conn.commit()
        conn.close()
    return jsonify({"msg": "Procedimento salvo com sucesso!"})


@app.route("/api/check_auth")
def check_auth():
    if current_user.is_authenticated:
        # Busca permissões atualizadas no banco para garantir
        try:
            conn = db.conectar(read_only=True)
            u = conn.execute(
                "SELECT role, permissoes FROM usuarios WHERE id=?", (current_user.id,)
            ).fetchone()
            conn.close()
            role = u["role"] if u else "user"
            perms = u["permissoes"] if u and u["permissoes"] else "[]"
            return jsonify(
                {"user": current_user.username, "role": role, "perms": perms}
            )
        except:
            return jsonify(
                {"user": current_user.username, "role": "user", "perms": "[]"}
            )

    return jsonify({"erro": "Nao logado"}), 401


@app.route("/api/config", methods=["GET"])
@login_required
def get_config():
    conn = db.conectar(read_only=True)
    c = conn.execute("SELECT * FROM configuracoes WHERE id=1").fetchone()
    conn.close()
    data = dict(c) if c else {}
    data["ip_rede"] = obter_ip_rede()
    return jsonify(data)


@app.route("/api/config/publico", methods=["GET"])
def get_config_publico():
    """🔓 Rota pública para TV acessar configurações"""
    conn = db.conectar(read_only=True)
    # Adicionado mensagem_tv na consulta
    c = conn.execute(
        "SELECT nome_clinica, endereco, telefone, mensagem_tv FROM configuracoes WHERE id=1"
    ).fetchone()
    conn.close()

    data = dict(c) if c else {}
    # Define um padrão se estiver vazio
    if not data.get("mensagem_tv"):
        data["mensagem_tv"] = (
            "Bem-vindo à nossa clínica! • Por favor, aguarde ser chamado."
        )

    return jsonify(data)


@app.route("/api/config/salvar", methods=["POST"])
@login_required
def save_config():
    d = request.json
    cnpj = d.get("cnpj", "")[:20]

    with DB_WRITE_LOCK:
        conn = db.conectar()
        # Adicionado msg_tv no update
        conn.execute(
            "UPDATE configuracoes SET nome_clinica=?, endereco=?, telefone=?, cnpj=?, mensagem_tv=? WHERE id=1",
            (d["nome"], d["end"], d["tel"], cnpj, d.get("msg_tv", "")),
        )
        conn.commit()
        conn.close()
    return jsonify({"msg": "Salvo"})


@app.route("/api/mudar_senha", methods=["POST"])
@login_required
def mudar_senha():
    d = request.json
    conn = db.conectar(read_only=True)
    u = conn.execute(
        "SELECT password_hash FROM usuarios WHERE id = ?", (current_user.id,)
    ).fetchone()

    if not u or not check_password_hash(u["password_hash"], d["antiga"]):
        conn.close()
        return jsonify({"erro": "Senha antiga incorreta"}), 401

    conn.close()

    with DB_WRITE_LOCK:  # 🔒 Protege escrita
        conn = db.conectar()
        conn.execute(
            "UPDATE usuarios SET password_hash = ? WHERE id = ?",
            (generate_password_hash(d["nova"]), current_user.id),
        )
        conn.commit()
        conn.close()

    return jsonify({"msg": "Sucesso"})


@app.route("/api/backup")
@login_required
def backup():
    bkp = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    shutil.copy2(db.db_path, os.path.join(DATA_DIR, bkp))
    return send_file(os.path.join(DATA_DIR, bkp), as_attachment=True)


@app.route("/api/dashboard_stats")
@login_required
def dash():
    conn = db.conectar(read_only=True)
    c = conn.cursor()

    h_ini = datetime.now().strftime("%Y-%m-%d 00:00:00")
    h_fim = datetime.now().strftime("%Y-%m-%d 23:59:59")
    m_ini = datetime.now().strftime("%Y-%m-01 00:00:00")
    prox_mes = (datetime.now().replace(day=28) + timedelta(days=4)).replace(day=1)
    mes_fim = (prox_mes - timedelta(seconds=1)).strftime("%Y-%m-%d 23:59:59")
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    s = {
        "hoje": 0,
        "mes": 0,
        "faturamento": "---",  # Padrão escondido
        "pendencias": "---",  # Padrão escondido
        "proximos": [],
        "grafico": [],
    }
    try:
        s["hoje"] = c.execute(
            "SELECT COUNT(*) FROM agendamentos WHERE data_hora_inicio BETWEEN ? AND ? AND (status!='Cancelado' OR status IS NULL)",
            (h_ini, h_fim),
        ).fetchone()[0]
        s["mes"] = c.execute(
            "SELECT COUNT(*) FROM agendamentos WHERE data_hora_inicio BETWEEN ? AND ? AND (status!='Cancelado' OR status IS NULL)",
            (m_ini, mes_fim),
        ).fetchone()[0]

        # --- SEGURANÇA FINANCEIRA ---
        # Só calcula e mostra dinheiro se for ADMIN
        if current_user.role == "admin":
            fat_val = c.execute(
                "SELECT COALESCE(SUM(valor_pago),0) FROM contas_receber WHERE data_pagamento BETWEEN ? AND ?",
                (m_ini, mes_fim),
            ).fetchone()[0]
            s["faturamento"] = fat_val  # Envia o número real

            s["pendencias"] = c.execute(
                "SELECT COUNT(*) FROM contas_receber WHERE status='Pendente' AND data_vencimento < ?",
                (h_ini,),
            ).fetchone()[0]
        # -----------------------------

        sql_prox = """
            SELECT a.data_hora_inicio, p.nome as paciente, pr.nome as profissional 
            FROM agendamentos a 
            JOIN pacientes p ON a.paciente_id=p.id 
            JOIN profissionais pr ON a.profissional_id=pr.id 
            WHERE a.data_hora_fim > ? 
            AND (a.status != 'Cancelado' OR a.status IS NULL)
            AND a.status != 'Finalizado'
            ORDER BY a.data_hora_inicio ASC 
            LIMIT 8
        """
        s["proximos"] = [dict(r) for r in c.execute(sql_prox, (agora,)).fetchall()]

        s["grafico"] = [
            {"nome": r["nome"] or "Geral", "total": r["total"]}
            for r in c.execute(
                "SELECT e.nome, COUNT(a.id) as total FROM agendamentos a JOIN profissionais p ON a.profissional_id = p.id LEFT JOIN especialidades e ON p.especialidade_id = e.id WHERE a.data_hora_inicio BETWEEN ? AND ? AND a.status != 'Cancelado' GROUP BY e.nome ORDER BY total DESC",
                (m_ini, mes_fim),
            ).fetchall()
        ]
    except Exception as e:
        print("Erro Dash:", e)

    conn.close()
    return jsonify(s)


@app.route("/api/agenda/calendario", methods=["GET"])
@login_required
def cal_ag():
    conn = db.conectar(read_only=True)
    evs = []
    cores = {
        "Agendado": "#F59E0B",
        "Confirmado": "#3B82F6",
        "Realizado": "#10B981",
        "NoShow": "#EF4444",
        "Em Espera": "#8B5CF6",
        "Em Atendimento": "#EC4899",
    }
    for r in conn.execute(
        "SELECT a.id, a.data_hora_inicio, a.data_hora_fim, COALESCE(a.status, 'Agendado') as status, p.nome as paciente FROM agendamentos a JOIN pacientes p ON a.paciente_id=p.id WHERE a.status!='Cancelado' OR a.status IS NULL"
    ).fetchall():
        st = r["status"]
        evs.append(
            {
                "id": r["id"],
                "title": f"{r['paciente']} ({st})",
                "start": r["data_hora_inicio"],
                "end": r["data_hora_fim"],
                "backgroundColor": cores.get(st, "#6B7280"),
                "borderColor": cores.get(st, "#6B7280"),
            }
        )
    conn.close()
    return jsonify(evs)


@app.route("/api/sala_espera")
def sala_espera():
    """🔒 Retorna o cache (ultra rápido, sem acessar banco)"""
    with CACHE_LOCK:
        return jsonify(DADOS_TV_CACHE)


@app.route("/api/pacientes/busca", methods=["GET"])
@login_required
def busca_pacientes():
    termo = request.args.get("termo", "")
    conn = db.conectar(read_only=True)
    query = """
        SELECT * FROM pacientes 
        WHERE nome LIKE ? 
        OR cpf LIKE ? 
        OR telefone_principal LIKE ? 
        OR email LIKE ?
        ORDER BY nome 
        LIMIT 20
    """
    busca = f"%{termo}%"
    r = [dict(x) for x in conn.execute(query, (busca, busca, busca, busca)).fetchall()]
    conn.close()
    return jsonify(r)


@app.route("/api/pacientes/salvar", methods=["POST"])
@login_required
def save_pac():
    d = request.json

    # 1. Validação
    if not d.get("nome"):
        return jsonify({"erro": "Nome do paciente é obrigatório"}), 400

    end = d.get("endereco", "")
    resp = json.dumps(d.get("responsavel", {}))
    v = (
        d["nome"],
        d.get("cpf"),
        d.get("rg"),
        d.get("nasc"),
        d.get("sexo"),
        d.get("tel"),
        d.get("email"),
        end,
        d.get("conv"),
        d.get("obs"),
        d.get("meds"),
        resp,
        d.get("foto"),
    )

    with DB_WRITE_LOCK:
        conn = db.conectar()

        # 2. TRAVA DE DUPLICIDADE (CPF)
        if d.get("cpf") and len(d.get("cpf")) > 5:  # Só valida se tiver CPF preenchido
            check = conn.execute(
                "SELECT id FROM pacientes WHERE cpf=? AND ativo=1", (d.get("cpf"),)
            ).fetchone()
            # Se achou e não é o mesmo ID que estamos editando
            if check and (not d.get("id") or str(check["id"]) != str(d.get("id"))):
                conn.close()
                return jsonify({"erro": "Este CPF já pertence a outro paciente!"}), 400

        # 3. Trava de Duplicidade (Nome + Telefone) - Caso não tenha CPF
        elif not d.get("id"):
            check = conn.execute(
                "SELECT id FROM pacientes WHERE nome=? AND telefone_principal=? AND ativo=1",
                (d["nome"], d.get("tel")),
            ).fetchone()
            if check:
                conn.close()
                return (
                    jsonify({"erro": "Paciente com mesmo Nome e Telefone já existe!"}),
                    400,
                )

        if d.get("id"):
            conn.execute(
                "UPDATE pacientes SET nome=?, cpf=?, rg=?, data_nascimento=?, sexo=?, telefone_principal=?, email=?, endereco=?, convenio_id=?, observacoes_medicas=?, medicamentos_em_uso=?, responsavel=?, foto=? WHERE id=?",
                v + (d["id"],),
            )
        else:
            conn.execute(
                "INSERT INTO pacientes (nome, cpf, rg, data_nascimento, sexo, telefone_principal, email, endereco, convenio_id, observacoes_medicas, medicamentos_em_uso, responsavel, foto) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                v,
            )

        conn.commit()
        conn.close()

    return jsonify({"msg": "Salvo"})


@app.route("/api/pacientes/deletar/<int:id>", methods=["DELETE"])
@login_required
def deletar_paciente(id):
    with DB_WRITE_LOCK:
        conn = db.conectar()
        # Verifica histórico completo
        tem_ag = conn.execute(
            "SELECT id FROM agendamentos WHERE paciente_id=? LIMIT 1", (id,)
        ).fetchone()
        tem_pr = conn.execute(
            "SELECT id FROM prontuarios WHERE paciente_id=? LIMIT 1", (id,)
        ).fetchone()
        tem_fin = conn.execute(
            "SELECT id FROM contas_receber WHERE paciente_id=? LIMIT 1", (id,)
        ).fetchone()

        if tem_ag or tem_pr or tem_fin:
            conn.execute("UPDATE pacientes SET ativo=0 WHERE id=?", (id,))
            msg = (
                "Paciente ARQUIVADO (possui histórico). Não aparecerá mais nas listas."
            )
        else:
            conn.execute("DELETE FROM pacientes WHERE id=?", (id,))
            msg = "Paciente EXCLUÍDO (era um cadastro vazio)."
        conn.commit()
        conn.close()
    return jsonify({"msg": msg})


# --- ROTA INTELIGENTE PROFISSIONAIS ---
@app.route("/api/profissionais/deletar/<int:id>", methods=["DELETE"])
@login_required
def deletar_profissional(id):
    with DB_WRITE_LOCK:
        conn = db.conectar()
        tem_ag = conn.execute(
            "SELECT id FROM agendamentos WHERE profissional_id=? LIMIT 1", (id,)
        ).fetchone()

        if tem_ag:
            conn.execute("UPDATE profissionais SET ativo=0 WHERE id=?", (id,))
            msg = "Profissional INATIVADO (possui agenda). Histórico mantido."
        else:
            conn.execute("DELETE FROM profissionais WHERE id=?", (id,))
            msg = "Profissional EXCLUÍDO permanentemente."
        conn.commit()
        conn.close()
    return jsonify({"msg": msg})


# --- ROTA INTELIGENTE CONVÊNIOS ---
@app.route("/api/auxiliares/convenios/deletar/<int:id>", methods=["DELETE"])
@login_required
def del_conv(id):
    with DB_WRITE_LOCK:
        conn = db.conectar()
        # Se tiver paciente usando este convênio, não pode excluir nem inativar facilmente
        uso = conn.execute(
            "SELECT id FROM pacientes WHERE convenio_id=? LIMIT 1", (id,)
        ).fetchone()
        if uso:
            conn.close()
            return (
                jsonify(
                    {
                        "erro": "Não é possível excluir: Existem pacientes vinculados a este convênio."
                    }
                ),
                400,
            )

        conn.execute("DELETE FROM convenios WHERE id=?", (id,))
        conn.commit()
        conn.close()
    return jsonify({"msg": "Convênio excluído"})


@app.route("/api/profissionais", methods=["GET"])
@login_required
def list_prof():
    conn = db.conectar(read_only=True)
    r = [
        dict(x)
        for x in conn.execute(
            "SELECT p.*, e.nome as esp_nome FROM profissionais p LEFT JOIN especialidades e ON p.especialidade_id=e.id ORDER BY p.nome"
        ).fetchall()
    ]
    conn.close()
    return jsonify(r)


@app.route("/api/profissionais/salvar", methods=["POST"])
@login_required
def save_prof():
    d = request.json

    if not d.get("nome"):
        return jsonify({"erro": "Nome é obrigatório"}), 400

    with DB_WRITE_LOCK:
        conn = db.conectar()

        # Verifica CPF
        if d.get("cpf"):
            check_cpf = conn.execute(
                "SELECT id FROM profissionais WHERE cpf=? AND ativo=1", (d.get("cpf"),)
            ).fetchone()
            if check_cpf and (
                not d.get("id") or str(check_cpf["id"]) != str(d.get("id"))
            ):
                conn.close()
                return (
                    jsonify({"erro": "CPF já cadastrado para outro profissional!"}),
                    400,
                )

        disp = json.dumps(d.get("dias", []))
        end = json.dumps(d.get("endereco", {}))
        bank = json.dumps(d.get("banco", {}))

        # ADICIONADO: d.get("foto", "") no final da tupla
        v = (
            d["nome"],
            d.get("crm"),
            d.get("cpf"),
            d.get("nasc"),
            d.get("esp_id"),
            d.get("email"),
            d.get("tel"),
            end,
            bank,
            d.get("cor", "#10B981"),
            d.get("comissao", 0),
            d.get("bio"),
            disp,
            d.get("ativo", 1),
            d.get("valor_padrao", 0),
            d.get("assinatura_path", ""),
            d.get("foto", ""),
        )

        if d.get("id"):
            # ADICIONADO: foto=? no SQL
            conn.execute(
                "UPDATE profissionais SET nome=?, crm=?, cpf=?, data_nascimento=?, especialidade_id=?, email=?, telefone=?, endereco=?, dados_bancarios=?, cor_agenda=?, comissao=?, bio=?, disponibilidade=?, ativo=?, valor_padrao=?, assinatura_path=?, foto=? WHERE id=?",
                v + (d["id"],),
            )
        else:
            # ADICIONADO: foto e ? no SQL
            conn.execute(
                "INSERT INTO profissionais (nome, crm, cpf, data_nascimento, especialidade_id, email, telefone, endereco, dados_bancarios, cor_agenda, comissao, bio, disponibilidade, ativo, valor_padrao, assinatura_path, foto) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                v,
            )

        conn.commit()
        conn.close()

    return jsonify({"msg": "Salvo"})


@app.route("/api/matriz_precos", methods=["GET"])
@login_required
def get_matriz_precos():
    conn = db.conectar(read_only=True)

    # 1. Busca todos os convênios ativos
    convs = [
        dict(c)
        for c in conn.execute("SELECT id, nome FROM convenios ORDER BY nome").fetchall()
    ]

    # 2. Busca todos os procedimentos
    procs = [
        dict(p)
        for p in conn.execute(
            "SELECT id, nome, codigo_tuss FROM procedimentos ORDER BY nome"
        ).fetchall()
    ]

    # 3. Busca todos os preços já cadastrados
    precos_db = conn.execute(
        "SELECT procedimento_id, convenio_id, valor FROM procedimento_precos"
    ).fetchall()

    conn.close()

    # Cria um dicionário para acesso rápido: precos_map['procID_convID'] = valor
    precos_map = {}
    for p in precos_db:
        chave = f"{p['procedimento_id']}_{p['convenio_id']}"
        precos_map[chave] = p["valor"]

    return jsonify({"convs": convs, "procs": procs, "mapa": precos_map})


@app.route("/api/matriz_precos/salvar", methods=["POST"])
@login_required
def save_matriz_precos():
    dados = request.json.get("alteracoes", [])  # Lista de {proc_id, conv_id, valor}

    with DB_WRITE_LOCK:
        conn = db.conectar()
        for item in dados:
            pid = item["proc_id"]
            cid = item["conv_id"]
            val = item["valor"]

            # Remove preço anterior
            conn.execute(
                "DELETE FROM procedimento_precos WHERE procedimento_id=? AND convenio_id=?",
                (pid, cid),
            )

            # Se tiver valor, insere o novo (se for 0 ou vazio, deixa deletado)
            if val and float(val) > 0:
                conn.execute(
                    "INSERT INTO procedimento_precos (procedimento_id, convenio_id, valor) VALUES (?,?,?)",
                    (pid, cid, val),
                )

        conn.commit()
        conn.close()

    return jsonify({"msg": "Matriz atualizada com sucesso!"})


@app.route("/api/agenda", methods=["GET"])
@login_required
def list_ag():
    hoje = datetime.now().strftime("%Y-%m-%d")
    dt_ini = request.args.get("inicio", hoje)
    dt_fim = request.args.get("fim", hoje)
    prof = request.args.get("prof_id")

    conn = db.conectar(read_only=True)

    # --- CORREÇÃO: Adicionado p.foto para aparecer no Cockpit ---
    q = """
        SELECT a.*, 
        COALESCE(p.nome, 'Desconhecido') as paciente, 
        p.foto as paciente_foto,  
        COALESCE(pr.nome, 'Desconhecido') as profissional 
        FROM agendamentos a 
        LEFT JOIN pacientes p ON a.paciente_id=p.id 
        LEFT JOIN profissionais pr ON a.profissional_id=pr.id 
        WHERE DATE(a.data_hora_inicio) BETWEEN ? AND ?
    """

    p = [dt_ini, dt_fim]
    if prof:
        q += " AND a.profissional_id=?"
        p.append(prof)

    # Ordena: Status 'Em Atendimento' primeiro, depois hora
    r = [
        dict(x) for x in conn.execute(q + " ORDER BY a.data_hora_inicio", p).fetchall()
    ]
    conn.close()
    return jsonify(r)


@app.route("/api/agenda/salvar", methods=["POST"])
@login_required
def save_ag():
    d = request.json

    if (
        not d.get("paciente_id")
        or not d.get("profissional_id")
        or not d.get("data")
        or not d.get("hora")
    ):
        return jsonify({"erro": "Campos obrigatórios"}), 400

    ini = datetime.strptime(f"{d['data']} {d['hora']}", "%Y-%m-%d %H:%M")
    fim = ini + timedelta(minutes=int(d.get("duracao", 30)))
    istr, fstr = ini.strftime("%Y-%m-%d %H:%M:%S"), fim.strftime("%Y-%m-%d %H:%M:%S")

    with DB_WRITE_LOCK:  # 🔒 Protege escrita
        conn = db.conectar()

        # Verifica conflito
        check = "SELECT id FROM agendamentos WHERE profissional_id=? AND status!='Cancelado' AND data_hora_inicio < ? AND data_hora_fim > ?"
        params = [d["profissional_id"], fstr, istr]
        if d.get("id"):
            check += " AND id!=?"
            params.append(d["id"])

        if conn.execute(check, params).fetchone():
            conn.close()
            return jsonify({"erro": "Horário indisponível"}), 409

        v = (
            d["paciente_id"],
            d["profissional_id"],
            istr,
            d.get("duracao", 30),
            fstr,
            "Agendado",
            d.get("tipo"),
            d.get("obs"),
            d.get("sala_id"),
        )

        if d.get("id"):
            conn.execute(
                "UPDATE agendamentos SET paciente_id=?, profissional_id=?, data_hora_inicio=?, duracao_minutos=?, data_hora_fim=?, status=?, tipo=?, observacoes=?, sala_id=? WHERE id=?",
                v + (d["id"],),
            )
        else:
            conn.execute(
                "INSERT INTO agendamentos (paciente_id, profissional_id, data_hora_inicio, duracao_minutos, data_hora_fim, status, tipo, observacoes, sala_id) VALUES (?,?,?,?,?,?,?,?,?)",
                v,
            )

        conn.commit()
        conn.close()

    # Atualiza cache
    atualizar_cache_tv()

    return jsonify({"msg": "Ok"})


@app.route("/api/agenda/deletar/<int:id>", methods=["DELETE"])
@login_required
def del_ag(id):
    with DB_WRITE_LOCK:  # 🔒 Protege escrita
        conn = db.conectar()
        conn.execute("DELETE FROM agendamentos WHERE id=?", (id,))
        conn.commit()
        conn.close()

    atualizar_cache_tv()
    return jsonify({"msg": "Deletado"})


@app.route("/api/agenda/status", methods=["POST"])
@login_required
def st_ag():
    d = request.json
    novo_status = d["status"]
    ag_id = d["id"]

    # Dados vindos do Checkout
    forma_pag = d.get("forma_pagamento")
    status_fin = d.get("status_financeiro", "Pendente")
    valor_final = d.get("valor_final")  # Permite ajustar o valor na hora H

    with DB_WRITE_LOCK:
        conn = db.conectar()

        # 1. Atualiza o status do agendamento
        # Se vier um valor novo (ex: desconto na hora), atualiza no agendamento também
        if valor_final:
            conn.execute(
                "UPDATE agendamentos SET status=?, valor=? WHERE id=?",
                (novo_status, valor_final, ag_id),
            )
        else:
            conn.execute(
                "UPDATE agendamentos SET status=? WHERE id=?", (novo_status, ag_id)
            )

        # 2. Lógica do Checkout (Só se for Finalizado e tiver valor)
        if novo_status == "Finalizado" and valor_final and float(valor_final) > 0:
            # Verifica se já gerou para não duplicar
            ag = conn.execute(
                "SELECT financeiro_gerado, paciente_id FROM agendamentos WHERE id=?",
                (ag_id,),
            ).fetchone()

            if ag and not ag["financeiro_gerado"]:
                # Dados para o financeiro
                pac = conn.execute(
                    "SELECT nome FROM pacientes WHERE id=?", (ag["paciente_id"],)
                ).fetchone()
                pac_nome = pac["nome"] if pac else "Paciente"

                dt_pag = (
                    datetime.now().strftime("%Y-%m-%d")
                    if status_fin == "Pago"
                    else None
                )
                val_pago = valor_final if status_fin == "Pago" else 0

                # Insere no Contas a Receber
                cursor = conn.execute(
                    "INSERT INTO contas_receber (paciente_id, descricao, valor_total, valor_pago, data_vencimento, data_pagamento, categoria, status, forma_pagamento, parcelas, parcela_atual) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        ag["paciente_id"],
                        f"Consulta: {pac_nome}",
                        valor_final,
                        val_pago,  # Se pago, entra cheio. Se pendente, entra 0
                        datetime.now().strftime("%Y-%m-%d"),
                        dt_pag,
                        "Consultas",
                        status_fin,  # "Pago" ou "Pendente"
                        forma_pag,
                        1,
                        1,
                    ),
                )

                # Se foi PAGO, lança também no CAIXA (Movimentação)
                if status_fin == "Pago":
                    rec_id = cursor.lastrowid
                    conn.execute(
                        "INSERT INTO caixa (tipo, valor, descricao, usuario, referencia_id, data_hora) VALUES (?,?,?,?,?,?)",
                        (
                            "Entrada",
                            valor_final,
                            f"Recebimento Consulta: {pac_nome}",
                            current_user.username,
                            rec_id,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        ),
                    )

                # Marca como gerado
                conn.execute(
                    "UPDATE agendamentos SET financeiro_gerado=1 WHERE id=?", (ag_id,)
                )

        conn.commit()
        conn.close()

    atualizar_cache_tv()
    return jsonify({"msg": "Ok"})


@app.route("/api/agenda/iniciar_atendimento_paciente", methods=["POST"])
@login_required
def ini_atend_pac():
    d = request.json
    h = datetime.now().strftime("%Y-%m-%d")

    with DB_WRITE_LOCK:  # 🔒 Protege escrita
        conn = db.conectar()

        ag = conn.execute(
            "SELECT id FROM agendamentos WHERE paciente_id=? AND data_hora_inicio BETWEEN ? AND ? AND status NOT IN ('Cancelado','Finalizado')",
            (d["id"], f"{h} 00:00:00", f"{h} 23:59:59"),
        ).fetchone()

        if ag:
            conn.execute(
                "UPDATE agendamentos SET status='Em Atendimento' WHERE id=?",
                (ag["id"],),
            )
        else:
            prof_id = d.get("prof_id")
            if not prof_id:
                p = conn.execute(
                    "SELECT id FROM profissionais WHERE ativo=1 LIMIT 1"
                ).fetchone()
                prof_id = p["id"] if p else 1

            now = datetime.now()
            ini_str = now.strftime("%Y-%m-%d %H:%M:%S")
            fim_str = (now + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")

            conn.execute(
                "INSERT INTO agendamentos (paciente_id, profissional_id, data_hora_inicio, duracao_minutos, data_hora_fim, status, tipo, observacoes) VALUES (?,?,?,?,?,?,?,?)",
                (
                    d["id"],
                    prof_id,
                    ini_str,
                    30,
                    fim_str,
                    "Em Atendimento",
                    "Encaixe",
                    "Criado via Atendimento",
                ),
            )

        conn.commit()
        conn.close()

    atualizar_cache_tv()
    return jsonify({"msg": "Atualizado"})


@app.route("/api/agendamento/transferir", methods=["POST"])
@login_required
def tr_ag():
    d = request.json
    # Monta as datas
    ini = datetime.strptime(f"{d['data']} {d['hora']}", "%Y-%m-%d %H:%M")
    fim = ini + timedelta(minutes=30)
    istr, fstr = ini.strftime("%Y-%m-%d %H:%M:%S"), fim.strftime("%Y-%m-%d %H:%M:%S")

    with DB_WRITE_LOCK:
        conn = db.conectar()

        # Verifica se o médico JÁ TEM alguém nesse horário (Excluindo o próprio agendamento)
        # status!='Cancelado' garante que horário vago (cancelado) possa ser usado
        conflito = conn.execute(
            "SELECT id FROM agendamentos WHERE profissional_id=? AND status!='Cancelado' AND id!=? AND ((data_hora_inicio < ? AND data_hora_fim > ?))",
            (d["profissional_id"], d["id"], fstr, istr),
        ).fetchone()

        if conflito:
            conn.close()
            return jsonify({"erro": "Horário Ocupado!"}), 409

        # Se livre, atualiza
        conn.execute(
            "UPDATE agendamentos SET profissional_id=?, data_hora_inicio=?, data_hora_fim=?, status='Agendado' WHERE id=?",
            (d["profissional_id"], istr, fstr, d["id"]),
        )
        conn.commit()
        conn.close()

    return jsonify({"msg": "Ok"})


@app.route("/api/financeiro/<t>", methods=["GET"])
@login_required
def list_fin(t):
    # Pega mês e ano da URL (Ex: /api/financeiro/receber?mes=11&ano=2025)
    mes = request.args.get("mes")
    ano = request.args.get("ano")

    conn = db.conectar(read_only=True)
    r = []

    # Filtro de Data (SQL)
    filtro_data = ""
    params = []

    if mes and ano:
        # Formata para buscar no SQLite (strftime)
        if t == "caixa":
            filtro_data = (
                " WHERE strftime('%m', data_hora) = ? AND strftime('%Y', data_hora) = ?"
            )
        else:
            filtro_data = " WHERE strftime('%m', data_vencimento) = ? AND strftime('%Y', data_vencimento) = ?"
        params = [f"{int(mes):02d}", ano]

    try:
        if t == "caixa":
            query = f"SELECT * FROM caixa {filtro_data} ORDER BY data_hora DESC"
            r = conn.execute(query, params).fetchall()
        elif t == "receber":
            query = f"SELECT c.*, p.nome as pessoa FROM contas_receber c LEFT JOIN pacientes p ON c.paciente_id=p.id {filtro_data} ORDER BY c.data_vencimento"
            r = conn.execute(query, params).fetchall()
        else:
            query = f"SELECT c.*, c.fornecedor as pessoa FROM contas_pagar c {filtro_data} ORDER BY c.data_vencimento"
            r = conn.execute(query, params).fetchall()
    except Exception as e:
        print(f"Erro Fin: {e}")
        r = []

    conn.close()
    return jsonify([dict(x) for x in r])


@app.route("/api/usuarios", methods=["GET"])
@login_required
def list_users():
    # Só admin pode ver lista de usuários
    if current_user.role != "admin":
        return jsonify({"erro": "Acesso negado"}), 403

    conn = db.conectar(read_only=True)
    # 🔥 Pega também a coluna permissoes
    users = [
        dict(u)
        for u in conn.execute(
            "SELECT id, username, role, permissoes FROM usuarios"
        ).fetchall()
    ]
    conn.close()
    return jsonify(users)


@app.route("/api/prontuario/retificar", methods=["POST"])
@login_required
def retificar_pr():
    d = request.json

    # Validação simples
    if not d.get("id") or not d.get("justificativa"):
        return jsonify({"erro": "Dados incompletos"}), 400

    usuario = current_user.username
    data_hoje = datetime.now().strftime("%d/%m/%Y às %H:%M")

    # Monta o texto com auditoria (Quem e Quando)
    nota = f"\n[RETIFICAÇÃO feita por {usuario} em {data_hoje}]:\n{d['justificativa']}"

    with DB_WRITE_LOCK:
        conn = db.conectar()
        # Concatena a nova nota ao que já existia (COALESCE garante que não quebre se for vazio)
        conn.execute(
            "UPDATE prontuarios SET retificacao = COALESCE(retificacao, '') || ? WHERE id=?",
            (nota, d["id"]),
        )
        conn.commit()
        conn.close()

    return jsonify({"msg": "Retificação anexada ao prontuário."})


@app.route("/api/usuarios/salvar", methods=["POST"])
@login_required
def save_user():
    # Só admin pode criar usuários
    if current_user.role != "admin":
        return jsonify({"erro": "Apenas admin pode gerenciar usuários"}), 403

    d = request.json
    username = d.get("username")
    password = d.get("password")
    role = d.get("role", "user")
    perms = json.dumps(d.get("perms", []))  # 🔥 Converte lista de checkboxes para texto

    if not username:
        return jsonify({"erro": "Nome de usuário obrigatório"}), 400

    with DB_WRITE_LOCK:
        conn = db.conectar()

        # Verifica se usuário já existe (apenas na criação)
        if not d.get("id"):
            exists = conn.execute(
                "SELECT id FROM usuarios WHERE username=?", (username,)
            ).fetchone()
            if exists:
                conn.close()
                return jsonify({"erro": "Usuário já existe"}), 400

        if d.get("id"):
            # Edição
            if password:
                pwd_hash = generate_password_hash(password)
                conn.execute(
                    "UPDATE usuarios SET username=?, password_hash=?, role=?, permissoes=? WHERE id=?",
                    (username, pwd_hash, role, perms, d["id"]),
                )
            else:
                conn.execute(
                    "UPDATE usuarios SET username=?, role=?, permissoes=? WHERE id=?",
                    (username, role, perms, d["id"]),
                )
        else:
            # Criação
            if not password:
                return jsonify({"erro": "Senha obrigatória para novo usuário"}), 400
            pwd_hash = generate_password_hash(password)
            conn.execute(
                "INSERT INTO usuarios (username, password_hash, role, permissoes) VALUES (?,?,?,?)",
                (username, pwd_hash, role, perms),
            )

        conn.commit()
        conn.close()

    return jsonify({"msg": "Usuário salvo com sucesso"})


@app.route("/api/usuarios/deletar/<int:id>", methods=["DELETE"])
@login_required
def del_user(id):
    if current_user.role != "admin":
        return jsonify({"erro": "Proibido"}), 403

    # Impede deletar a si mesmo ou o admin principal
    if str(id) == "1" or str(id) == str(current_user.id):
        return jsonify({"erro": "Não é possível excluir este usuário"}), 400

    with DB_WRITE_LOCK:
        conn = db.conectar()
        conn.execute("DELETE FROM usuarios WHERE id=?", (id,))
        conn.commit()
        conn.close()
    return jsonify({"msg": "Deletado"})


@app.route("/api/financeiro/salvar", methods=["POST"])
@login_required
def save_fin():
    try:
        d = request.json
        if not d.get("venc") or not d.get("cat"):
            return jsonify({"erro": "Preencha Vencimento e Categoria"}), 400

        t = d["tipo"]
        parc = int(d.get("parc", 1) or 1)

        # BLINDAGEM DE VALOR
        val_str = str(d.get("valor", "0")).replace(",", ".")
        if not val_str or val_str.strip() == "":
            val_str = "0"
        try:
            val = float(val_str) / parc
        except:
            return jsonify({"erro": "Valor inválido"}), 400

        dt = datetime.strptime(d["venc"], "%Y-%m-%d")

        with DB_WRITE_LOCK:
            conn = db.conectar()

            for i in range(parc):
                venc = (dt + timedelta(days=30 * i)).strftime("%Y-%m-%d")
                desc = f"{d['desc']} ({i+1}/{parc})" if parc > 1 else d["desc"]
                params = (
                    d.get("paciente_id") if t == "receber" else d.get("fornecedor"),
                    desc,
                    val,
                    venc,
                    d["cat"],
                    d.get("cc", ""),
                    d.get("forma", ""),
                    parc,
                    i + 1,
                )
                if t == "receber":
                    conn.execute(
                        "INSERT INTO contas_receber (paciente_id, descricao, valor_total, data_vencimento, categoria, centro_custo, forma_pagamento, parcelas, parcela_atual) VALUES (?,?,?,?,?,?,?,?,?)",
                        params,
                    )
                else:
                    conn.execute(
                        "INSERT INTO contas_pagar (fornecedor, descricao, valor_total, data_vencimento, categoria, centro_custo, forma_pagamento, parcelas, parcela_atual) VALUES (?,?,?,?,?,?,?,?,?)",
                        params,
                    )
            conn.commit()
            conn.close()

        return jsonify({"msg": "Ok"})
    except Exception as e:
        print(f"Erro financeiro: {e}")  # Log no console
        return jsonify({"erro": f"Erro ao salvar: {str(e)}"}), 500


@app.route("/api/upload", methods=["POST"])
@login_required
def upload_arquivo():
    if "file" not in request.files:
        return jsonify({"erro": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"erro": "Nome vazio"}), 400

    if file:
        ext = os.path.splitext(file.filename)[1]
        novo_nome = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{int(time.time())}{ext}"
        caminho = os.path.join(app.config["UPLOAD_FOLDER"], novo_nome)
        file.save(caminho)
        return jsonify(
            {"msg": "Sucesso", "arquivo": novo_nome, "url": f"/uploads/{novo_nome}"}
        )


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/api/modelos", methods=["GET"])
@login_required
def list_modelos():
    tipo = request.args.get("tipo")
    conn = db.conectar(read_only=True)
    if tipo:
        r = [
            dict(x)
            for x in conn.execute(
                "SELECT * FROM modelos_documentos WHERE tipo=?", (tipo,)
            ).fetchall()
        ]
    else:
        r = [
            dict(x) for x in conn.execute("SELECT * FROM modelos_documentos").fetchall()
        ]
    conn.close()
    return jsonify(r)


@app.route("/api/modelos/salvar", methods=["POST"])
@login_required
def save_modelo():
    d = request.json
    with DB_WRITE_LOCK:
        conn = db.conectar()
        if d.get("id"):
            conn.execute(
                "UPDATE modelos_documentos SET nome=?, conteudo=? WHERE id=?",
                (d["nome"], d["conteudo"], d["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO modelos_documentos (tipo, nome, conteudo) VALUES (?,?,?)",
                (d["tipo"], d["nome"], d["conteudo"]),
            )
        conn.commit()
        conn.close()
    return jsonify({"msg": "Modelo salvo"})


@app.route("/api/modelos/deletar/<int:id>", methods=["DELETE"])
@login_required
def del_modelo(id):
    with DB_WRITE_LOCK:
        conn = db.conectar()
        conn.execute("DELETE FROM modelos_documentos WHERE id=?", (id,))
        conn.commit()
        conn.close()
    return jsonify({"msg": "Deletado"})


@app.route("/api/profissionais/publico")
def list_prof_publico():
    """Versão pública de profissionais (sem login)"""
    conn = db.conectar(read_only=True)
    r = [
        dict(x)
        for x in conn.execute(
            "SELECT p.*, e.nome as esp_nome FROM profissionais p LEFT JOIN especialidades e ON p.especialidade_id=e.id ORDER BY p.nome"
        ).fetchall()
    ]
    conn.close()
    return jsonify(r)


@app.route("/api/pacientes")
@login_required
def list_pacientes_geral():
    filtro = request.args.get("filtro", "")
    conn = db.conectar(read_only=True)

    if filtro:
        busca = f"%{filtro}%"
        query = """
            SELECT * FROM pacientes 
            WHERE nome LIKE ? OR cpf LIKE ? OR telefone_principal LIKE ? 
            ORDER BY nome LIMIT 50
        """
        r = [dict(x) for x in conn.execute(query, (busca, busca, busca)).fetchall()]
    else:
        r = [
            dict(x)
            for x in conn.execute(
                "SELECT * FROM pacientes ORDER BY nome LIMIT 100"
            ).fetchall()
        ]

    conn.close()
    return jsonify(r)


@app.route("/api/pacientes/publico")
def list_pacientes_publico():
    """Versão pública de pacientes (sem login) - apenas para TV"""
    conn = db.conectar(read_only=True)
    r = [
        dict(x)
        for x in conn.execute(
            "SELECT * FROM pacientes ORDER BY nome LIMIT 100"
        ).fetchall()
    ]
    conn.close()
    return jsonify(r)


@app.route("/api/financeiro/baixar", methods=["POST"])
@login_required
def baixa_fin():
    d = request.json
    tab = f"contas_{d['tipo']}"

    with DB_WRITE_LOCK:  # 🔒 Protege escrita
        conn = db.conectar()
        c = conn.execute(f"SELECT * FROM {tab} WHERE id=?", (d["id"],)).fetchone()
        np = float(c["valor_pago"]) + float(d["valor_pago"])
        st = "Pago" if np >= float(c["valor_total"]) - 0.1 else "Parcial"
        conn.execute(
            f"UPDATE {tab} SET status=?, valor_pago=?, data_pagamento=? WHERE id=?",
            (st, np, datetime.now().strftime("%Y-%m-%d"), d["id"]),
        )
        conn.execute(
            "INSERT INTO caixa (tipo, valor, descricao, usuario, referencia_id) VALUES (?,?,?,?,?)",
            (
                "Entrada" if d["tipo"] == "receber" else "Saída",
                d["valor_pago"],
                f"Baixa: {c['descricao']}",
                current_user.username,
                d["id"],
            ),
        )
        conn.commit()
        conn.close()

    return jsonify({"msg": "Ok"})


@app.route("/api/auxiliares/<t>", methods=["GET"])
@login_required
def list_ax(t):
    if t not in ["especialidades", "salas", "procedimentos", "convenios"]:
        return jsonify([])

    # MUDANÇA: Usamos conexão normal (sem read_only) para garantir dados frescos
    conn = db.conectar()

    r = [dict(x) for x in conn.execute(f"SELECT * FROM {t} ORDER BY nome").fetchall()]
    conn.close()
    return jsonify(r)


@app.route("/api/auxiliares/<t>/salvar", methods=["POST"])
@login_required
def save_ax(t):
    # Proteção: Se não enviar o nome ou for vazio
    if not request.json or "nome" not in request.json:
        return jsonify({"erro": "Nome é obrigatório"}), 400

    nome = request.json["nome"].strip()  # Remove espaços extras

    if not nome:
        return jsonify({"erro": "O nome não pode estar vazio"}), 400

    with DB_WRITE_LOCK:
        conn = db.conectar()
        # TRAVA: Verifica se já existe item com esse nome na tabela
        check = conn.execute(f"SELECT id FROM {t} WHERE nome=?", (nome,)).fetchone()
        if check:
            conn.close()
            return jsonify({"erro": "Item já cadastrado!"}), 400

        conn.execute(f"INSERT INTO {t} (nome) VALUES (?)", (nome,))
        conn.commit()
        conn.close()
    return jsonify({"msg": "Ok"})


@app.route("/api/auxiliares/<t>/deletar/<int:id>", methods=["DELETE"])
@login_required
def del_ax(t, id):
    with DB_WRITE_LOCK:  # 🔒 Protege escrita
        conn = db.conectar()
        conn.execute(f"DELETE FROM {t} WHERE id=?", (id,))
        conn.commit()
        conn.close()
    return jsonify({"msg": "Ok"})


@app.route("/api/convenios", methods=["GET"])
@login_required
def list_conv():
    # CORREÇÃO: Usamos db.conectar() sem read_only=True
    # Isso garante que ele veja o convênio que acabou de ser salvo
    conn = db.conectar()

    r = [
        dict(x)
        for x in conn.execute("SELECT * FROM convenios ORDER BY nome").fetchall()
    ]
    conn.close()
    return jsonify(r)


@app.route("/api/convenios/salvar", methods=["POST"])
@login_required
def save_conv():
    d = request.json
    # Adicionei d.get('tabela') no final da lista de valores
    v = (
        d["nome"],
        d.get("ans"),
        d.get("cnpj"),
        d.get("prazo", 30),
        d.get("tel"),
        d.get("email"),
        d.get("site"),
        d.get("tabela"),
    )

    with DB_WRITE_LOCK:
        conn = db.conectar()

        # Validação de duplicidade (Mantive a lógica inteligente que fizemos antes)
        if not d.get("id"):
            check_nome = conn.execute(
                "SELECT id FROM convenios WHERE nome=?", (d["nome"],)
            ).fetchone()
            if check_nome:
                conn.close()
                return jsonify({"erro": "Já existe um convênio com esse nome!"}), 400

            if d.get("cnpj") and len(d.get("cnpj")) > 5:
                check_cnpj = conn.execute(
                    "SELECT id FROM convenios WHERE cnpj=?", (d.get("cnpj"),)
                ).fetchone()
                if check_cnpj:
                    conn.close()
                    return jsonify({"erro": "CNPJ já cadastrado!"}), 400

        if d.get("id"):
            # Adicionei arquivo_tabela=? no UPDATE
            conn.execute(
                "UPDATE convenios SET nome=?, registro_ans=?, cnpj=?, prazo_pagamento=?, telefone=?, email=?, site=?, arquivo_tabela=? WHERE id=?",
                v + (d["id"],),
            )
        else:
            # Adicionei arquivo_tabela e ? no INSERT
            conn.execute(
                "INSERT INTO convenios (nome, registro_ans, cnpj, prazo_pagamento, telefone, email, site, arquivo_tabela) VALUES (?,?,?,?,?,?,?,?)",
                v,
            )

        conn.commit()
        conn.close()

    return jsonify({"msg": "Ok"})


@app.route("/api/prontuario/<int:id>", methods=["GET"])
@login_required
def list_pr(id):
    conn = db.conectar(read_only=True)
    # CORREÇÃO: Mudado de JOIN para LEFT JOIN para não perder histórico se médico for excluído
    r = [
        dict(x)
        for x in conn.execute(
            "SELECT p.*, COALESCE(prof.nome, 'Profissional Excluído') as profissional FROM prontuarios p LEFT JOIN profissionais prof ON p.profissional_id=prof.id WHERE p.paciente_id=? ORDER BY p.data_atendimento DESC",
            (id,),
        ).fetchall()
    ]
    conn.close()
    return jsonify(r)


@app.route("/api/prontuario/salvar", methods=["POST"])
@login_required
def save_pr():
    d = request.json

    with DB_WRITE_LOCK:
        conn = db.conectar()

        # Monta a "Evolução Resumo" juntando o SOAP para manter compatibilidade com relatórios antigos
        evolucao_texto = d.get("evolucao")  # Se vier o texto antigo
        if not evolucao_texto:
            # Se for SOAP, monta um texto legível
            s = d.get("subjetivo", "")
            o = d.get("objetivo", "")
            a = d.get("avaliacao", "")
            p = d.get("plano", "")
            evolucao_texto = f"S: {s}\nO: {o}\nA: {a}\nP: {p}"

        conn.execute(
            """INSERT INTO prontuarios 
            (paciente_id, profissional_id, data_atendimento, evolucao_clinica, diagnostico, prescricao, 
            exames_solicitados, peso, altura, pressao, temp, saturacao, anexos,
            queixa_principal, subjetivo, objetivo, avaliacao, plano, conduta, retorno) 
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                d["paciente_id"],
                d["profissional_id"],
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                evolucao_texto,  # Salva o resumo na coluna antiga
                d.get("diagnostico"),
                d.get("prescricao"),
                d.get("exames"),
                d.get("peso"),
                d.get("altura"),
                d.get("pressao"),
                d.get("temp"),
                d.get("saturacao"),
                d.get("anexos"),
                # Novos campos SOAP
                d.get("queixa_principal"),
                d.get("subjetivo"),
                d.get("objetivo"),
                d.get("avaliacao"),
                d.get("plano"),
                d.get("conduta"),
                d.get("retorno"),
            ),
        )

        if d.get("alergias"):
            conn.execute(
                "UPDATE pacientes SET alergias=? WHERE id=?",
                (d["alergias"], d["paciente_id"]),
            )

        conn.commit()
        conn.close()

    return jsonify({"msg": "Ok"})


@app.route("/api/relatorios/gerar", methods=["POST"])
@login_required
def rel():
    d = request.json
    conn = db.conectar(read_only=True)
    ini, fim = d["inicio"], d["fim"]
    response = {"lista": [], "resumo": {}}

    try:
        if d["tipo"] == "agendamentos":
            response["lista"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT a.data_hora_inicio, p.nome as paciente, pr.nome as profissional, a.status, a.valor FROM agendamentos a JOIN pacientes p ON a.paciente_id=p.id JOIN profissionais pr ON a.profissional_id=pr.id WHERE DATE(a.data_hora_inicio) BETWEEN ? AND ? ORDER BY a.data_hora_inicio",
                    (ini, fim),
                ).fetchall()
            ]
            stats = conn.execute(
                "SELECT status, COUNT(*) as qtd, SUM(valor) as total FROM agendamentos WHERE DATE(data_hora_inicio) BETWEEN ? AND ? GROUP BY status",
                (ini, fim),
            ).fetchall()
            response["resumo"] = {
                "labels": [s["status"] for s in stats],
                "data": [s["qtd"] for s in stats],
                "total_valor": sum([s["total"] or 0 for s in stats]),
                "total_qtd": sum([s["qtd"] for s in stats]),
            }

        elif d["tipo"] == "financeiro":
            r_in = conn.execute(
                "SELECT data_vencimento as data, descricao, categoria, 'Receita' as tipo, valor_total as valor, forma_pagamento FROM contas_receber WHERE data_vencimento BETWEEN ? AND ? AND status='Pago'",
                (ini, fim),
            ).fetchall()
            r_out = conn.execute(
                "SELECT data_vencimento as data, descricao, categoria, 'Despesa' as tipo, valor_total as valor, forma_pagamento FROM contas_pagar WHERE data_vencimento BETWEEN ? AND ? AND status='Pago'",
                (ini, fim),
            ).fetchall()
            full_list = [dict(x) for x in r_in] + [dict(x) for x in r_out]
            full_list.sort(key=lambda x: x["data"])
            response["lista"] = full_list
            total_rec = sum([x["valor"] for x in full_list if x["tipo"] == "Receita"])
            total_desp = sum([x["valor"] for x in full_list if x["tipo"] == "Despesa"])
            cats = conn.execute(
                "SELECT categoria, SUM(valor_total) as total FROM contas_receber WHERE status='Pago' AND data_vencimento BETWEEN ? AND ? GROUP BY categoria ORDER BY total DESC LIMIT 5",
                (ini, fim),
            ).fetchall()
            response["resumo"] = {
                "receita": total_rec,
                "despesa": total_desp,
                "saldo": total_rec - total_desp,
                "cat_labels": [c["categoria"] for c in cats],
                "cat_values": [c["total"] for c in cats],
            }

        elif d["tipo"] == "profissionais":
            response["lista"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT pr.nome as profissional, COUNT(a.id) as atendimentos, SUM(CASE WHEN a.status='Finalizado' THEN 1 ELSE 0 END) as finalizados, SUM(CASE WHEN a.status='Finalizado' THEN a.valor ELSE 0 END) as faturamento_est FROM agendamentos a JOIN profissionais pr ON a.profissional_id=pr.id WHERE DATE(a.data_hora_inicio) BETWEEN ? AND ? GROUP BY pr.nome ORDER BY faturamento_est DESC",
                    (ini, fim),
                ).fetchall()
            ]
            response["resumo"] = {
                "labels": [x["profissional"] for x in response["lista"]],
                "data_atend": [x["atendimentos"] for x in response["lista"]],
                "data_fat": [x["faturamento_est"] or 0 for x in response["lista"]],
            }

        # --- NOVO: REPASSE MÉDICO ---
        elif d["tipo"] == "repasse":
            rows = conn.execute(
                """
                SELECT pr.nome, pr.comissao, COUNT(a.id) as qtd_atendimentos, SUM(a.valor) as total_produzido, (SUM(a.valor) * (pr.comissao / 100.0)) as valor_repasse
                FROM agendamentos a JOIN profissionais pr ON a.profissional_id = pr.id
                WHERE a.status = 'Finalizado' AND DATE(a.data_hora_inicio) BETWEEN ? AND ?
                GROUP BY pr.id
            """,
                (ini, fim),
            ).fetchall()
            response["lista"] = [dict(r) for r in rows]
            total_prod = sum([r["total_produzido"] or 0 for r in response["lista"]])
            total_rep = sum([r["valor_repasse"] or 0 for r in response["lista"]])
            response["resumo"] = {
                "total_produzido": total_prod,
                "total_repasse": total_rep,
                "lucro_bruto": total_prod - total_rep,
            }

        # --- NOVO: FECHAMENTO DE CAIXA ---
        elif d["tipo"] == "fechamento":
            pagamentos = conn.execute(
                "SELECT forma_pagamento, SUM(valor_total) as total FROM contas_receber WHERE status='Pago' AND data_pagamento BETWEEN ? AND ? GROUP BY forma_pagamento",
                (ini, fim),
            ).fetchall()
            saidas = (
                conn.execute(
                    "SELECT SUM(valor_pago) FROM contas_pagar WHERE data_pagamento BETWEEN ? AND ?",
                    (ini, fim),
                ).fetchone()[0]
                or 0
            )
            response["lista"] = [dict(r) for r in pagamentos]
            total_entradas = sum([r["total"] for r in pagamentos])
            response["resumo"] = {
                "total_entradas": total_entradas,
                "total_saidas": saidas,
                "saldo_periodo": total_entradas - saidas,
            }

        elif d["tipo"] == "pacientes":
            response["lista"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT nome, cpf, telefone_principal, email, created_at as cadastro FROM pacientes ORDER BY nome"
                ).fetchall()
            ]
            response["resumo"] = {"total": len(response["lista"])}

        elif d["tipo"] == "convenios":
            response["lista"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT c.nome as convenio, COUNT(a.id) as atendimentos FROM agendamentos a JOIN pacientes p ON a.paciente_id=p.id JOIN convenios c ON p.convenio_id=c.id WHERE DATE(a.data_hora_inicio) BETWEEN ? AND ? GROUP BY c.nome ORDER BY atendimentos DESC",
                    (ini, fim),
                ).fetchall()
            ]
            response["resumo"] = {
                "labels": [x["convenio"] for x in response["lista"]],
                "data": [x["atendimentos"] for x in response["lista"]],
            }

        elif d["tipo"] == "aniversariantes":
            mes = datetime.strptime(ini, "%Y-%m-%d").strftime("%m")
            response["lista"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT nome, strftime('%d/%m', data_nascimento) as dia, telefone_principal FROM pacientes WHERE strftime('%m', data_nascimento) = ? ORDER BY strftime('%d', data_nascimento)",
                    (mes,),
                ).fetchall()
            ]

    except Exception as e:
        print("Erro Rel:", e)
        traceback.print_exc()
    finally:
        conn.close()
    return jsonify(response)


@app.route("/tv")
def tv_screen():
    return send_from_directory(BASE_DIR, "tv.html")


@app.route("/debug/db")
def debug_db():
    import glob

    app_data = os.getenv("APPDATA", "")
    locais = [os.path.join(BASE_DIR, "*.db"), os.path.join(os.getcwd(), "*.db")]

    if app_data:
        locais.append(os.path.join(app_data, "ClinicaSysPro", "*.db"))

    encontrados = []

    for p in locais:
        try:
            encontrados.extend(glob.glob(p))
        except:
            pass

    info = f"<h1>🔍 Diagnóstico de Banco de Dados</h1>"
    info += f"<p><b>Pasta Base (BASE_DIR):</b> {BASE_DIR}</p>"
    info += f"<p><b>Pasta de Dados Atual (DATA_DIR):</b> {DATA_DIR}</p>"

    try:
        info += f"<p style='color:green;font-size:1.2rem'><b>✅ Banco ATIVO agora:</b> {db.db_path}</p>"

        # Mostra quantos registros tem no banco ativo
        conn = db.conectar(read_only=True)
        pacientes = conn.execute("SELECT COUNT(*) FROM pacientes").fetchone()[0]
        agendamentos = conn.execute("SELECT COUNT(*) FROM agendamentos").fetchone()[0]
        conn.close()

        info += f"<p><b>📊 Dados no banco ativo:</b></p>"
        info += f"<ul><li>Pacientes: {pacientes}</li><li>Agendamentos: {agendamentos}</li></ul>"
    except Exception as e:
        info += f"<p style='color:red'><b>❌ Erro ao ler banco:</b> {e}</p>"

    info += "<hr><h3>📂 Arquivos .db encontrados:</h3><ul>"

    if not encontrados:
        info += "<li><i>Nenhum banco encontrado</i></li>"

    banco_com_dados = None
    max_registros = 0

    for f in encontrados:
        try:
            tamanho = os.path.getsize(f) / 1024
            # Verifica se é o banco ativo
            ativo = " ✅ <b>(ESTE ESTÁ SENDO USADO)</b>" if f == db.db_path else ""

            # Conta registros de cada banco
            try:
                conn_test = sqlite3.connect(f"file:{f}?mode=ro", uri=True)
                p_count = conn_test.execute(
                    "SELECT COUNT(*) FROM pacientes"
                ).fetchone()[0]
                a_count = conn_test.execute(
                    "SELECT COUNT(*) FROM agendamentos"
                ).fetchone()[0]
                conn_test.close()

                # Identifica o banco com mais dados
                total = p_count + a_count
                if total > max_registros and f != db.db_path:
                    max_registros = total
                    banco_com_dados = f

                info += f"<li>📂 <b>{f}</b> - {tamanho:.2f} KB {ativo}<br>&nbsp;&nbsp;&nbsp;→ {p_count} pacientes, {a_count} agendamentos</li>"
            except:
                info += f"<li>📂 <b>{f}</b> - {tamanho:.2f} KB {ativo}</li>"

        except Exception as e:
            info += f"<li>📂 <b>{f}</b> - Erro: {e}</li>"

    info += "</ul>"

    # 🔥 BOTÃO DE CORREÇÃO AUTOMÁTICA
    if banco_com_dados:
        info += f"<hr><div style='background:#fee;padding:20px;border-radius:8px;border:2px solid #f00'>"
        info += f"<h2>⚠️ PROBLEMA DETECTADO!</h2>"
        info += f"<p>O sistema está usando um banco VAZIO, mas existe outro com dados em:</p>"
        info += f"<p style='font-family:monospace;background:#fff;padding:10px'>{banco_com_dados}</p>"
        info += f"<form method='POST' action='/debug/fix-db' style='margin-top:20px'>"
        info += f"<input type='hidden' name='source' value='{banco_com_dados}'>"
        info += f"<button type='submit' style='background:#f00;color:#fff;padding:15px 30px;border:none;border-radius:8px;font-size:1.2rem;cursor:pointer;font-weight:bold'>🔧 CORRIGIR AGORA (Copiar dados)</button>"
        info += f"</form>"
        info += f"</div>"
    else:
        info += "<hr><p style='color:green'>✅ Tudo certo! O banco ativo tem dados.</p>"

    info += "<hr><p><b>💡 Dica:</b> Se você ver DOIS bancos com dados diferentes, o sistema está dividido!</p>"

    return info


@app.route("/debug/fix-db", methods=["POST"])
def fix_db():
    """🔧 Copia o banco com dados para o local correto"""
    source = request.form.get("source")

    if not source or not os.path.exists(source):
        return "<h1>❌ Erro: Banco de origem não encontrado!</h1>"

    try:
        # Faz backup do banco atual (vazio)
        if os.path.exists(db.db_path):
            backup_path = db.db_path + ".backup_vazio"
            shutil.copy2(db.db_path, backup_path)

        # Copia o banco com dados
        shutil.copy2(source, db.db_path)

        # Força reinicialização do cache
        atualizar_cache_tv()

        return f"""
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family:sans-serif;padding:40px;text-align:center">
            <h1 style="color:green">✅ BANCO CORRIGIDO COM SUCESSO!</h1>
            <p>O banco com dados foi copiado para o local correto.</p>
            <p><b>Origem:</b> {source}</p>
            <p><b>Destino:</b> {db.db_path}</p>
            <hr>
            <h2>⚠️ PRÓXIMO PASSO IMPORTANTE:</h2>
            <p style="font-size:1.2rem;color:#f00;font-weight:bold">FECHE TUDO e REABRA o sistema!</p>
            <br>
            <button onclick="window.close()" style="padding:15px 30px;background:#10b981;color:#fff;border:none;border-radius:8px;font-size:1.1rem;cursor:pointer">Fechar esta janela</button>
        </body>
        </html>
        """
    except Exception as e:
        return f"<h1>❌ Erro ao copiar banco:</h1><pre>{e}</pre>"


@app.route("/api/agenda/chamar_painel", methods=["POST"])
@login_required
def chamar_painel():
    d = request.json
    if not d.get("id"):
        return jsonify({"erro": "ID inválido"}), 400

    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with DB_WRITE_LOCK:
        conn = db.conectar()
        # Verifica se atualizou alguma linha
        cursor = conn.execute(
            "UPDATE agendamentos SET status='Em Atendimento', data_chamada=? WHERE id=?",
            (agora, d["id"]),
        )
        linhas_afetadas = cursor.rowcount
        conn.commit()
        conn.close()

    if linhas_afetadas == 0:
        return jsonify({"erro": "Agendamento não encontrado"}), 404

    atualizar_cache_tv()
    return jsonify({"msg": "Chamado"})


@app.route("/api/exportar/<tipo>")
@login_required
def exportar(tipo):
    conn = db.conectar(read_only=True)
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    cursor = None
    try:
        if tipo == "financeiro":
            cursor = conn.execute(
                "SELECT data_vencimento, descricao, categoria, valor_total, status, 'Receita' as tipo FROM contas_receber UNION ALL SELECT data_vencimento, descricao, categoria, valor_total, status, 'Despesa' as tipo FROM contas_pagar ORDER BY data_vencimento"
            )
            writer.writerow(
                ["Data", "Descrição", "Categoria", "Valor", "Status", "Tipo"]
            )
        elif tipo == "pacientes":
            cursor = conn.execute(
                "SELECT nome, cpf, telefone_principal, email, endereco FROM pacientes"
            )
            writer.writerow(["Nome", "CPF", "Telefone", "Email", "Endereço"])
        elif tipo == "agendamentos":
            cursor = conn.execute(
                "SELECT a.data_hora_inicio, p.nome, pr.nome, a.status, a.valor FROM agendamentos a JOIN pacientes p ON a.paciente_id=p.id JOIN profissionais pr ON a.profissional_id=pr.id ORDER BY a.data_hora_inicio DESC"
            )
            writer.writerow(
                ["Data/Hora", "Paciente", "Profissional", "Status", "Valor"]
            )
        elif tipo == "profissionais":
            cursor = conn.execute(
                "SELECT nome, crm, telefone, email, especialidade_id FROM profissionais"
            )
            writer.writerow(["Nome", "CRM", "Telefone", "Email", "Especialidade (ID)"])
        # NOVO: EXPORTAÇÃO DE REPASSE
        elif tipo == "repasse_geral":
            cursor = conn.execute(
                "SELECT pr.nome, pr.comissao, COUNT(a.id), SUM(a.valor), (SUM(a.valor)*(pr.comissao/100.0)) FROM agendamentos a JOIN profissionais pr ON a.profissional_id = pr.id WHERE a.status='Finalizado' GROUP BY pr.id"
            )
            writer.writerow(
                [
                    "Profissional",
                    "Comissao %",
                    "Qtd Atendimentos",
                    "Total Produzido",
                    "Valor Repasse",
                ]
            )
        else:
            return jsonify({"erro": "Tipo inválido"}), 400

        if cursor:
            writer.writerows(cursor.fetchall())
    except Exception as e:
        print(f"Erro exportação: {e}")
        return jsonify({"erro": "Falha ao exportar"}), 500
    finally:
        conn.close()

    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-disposition": f"attachment; filename={tipo}_{datetime.now().strftime('%Y%m%d')}.csv"
        },
    )


class Api:
    def abrir_tv(self):
        # 1. Procura se já existe uma janela chamada "Painel TV - ClínicaSys"
        for w in webview.windows:
            if w.title == "Painel TV - ClínicaSys":
                try:
                    w.restore()
                    w.focus()
                    return "Janela já aberta"
                except:
                    pass

        # 2. Se não existe, cria uma nova
        webview.create_window(
            "Painel TV - ClínicaSys", "http://localhost:5000/tv", width=1000, height=700
        )
        return "Nova janela criada"

    def salvar_pdf(self, nome_arquivo, dados_base64):
        import webview
        import base64
        import os

        # Abre a janela nativa do Windows para escolher onde salvar
        caminho_escolhido = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=nome_arquivo,
            file_types=("Documentos PDF (*.pdf)", "Todos os arquivos (*.*)"),
        )

        if caminho_escolhido:
            try:
                # O PyWebview retorna uma lista, pegamos o primeiro item
                caminho_final = (
                    caminho_escolhido[0]
                    if isinstance(caminho_escolhido, (tuple, list))
                    else caminho_escolhido
                )

                # Decodifica o Base64 que veio do Javascript e salva como binário (wb)
                dados = base64.b64decode(dados_base64)
                with open(caminho_final, "wb") as f:
                    f.write(dados)

                # Tenta abrir o PDF automaticamente para o usuário ver
                try:
                    os.startfile(caminho_final)
                except:
                    pass

                return "✅ Recibo salvo e aberto com sucesso!"
            except Exception as e:
                return f"❌ Erro ao salvar: {str(e)}"

        return "Cancelado"

    def salvar_arquivo(self, nome_arquivo, conteudo):
        """
        Função que faltava para salvar o CSV/Excel
        """
        import webview
        import os

        # Janela de salvar arquivo
        caminho_escolhido = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=nome_arquivo,
            file_types=("Planilha CSV (*.csv)", "Todos os arquivos (*.*)"),
        )

        if caminho_escolhido:
            try:
                caminho_final = (
                    caminho_escolhido[0]
                    if isinstance(caminho_escolhido, (tuple, list))
                    else caminho_escolhido
                )

                # Salva o texto (utf-8-sig ajuda o Excel a ler acentos corretamente)
                with open(caminho_final, "w", encoding="utf-8-sig") as f:
                    f.write(conteudo)

                # Tenta abrir o arquivo automaticamente
                try:
                    os.startfile(caminho_final)
                except:
                    pass

                return "✅ Relatório exportado com sucesso!"
            except Exception as e:
                return f"❌ Erro ao salvar: {str(e)}"

        return "Cancelado"


@app.route("/api/agenda/resumo_qtd", methods=["GET"])
@login_required
def cal_resumo_qtd():
    prof_id = request.args.get("prof_id")  # <--- Captura o filtro
    conn = db.conectar(read_only=True)

    # Monta a query base
    sql = "SELECT DATE(data_hora_inicio) as dia, COUNT(*) as total FROM agendamentos WHERE status != 'Cancelado'"
    params = []

    # Se tiver filtro de médico, adiciona na contagem
    if prof_id:
        sql += " AND profissional_id = ?"
        params.append(prof_id)

    sql += " GROUP BY DATE(data_hora_inicio)"

    rows = conn.execute(sql, params).fetchall()
    conn.close()

    eventos = []
    for r in rows:
        total = r["total"]
        cor = "#10B981"
        if total > 5:
            cor = "#3B82F6"
        if total > 10:
            cor = "#F59E0B"

        eventos.append(
            {
                "title": f"{total} agend.",
                "start": r["dia"],
                "allDay": True,
                "backgroundColor": cor,
                "borderColor": cor,
                "classNames": ["evento-contador"],
            }
        )

    return jsonify(eventos)


@app.route("/api/recibo/<int:ag_id>")
@login_required
def gerar_recibo_pdf(ag_id):
    conn = db.conectar(read_only=True)
    # Busca dados do agendamento, paciente e profissional
    query = """
        SELECT a.*, p.nome as paciente, p.cpf, pr.nome as profissional, pr.crm 
        FROM agendamentos a 
        JOIN pacientes p ON a.paciente_id=p.id 
        JOIN profissionais pr ON a.profissional_id=pr.id 
        WHERE a.id = ?
    """
    dados = conn.execute(query, (ag_id,)).fetchone()
    conf = conn.execute("SELECT * FROM configuracoes").fetchone()
    conn.close()

    if not dados:
        return "Agendamento não encontrado", 404

    # Cria o PDF na memória
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)

    # Cabeçalho
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 800, conf["nome_clinica"] if conf else "Minha Clínica")
    c.setFont("Helvetica", 10)
    c.drawString(50, 785, conf["endereco"] if conf else "")
    c.drawString(50, 770, f"Tel: {conf['telefone'] if conf else ''}")

    c.line(50, 760, 550, 760)

    # Título
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(300, 720, "RECIBO")

    # Corpo
    valor = f"R$ {dados['valor']:.2f}".replace(".", ",")
    texto_valor = f"Recebemos de {dados['paciente']} (CPF: {dados['cpf'] or 'N/I'})"
    texto_referente = f"A importância de {valor} referente a consulta médica."

    c.setFont("Helvetica", 12)
    c.drawString(50, 650, texto_valor)
    c.drawString(50, 630, texto_referente)
    c.drawString(
        50,
        610,
        f"Data do atendimento: {datetime.strptime(dados['data_hora_inicio'], '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y')}",
    )
    c.drawString(
        50, 590, f"Profissional: {dados['profissional']} - CRM: {dados['crm']}"
    )

    # Data e Assinatura
    c.drawString(300, 500, f"Data da emissão: {datetime.now().strftime('%d/%m/%Y')}")
    c.line(300, 450, 500, 450)
    c.drawString(300, 435, "Assinatura / Carimbo")

    c.save()
    buffer.seek(0)

    return Response(
        buffer,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"inline; filename=recibo_{ag_id}.pdf"},
    )


def auto_refresh_cache():
    print("🚀 Thread de cache iniciada")
    while True:
        try:
            # Adicionado sleep pequeno antes para não competir CPU na inicialização
            time.sleep(15)
            atualizar_cache_tv()
        except Exception as e:
            print(f"⚠️ Erro CRÍTICO na thread de cache: {e}")
            traceback.print_exc()
            # Se der erro, espera um pouco mais antes de tentar de novo para não floodar o log
            time.sleep(30)


if __name__ == "__main__":
    print("=" * 50)
    print("🏥 INICIANDO CLINICASYS PRO")
    print("=" * 50)
    print(f"📂 Pasta do executável: {BASE_DIR}")
    print(f"💾 Banco de dados em: {db.db_path}")
    print("=" * 50)

    try:
        print("👤 Pré-carregando usuário ADMIN na memória...")
        conn = db.conectar()
        admin = conn.execute("SELECT * FROM usuarios WHERE username='admin'").fetchone()
        conn.close()
        if admin:
            u_obj = User(admin["id"], admin["username"], admin["role"])
            USER_CACHE_RAM[admin["id"]] = u_obj
            print("✅ Admin carregado no Cache RAM (Sistema Blindado)")
    except Exception as e:
        print(f"⚠️ Erro ao pré-carregar admin: {e}")

    # Inicia o servidor Flask em uma thread separada
    t = threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0", port=5000, threaded=True, use_reloader=False, debug=False
        )
    )
    t.daemon = True
    t.start()
    print("✅ Servidor Flask iniciado")

    # Thread de auto-refresh do cache
    cache_thread = threading.Thread(target=auto_refresh_cache)
    cache_thread.daemon = True
    cache_thread.start()

    # Carregamento inicial
    time.sleep(1)
    atualizar_cache_tv()

    print("✅ Cache inicial carregado")
    print("=" * 50)

    # Cria a API
    api = Api()

    # Cria a janela principal
    window = webview.create_window(
        "ClinicaSys Pro",
        "http://localhost:5000",  # Voltamos para o padrão universal
        min_size=(1024, 768),
        js_api=api,
    )
    print("✅ Janela principal criada")
    print("✅ Sistema pronto para uso!")
    print("=" * 50)

    webview.start()
