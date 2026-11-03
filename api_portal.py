import os
import re
import hmac
import json
import base64
import secrets
import hashlib
import psycopg

from datetime import date, timedelta

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Header
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


app = FastAPI(
    title="Portal AgroHara API",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://agrohara.github.io",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# ============================================================
# MODELOS
# ============================================================

class LoginCPF(BaseModel):
    cpf: str


class AdminAcessoCriar(BaseModel):
    cpf: str
    cod_reps: list[int]
    perfil: str = "VENDEDOR"
    admin: bool = False


class AdminStatusAlterar(BaseModel):
    ativo: bool


class AdminVinculosAlterar(BaseModel):
    cod_reps: list[int]


# ============================================================
# BANCO
# ============================================================

def conectar_banco():
    url = os.environ.get("RENDER_DATABASE_URL")

    if not url:
        raise RuntimeError(
            "RENDER_DATABASE_URL nao configurada."
        )

    return psycopg.connect(
        url,
        sslmode="require",
        connect_timeout=15
    )


# ============================================================
# ACESSOS - POSTGRESQL
# ============================================================

def normalizar_cpf(valor):
    digitos = re.sub(r"\D", "", str(valor or ""))

    if len(digitos) != 11:
        raise ValueError("CPF invalido.")

    if digitos == digitos[0] * 11:
        raise ValueError("CPF invalido.")

    # Valida os dois digitos verificadores do CPF.
    for tamanho in (9, 10):
        soma = sum(
            int(digitos[i]) * (tamanho + 1 - i)
            for i in range(tamanho)
        )
        digito = (soma * 10) % 11

        if digito == 10:
            digito = 0

        if digito != int(digitos[tamanho]):
            raise ValueError("CPF invalido.")

    return digitos


def hash_cpf(cpf):
    pepper = os.environ.get("OTP_PEPPER")

    if not pepper:
        raise RuntimeError(
            "OTP_PEPPER nao configurado."
        )

    return hmac.new(
        pepper.encode("utf-8"),
        cpf.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def buscar_acesso_por_hash(cpf_hash):
    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT
                a.id_acesso,
                a.cpf_hash,
                a.representante,
                a.perfil,
                a.admin,
                ARRAY_AGG(
                    ar.cod_rep
                    ORDER BY ar.cod_rep
                ) AS cod_reps
            FROM portal.acessos a

            INNER JOIN portal.acesso_representantes ar
                ON ar.id_acesso = a.id_acesso

            WHERE a.cpf_hash = %s
              AND a.ativo = true

            GROUP BY
                a.id_acesso,
                a.cpf_hash,
                a.representante,
                a.perfil,
                a.admin

            LIMIT 1
        """, (cpf_hash,))

        r = cur.fetchone()

    finally:
        con.close()

    if not r:
        return None

    cod_reps = [
        int(codigo)
        for codigo in (r[5] or [])
    ]

    if not cod_reps:
        return None

    return {
        "id_acesso": r[0],
        "cpf_hash": str(r[1]).strip().lower(),
        "representante": r[2],
        "perfil": str(r[3] or "VENDEDOR").strip().upper(),
        "admin": bool(r[4]),
        "cod_reps": cod_reps
    }


def dados_requisicao(request):
    if request is None:
        return None, None

    xff = str(
        request.headers.get("x-forwarded-for", "")
    ).strip()

    if xff:
        ip = xff.split(",", 1)[0].strip()
    elif request.client:
        ip = request.client.host
    else:
        ip = None

    if ip:
        ip = ip[:64]

    user_agent = str(
        request.headers.get("user-agent", "")
    ).strip() or None

    return ip, user_agent


def registrar_log(
    evento,
    request=None,
    id_acesso=None,
    cpf_hash=None,
    detalhe=None,
    cur=None
):
    ip, user_agent = dados_requisicao(request)

    criou_conexao = cur is None
    con = None

    if criou_conexao:
        con = conectar_banco()
        cur = con.cursor()

    try:
        cur.execute("""
            INSERT INTO portal.acessos_log (
                id_acesso,
                evento,
                cpf_hash,
                ip,
                user_agent,
                detalhe
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            id_acesso,
            evento,
            cpf_hash,
            ip,
            user_agent,
            detalhe
        ))

        if criou_conexao:
            con.commit()

    except Exception:
        if criou_conexao and con:
            con.rollback()
        # Falha de auditoria nao pode derrubar o login/logout.

    finally:
        if criou_conexao and con:
            con.close()


# ============================================================
# TOKEN / SESSAO
# ============================================================

def segredo_sessao():
    # Reaproveita o segredo ja configurado no Render.
    # Se no futuro quiser separar, basta criar PORTAL_SESSION_SECRET.
    segredo = (
        os.environ.get("PORTAL_SESSION_SECRET")
        or os.environ.get("OTP_PEPPER")
    )

    if not segredo:
        raise RuntimeError(
            "PORTAL_SESSION_SECRET/OTP_PEPPER nao configurado."
        )

    return segredo


def b64url_encode(valor_bytes):
    return base64.urlsafe_b64encode(
        valor_bytes
    ).decode("ascii").rstrip("=")


def b64url_decode(valor):
    padding = "=" * (
        (4 - len(valor) % 4) % 4
    )

    return base64.urlsafe_b64decode(
        valor + padding
    )


def criar_token_sessao(cpf_hash):
    agora = int(
        __import__("time").time()
    )

    payload = {
        "sub": cpf_hash,
        "iat": agora,
        "exp": agora + (12 * 60 * 60),
        "nonce": secrets.token_urlsafe(12)
    }

    payload_txt = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True
    )

    payload_b64 = b64url_encode(
        payload_txt.encode("utf-8")
    )

    assinatura = hmac.new(
        segredo_sessao().encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256
    ).digest()

    return (
        payload_b64
        + "."
        + b64url_encode(assinatura)
    )


def ler_token_sessao(token):
    try:
        payload_b64, assinatura_b64 = token.split(".", 1)

        assinatura_recebida = b64url_decode(
            assinatura_b64
        )

        assinatura_esperada = hmac.new(
            segredo_sessao().encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(
            assinatura_recebida,
            assinatura_esperada
        ):
            raise ValueError

        payload = json.loads(
            b64url_decode(
                payload_b64
            ).decode("utf-8")
        )

        agora = int(
            __import__("time").time()
        )

        if int(payload.get("exp", 0)) <= agora:
            raise ValueError

        cpf_hash = str(
            payload.get("sub", "")
        ).strip().lower()

        if not re.fullmatch(r"[0-9a-f]{64}", cpf_hash):
            raise ValueError

        return payload

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Sessao invalida ou expirada."
        )


def obter_id_usuario_tecnico(cur, cod_reps):
    # Tenta reaproveitar um usuario existente ligado a um dos codigos.
    cur.execute("""
        SELECT id_usuario
        FROM portal.usuarios
        WHERE ativo = true
          AND cod_rep = ANY(%s::integer[])
        ORDER BY id_usuario
        LIMIT 1
    """, (cod_reps,))

    r = cur.fetchone()

    if r:
        return r[0]

    # Fallback tecnico para manter a FK da tabela portal.sessoes
    # sem precisar criar nenhuma tabela nova.
    cur.execute("""
        SELECT id_usuario
        FROM portal.usuarios
        WHERE ativo = true
        ORDER BY id_usuario
        LIMIT 1
    """)

    r = cur.fetchone()

    if not r:
        raise RuntimeError(
            "Nenhum usuario tecnico ativo em portal.usuarios."
        )

    return r[0]


def validar_sessao(authorization):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Sessao nao informada."
        )

    partes = authorization.split(" ", 1)

    if (
        len(partes) != 2
        or partes[0].lower() != "bearer"
        or not partes[1].strip()
    ):
        raise HTTPException(
            status_code=401,
            detail="Sessao invalida."
        )

    token = partes[1].strip()

    payload = ler_token_sessao(
        token
    )

    cpf_hash = payload["sub"]

    acesso = buscar_acesso_por_hash(
        cpf_hash
    )

    if not acesso:
        raise HTTPException(
            status_code=401,
            detail="Acesso nao autorizado."
        )

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT id_sessao
            FROM portal.sessoes
            WHERE token_hash = %s
              AND ativo = true
              AND revogado_em IS NULL
              AND expira_em > now()
            LIMIT 1
        """, (token_hash,))

        sessao = cur.fetchone()

        if not sessao:
            raise HTTPException(
                status_code=401,
                detail="Sessao inexistente, expirada ou revogada."
            )

        cur.execute("""
            UPDATE portal.sessoes
               SET ultimo_acesso_em = now()
             WHERE id_sessao = %s
        """, (sessao[0],))

        con.commit()

    finally:
        con.close()

    return {
        "id_sessao": sessao[0],
        "id_acesso": acesso["id_acesso"],
        "id_usuario": acesso["cod_reps"][0],
        "representante": acesso["representante"],
        "perfil": acesso["perfil"],
        "admin": acesso["admin"],
        "cod_reps": acesso["cod_reps"],
        "cpf_hash": cpf_hash
    }


# ============================================================
# AUTH - LOGIN POR CPF
# ============================================================

@app.post("/auth/login")
def login_cpf(dados: LoginCPF, request: Request):
    try:
        cpf = normalizar_cpf(
            dados.cpf
        )

    except ValueError:
        registrar_log(
            "LOGIN_NEGADO",
            request=request,
            detalhe="CPF invalido."
        )

        raise HTTPException(
            status_code=401,
            detail="CPF nao autorizado."
        )

    cpf_hash = hash_cpf(
        cpf
    )

    acesso = buscar_acesso_por_hash(
        cpf_hash
    )

    if not acesso:
        registrar_log(
            "LOGIN_NEGADO",
            request=request,
            cpf_hash=cpf_hash,
            detalhe="CPF nao cadastrado ou acesso inativo."
        )

        raise HTTPException(
            status_code=401,
            detail="CPF nao autorizado."
        )

    token = criar_token_sessao(
        cpf_hash
    )

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    con = conectar_banco()
    cur = con.cursor()

    try:
        id_usuario_tecnico = obter_id_usuario_tecnico(
            cur,
            acesso["cod_reps"]
        )

        cur.execute("""
            INSERT INTO portal.sessoes (
                id_usuario,
                token_hash,
                expira_em,
                ultimo_acesso_em,
                ativo
            )
            VALUES (
                %s,
                %s,
                now() + interval '12 hours',
                now(),
                true
            )
            RETURNING
                id_sessao,
                expira_em
        """, (
            id_usuario_tecnico,
            token_hash
        ))

        sessao = cur.fetchone()

        registrar_log(
            "LOGIN_SUCESSO",
            request=request,
            id_acesso=acesso["id_acesso"],
            cpf_hash=cpf_hash,
            detalhe=f"id_sessao={sessao[0]}",
            cur=cur
        )

        con.commit()

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

    return {
        "status": "ok",
        "access_token": token,
        "token_type": "bearer",
        "expires_at": sessao[1],
        "usuario": {
            "id_usuario": acesso["cod_reps"][0],
            "representante": acesso["representante"],
            "perfil": acesso["perfil"],
            "admin": acesso["admin"]
        }
    }




# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "servico": "Portal AgroHara API"
    }


@app.get("/health/db")
def health_db():
    try:
        con = conectar_banco()
        cur = con.cursor()

        cur.execute("""
            SELECT
                current_database(),
                current_user,
                COUNT(*)
            FROM portal.vendas
        """)

        r = cur.fetchone()

        con.close()

        return {
            "status": "ok",
            "banco": r[0],
            "usuario_banco": r[1],
            "linhas_portal_vendas": r[2]
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Falha na conexao com o banco."
        )




# ============================================================
# ME
# ============================================================

@app.get("/me")
def me(
    authorization: str | None = Header(default=None)
):
    usuario = validar_sessao(
        authorization
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT MAX(dtemissao)
            FROM portal.vendas
        """)

        data_referencia = cur.fetchone()[0]

    finally:
        con.close()

    return {
        "id_usuario": usuario["id_usuario"],
        "nome": usuario["representante"],
        "representante": usuario["representante"],
        "perfil": usuario["perfil"],
        "admin": usuario["admin"],
        "data_referencia": data_referencia
    }





# ============================================================
# ADMINISTRACAO
# ============================================================

def exigir_admin(authorization):
    usuario = validar_sessao(
        authorization
    )

    if not usuario.get("admin"):
        raise HTTPException(
            status_code=403,
            detail="Acesso administrativo nao autorizado."
        )

    return usuario


def validar_cod_reps(cur, cod_reps):
    codigos = []

    for valor in (cod_reps or []):
        try:
            codigo = int(valor)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="COD_REP invalido."
            )

        if codigo <= 0:
            raise HTTPException(
                status_code=400,
                detail="COD_REP invalido."
            )

        if codigo not in codigos:
            codigos.append(codigo)

    if not codigos:
        raise HTTPException(
            status_code=400,
            detail="Informe pelo menos um COD_REP."
        )

    if len(codigos) > 50:
        raise HTTPException(
            status_code=400,
            detail="Quantidade de COD_REP acima do permitido."
        )

    cur.execute("""
        SELECT
            cod_rep,
            MAX(representante) AS representante
        FROM portal.vendas
        WHERE cod_rep = ANY(%s::integer[])
        GROUP BY cod_rep
        ORDER BY cod_rep
    """, (codigos,))

    encontrados = {
        int(r[0]): str(r[1] or "").strip()
        for r in cur.fetchall()
    }

    faltantes = [
        codigo
        for codigo in codigos
        if codigo not in encontrados
    ]

    if faltantes:
        raise HTTPException(
            status_code=400,
            detail=(
                "COD_REP nao encontrado em portal.vendas: "
                + ", ".join(str(x) for x in faltantes)
            )
        )

    nomes = []

    for codigo in codigos:
        nome = encontrados[codigo]

        if nome and nome not in nomes:
            nomes.append(nome)

    representante = (
        nomes[0]
        if len(nomes) == 1
        else " / ".join(nomes)
    )

    if not representante:
        representante = (
            "COD_REP "
            + ", ".join(str(x) for x in codigos)
        )

    return codigos, representante


@app.get("/admin/representantes")
def admin_representantes(
    q: str = "",
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    termo = str(q or "").strip()

    if len(termo) > 100:
        raise HTTPException(
            status_code=400,
            detail="Pesquisa muito longa."
        )

    con = conectar_banco()
    cur = con.cursor()

    try:
        if termo:
            cur.execute("""
                SELECT
                    cod_rep,
                    representante,
                    COUNT(*) AS linhas,
                    MIN(dtemissao) AS primeira_venda,
                    MAX(dtemissao) AS ultima_venda
                FROM portal.vendas
                WHERE cod_rep IS NOT NULL
                  AND representante IS NOT NULL
                  AND (
                        representante ILIKE %s
                        OR cod_rep::text = %s
                      )
                GROUP BY
                    cod_rep,
                    representante
                ORDER BY
                    representante,
                    cod_rep
                LIMIT 100
            """, (
                "%" + termo + "%",
                termo
            ))
        else:
            cur.execute("""
                SELECT
                    cod_rep,
                    representante,
                    COUNT(*) AS linhas,
                    MIN(dtemissao) AS primeira_venda,
                    MAX(dtemissao) AS ultima_venda
                FROM portal.vendas
                WHERE cod_rep IS NOT NULL
                  AND representante IS NOT NULL
                GROUP BY
                    cod_rep,
                    representante
                ORDER BY
                    representante,
                    cod_rep
                LIMIT 100
            """)

        linhas = cur.fetchall()

    finally:
        con.close()

    return [
        {
            "cod_rep": int(r[0]),
            "representante": r[1],
            "linhas": r[2],
            "primeira_venda": r[3],
            "ultima_venda": r[4]
        }
        for r in linhas
    ]


@app.get("/admin/acessos")
def admin_listar_acessos(
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT
                a.id_acesso,
                a.representante,
                a.perfil,
                a.ativo,
                a.admin,
                COALESCE(
                    ARRAY_AGG(
                        ar.cod_rep
                        ORDER BY ar.cod_rep
                    ) FILTER (
                        WHERE ar.cod_rep IS NOT NULL
                    ),
                    ARRAY[]::integer[]
                ) AS cod_reps,
                a.criado_em,
                a.atualizado_em
            FROM portal.acessos a

            LEFT JOIN portal.acesso_representantes ar
                ON ar.id_acesso = a.id_acesso

            GROUP BY
                a.id_acesso,
                a.representante,
                a.perfil,
                a.ativo,
                a.admin,
                a.criado_em,
                a.atualizado_em

            ORDER BY
                a.ativo DESC,
                a.representante,
                a.id_acesso
        """)

        linhas = cur.fetchall()

    finally:
        con.close()

    return [
        {
            "id_acesso": r[0],
            "representante": r[1],
            "perfil": r[2],
            "ativo": bool(r[3]),
            "admin": bool(r[4]),
            "cod_reps": [
                int(x)
                for x in (r[5] or [])
            ],
            "criado_em": r[6],
            "atualizado_em": r[7]
        }
        for r in linhas
    ]


@app.post("/admin/acessos")
def admin_criar_acesso(
    dados: AdminAcessoCriar,
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = exigir_admin(
        authorization
    )

    try:
        cpf = normalizar_cpf(
            dados.cpf
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="CPF invalido."
        )

    perfil = str(
        dados.perfil or "VENDEDOR"
    ).strip().upper()

    if perfil != "VENDEDOR":
        raise HTTPException(
            status_code=400,
            detail="Nesta versao, o perfil permitido e VENDEDOR."
        )

    cpf_hash = hash_cpf(
        cpf
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        codigos, representante = validar_cod_reps(
            cur,
            dados.cod_reps
        )

        cur.execute("""
            SELECT id_acesso
            FROM portal.acessos
            WHERE cpf_hash = %s
            LIMIT 1
        """, (cpf_hash,))

        existente = cur.fetchone()

        if existente:
            raise HTTPException(
                status_code=409,
                detail=(
                    "CPF ja cadastrado. "
                    "Edite o acesso existente."
                )
            )

        cur.execute("""
            INSERT INTO portal.acessos (
                cpf_hash,
                representante,
                perfil,
                ativo,
                admin
            )
            VALUES (
                %s,
                %s,
                %s,
                true,
                %s
            )
            RETURNING id_acesso
        """, (
            cpf_hash,
            representante,
            perfil,
            bool(dados.admin)
        ))

        id_acesso = cur.fetchone()[0]

        for codigo in codigos:
            cur.execute("""
                INSERT INTO portal.acesso_representantes (
                    id_acesso,
                    cod_rep
                )
                VALUES (%s, %s)
            """, (
                id_acesso,
                codigo
            ))

        registrar_log(
            "ADMIN_CADASTRO",
            request=request,
            id_acesso=usuario["id_acesso"],
            cpf_hash=usuario["cpf_hash"],
            detalhe=(
                f"alvo_id={id_acesso}; "
                f"cod_reps={','.join(str(x) for x in codigos)}"
            ),
            cur=cur
        )

        con.commit()

    except HTTPException:
        con.rollback()
        raise

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

    return {
        "status": "ok",
        "id_acesso": id_acesso,
        "representante": representante,
        "perfil": perfil,
        "ativo": True,
        "admin": bool(dados.admin),
        "cod_reps": codigos
    }


@app.post("/admin/acessos/{id_acesso}/vinculos")
def admin_alterar_vinculos(
    id_acesso: int,
    dados: AdminVinculosAlterar,
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = exigir_admin(
        authorization
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT id_acesso
            FROM portal.acessos
            WHERE id_acesso = %s
            LIMIT 1
        """, (id_acesso,))

        if not cur.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Acesso nao encontrado."
            )

        codigos, representante = validar_cod_reps(
            cur,
            dados.cod_reps
        )

        cur.execute("""
            DELETE FROM portal.acesso_representantes
            WHERE id_acesso = %s
        """, (id_acesso,))

        for codigo in codigos:
            cur.execute("""
                INSERT INTO portal.acesso_representantes (
                    id_acesso,
                    cod_rep
                )
                VALUES (%s, %s)
            """, (
                id_acesso,
                codigo
            ))

        cur.execute("""
            UPDATE portal.acessos
               SET representante = %s,
                   atualizado_em = NOW()
             WHERE id_acesso = %s
        """, (
            representante,
            id_acesso
        ))

        registrar_log(
            "ADMIN_VINCULOS",
            request=request,
            id_acesso=usuario["id_acesso"],
            cpf_hash=usuario["cpf_hash"],
            detalhe=(
                f"alvo_id={id_acesso}; "
                f"cod_reps={','.join(str(x) for x in codigos)}"
            ),
            cur=cur
        )

        con.commit()

    except HTTPException:
        con.rollback()
        raise

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

    return {
        "status": "ok",
        "id_acesso": id_acesso,
        "representante": representante,
        "cod_reps": codigos
    }


@app.post("/admin/acessos/{id_acesso}/status")
def admin_alterar_status(
    id_acesso: int,
    dados: AdminStatusAlterar,
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = exigir_admin(
        authorization
    )

    if (
        id_acesso == usuario["id_acesso"]
        and not dados.ativo
    ):
        raise HTTPException(
            status_code=400,
            detail="Voce nao pode bloquear o proprio acesso."
        )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            UPDATE portal.acessos
               SET ativo = %s,
                   atualizado_em = NOW()
             WHERE id_acesso = %s
            RETURNING representante
        """, (
            bool(dados.ativo),
            id_acesso
        ))

        r = cur.fetchone()

        if not r:
            raise HTTPException(
                status_code=404,
                detail="Acesso nao encontrado."
            )

        registrar_log(
            "ADMIN_STATUS",
            request=request,
            id_acesso=usuario["id_acesso"],
            cpf_hash=usuario["cpf_hash"],
            detalhe=(
                f"alvo_id={id_acesso}; "
                f"ativo={str(bool(dados.ativo)).lower()}"
            ),
            cur=cur
        )

        con.commit()

    except HTTPException:
        con.rollback()
        raise

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

    return {
        "status": "ok",
        "id_acesso": id_acesso,
        "representante": r[0],
        "ativo": bool(dados.ativo)
    }


@app.get("/admin/historico")
def admin_historico(
    id_acesso: int | None = None,
    evento: str | None = None,
    limite: int = 500,
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    if limite < 1 or limite > 2000:
        raise HTTPException(
            status_code=400,
            detail="Limite deve ficar entre 1 e 2000."
        )

    filtros = []
    parametros = []

    if id_acesso is not None:
        filtros.append(
            "l.id_acesso = %s"
        )
        parametros.append(
            id_acesso
        )

    if evento:
        evento = evento.strip().upper()

        if len(evento) > 30:
            raise HTTPException(
                status_code=400,
                detail="Evento invalido."
            )

        filtros.append(
            "l.evento = %s"
        )
        parametros.append(
            evento
        )

    where_sql = ""

    if filtros:
        where_sql = (
            "WHERE "
            + " AND ".join(filtros)
        )

    parametros.append(
        limite
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute(
            f"""
                SELECT
                    l.id_log,
                    l.id_acesso,
                    l.evento,
                    a.representante,
                    a.perfil,
                    l.ip,
                    l.user_agent,
                    l.detalhe,
                    l.criado_em AT TIME ZONE 'America/Sao_Paulo'
                FROM portal.acessos_log l

                LEFT JOIN portal.acessos a
                    ON a.id_acesso = l.id_acesso

                {where_sql}

                ORDER BY
                    l.criado_em DESC,
                    l.id_log DESC

                LIMIT %s
            """,
            parametros
        )

        linhas = cur.fetchall()

    finally:
        con.close()

    return [
        {
            "id_log": r[0],
            "id_acesso": r[1],
            "evento": r[2],
            "representante": r[3],
            "perfil": r[4],
            "ip": r[5],
            "user_agent": r[6],
            "detalhe": r[7],
            "data_hora": r[8]
        }
        for r in linhas
    ]


# ============================================================
# VENDAS
# ============================================================


@app.get("/vendas/metas")
def vendas_metas(
    de: date,
    ate: date,
    authorization: str | None = Header(default=None)
):
    usuario = validar_sessao(
        authorization
    )

    if usuario["perfil"] != "VENDEDOR":
        raise HTTPException(
            status_code=403,
            detail=(
                "Perfil ainda nao autorizado "
                "para este endpoint."
            )
        )

    if ate < de:
        raise HTTPException(
            status_code=400,
            detail="Periodo invalido."
        )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT
                ano,
                SUM(valor) AS valor
            FROM portal.metas
            WHERE cod_rep = ANY(%s::integer[])
              AND ano BETWEEN %s AND %s
            GROUP BY ano
            ORDER BY ano
        """, (
            usuario["cod_reps"],
            de.year,
            ate.year
        ))

        linhas = cur.fetchall()

    finally:
        con.close()

    return [
        {
            "ano": int(r[0]),
            "valor": float(r[1])
        }
        for r in linhas
    ]

def adicionar_meses(data_base: date, meses: int) -> date:
    total = data_base.year * 12 + (data_base.month - 1) + meses
    ano = total // 12
    mes = total % 12 + 1
    return date(ano, mes, 1)


@app.get("/vendas/resumo")
def vendas_resumo(
    modo: str | None = None,
    periodo: str | None = None,
    recorte: str = "todo",
    indice: int | None = None,
    authorization: str | None = Header(default=None)
):
    usuario = validar_sessao(
        authorization
    )

    if usuario["perfil"] != "VENDEDOR":
        raise HTTPException(
            status_code=403,
            detail=(
                "Perfil ainda nao autorizado "
                "para este endpoint."
            )
        )

    # --------------------------------------------------------
    # COMPATIBILIDADE COM O ENDPOINT ANTIGO
    # --------------------------------------------------------
    if modo is None and periodo is None:

        if recorte != "todo" or indice is not None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Para usar recorte, informe tambem "
                    "modo e periodo."
                )
            )

        filtro_sql = ""
        parametros_periodo = []

        filtro_resposta = {
            "modo": None,
            "periodo": None,
            "recorte": "todo",
            "indice": None,
            "de": None,
            "ate": None
        }

    else:

        if modo is None or periodo is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Informe modo e periodo juntos. "
                    "Ex.: modo=ano&periodo=2026 "
                    "ou modo=safra&periodo=26/27."
                )
            )

        modo = modo.strip().lower()
        periodo = periodo.strip()
        recorte = recorte.strip().lower()

        # ----------------------------------------------------
        # PERIODO PRINCIPAL
        # ----------------------------------------------------
        filtro_safra = ""
        parametros_periodo = []

        if modo == "ano":

            if not re.fullmatch(
                r"[0-9]{4}",
                periodo
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Ano invalido."
                )

            ano = int(periodo)

            if ano < 2000 or ano > 2100:
                raise HTTPException(
                    status_code=400,
                    detail="Ano invalido."
                )

            inicio_periodo = date(
                ano,
                1,
                1
            )

        elif modo == "safra":

            if not re.fullmatch(
                r"[0-9]{2}/[0-9]{2}",
                periodo
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Safra invalida."
                )

            ano_ini_2 = int(periodo[:2])
            ano_fim_2 = int(periodo[3:])

            if (ano_ini_2 + 1) % 100 != ano_fim_2:
                raise HTTPException(
                    status_code=400,
                    detail="Safra invalida."
                )

            # O historico atual do portal esta no seculo 2000.
            ano_inicio = 2000 + ano_ini_2

            inicio_periodo = date(
                ano_inicio,
                5,
                1
            )

            # Mantemos tambem a coluna safra como garantia
            # da regra oficial do banco.
            filtro_safra = """
              AND safra = %s
            """

            parametros_periodo.append(
                periodo
            )

        else:
            raise HTTPException(
                status_code=400,
                detail="Modo deve ser 'safra' ou 'ano'."
            )

        # ----------------------------------------------------
        # RECORTE DENTRO DO ANO / SAFRA
        #
        # todo       -> 12 meses
        # semestre   -> indice 1 ou 2
        # trimestre  -> indice 1 a 4
        # mes        -> indice 1 a 12
        #
        # Na safra:
        # mes 1 = maio
        # mes 2 = junho
        # ...
        # mes 12 = abril
        # ----------------------------------------------------
        if recorte == "todo":

            if indice is not None:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "O recorte 'todo' nao usa indice."
                    )
                )

            deslocamento = 0
            quantidade_meses = 12

        elif recorte == "semestre":

            if indice not in (1, 2):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Semestre deve usar indice 1 ou 2."
                    )
                )

            deslocamento = (
                indice - 1
            ) * 6

            quantidade_meses = 6

        elif recorte == "trimestre":

            if indice not in (1, 2, 3, 4):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Trimestre deve usar indice de 1 a 4."
                    )
                )

            deslocamento = (
                indice - 1
            ) * 3

            quantidade_meses = 3

        elif recorte == "mes":

            if (
                indice is None
                or indice < 1
                or indice > 12
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Mes deve usar indice de 1 a 12."
                    )
                )

            deslocamento = indice - 1
            quantidade_meses = 1

        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Recorte deve ser 'todo', "
                    "'semestre', 'trimestre' ou 'mes'."
                )
            )

        inicio_recorte = adicionar_meses(
            inicio_periodo,
            deslocamento
        )

        fim_recorte_exclusivo = adicionar_meses(
            inicio_recorte,
            quantidade_meses
        )

        fim_recorte_inclusivo = (
            fim_recorte_exclusivo
            - timedelta(days=1)
        )

        filtro_sql = f"""
          {filtro_safra}
          AND dtemissao >= %s
          AND dtemissao <  %s
        """

        parametros_periodo.extend([
            inicio_recorte,
            fim_recorte_exclusivo
        ])

        filtro_resposta = {
            "modo": modo,
            "periodo": periodo,
            "recorte": recorte,
            "indice": indice,
            "de": inicio_recorte,
            "ate": fim_recorte_inclusivo
        }

    # --------------------------------------------------------
    # CONSULTA
    # --------------------------------------------------------
    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute(
            f"""
                SELECT
                    COUNT(*),
                    COALESCE(SUM(valor_total_item), 0),
                    COALESCE(SUM(quantidade), 0),
                    MIN(dtemissao),
                    MAX(dtemissao),

                    COUNT(
                        DISTINCT CASE
                            WHEN cod_grupo IS NOT NULL
                             AND grupo_familiar IS NOT NULL
                             AND grupo_familiar <> 'SEM GRUPO INFORMADO'
                                THEN 'G:' || cod_grupo::text
                            ELSE 'C:' || cod_cliente::text
                        END
                    )

                FROM portal.vendas

                WHERE cod_rep = ANY(%s::integer[])
                  {filtro_sql}
            """,
            [
                usuario["cod_reps"],
                *parametros_periodo
            ]
        )

        r = cur.fetchone()

    finally:
        con.close()

    return {
        "usuario": {
            "id_usuario": usuario["id_usuario"],
            "representante": usuario["representante"],
            "perfil": usuario["perfil"]
        },
        "filtro": filtro_resposta,
        "resumo": {
            "linhas": r[0],
            "faturamento": r[1],
            "quantidade": r[2],
            "primeira_emissao": r[3],
            "ultima_emissao": r[4],
            "clientes": r[5]
        }
    }



@app.get("/vendas/itens")
def vendas_itens(
    de: date,
    ate: date,
    authorization: str | None = Header(default=None)
):
    usuario = validar_sessao(
        authorization
    )

    if usuario["perfil"] != "VENDEDOR":
        raise HTTPException(
            status_code=403,
            detail=(
                "Perfil ainda nao autorizado "
                "para este endpoint."
            )
        )

    if ate < de:
        raise HTTPException(
            status_code=400,
            detail="A data final deve ser maior ou igual a data inicial."
        )

    if (ate - de).days > 2000:
        raise HTTPException(
            status_code=400,
            detail="Intervalo de datas muito grande."
        )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT
                estab,
                seqnota,
                nota,
                serie,
                tipo_mov,
                dtemissao,
                prazopagto,
                cod_cliente,
                cliente_nome,
                cod_grupo,
                grupo_familiar,
                cliente_final,
                item_cod,
                item,
                unidade,
                grupo,
                subgrupo,
                COALESCE(quantidade, 0)::double precision,
                COALESCE(valor_total_item, 0)::double precision

            FROM portal.vendas

            WHERE cod_rep = ANY(%s::integer[])
              AND dtemissao >= %s
              AND dtemissao <= %s

            ORDER BY
                dtemissao,
                estab,
                seqnota,
                seqnotaitem
        """, (
            usuario["cod_reps"],
            de,
            ate
        ))

        linhas = cur.fetchall()

    finally:
        con.close()

    colunas = [
        "estab",
        "seqnota",
        "nota",
        "serie",
        "tipo_mov",
        "dtemissao",
        "prazopagto",
        "cod_cliente",
        "cliente_nome",
        "cod_grupo",
        "grupo_familiar",
        "cliente_final",
        "item_cod",
        "item",
        "unidade",
        "grupo",
        "subgrupo",
        "quantidade",
        "valor_total_item"
    ]

    return [
        dict(zip(colunas, linha))
        for linha in linhas
    ]




# ============================================================
# AUTH - LOGOUT
# ============================================================

@app.post("/auth/logout")
def logout(
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = validar_sessao(
        authorization
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            UPDATE portal.sessoes
               SET ativo = false,
                   revogado_em = COALESCE(
                       revogado_em,
                       now()
                   )
             WHERE id_sessao = %s
        """, (
            usuario["id_sessao"],
        ))

        registrar_log(
            "LOGOUT",
            request=request,
            id_acesso=usuario["id_acesso"],
            cpf_hash=usuario["cpf_hash"],
            detalhe=f"id_sessao={usuario['id_sessao']}",
            cur=cur
        )

        con.commit()

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

    return {
        "status": "ok",
        "mensagem": "Sessao encerrada."
    }


# ============================================================
# VETERINARIA - LAMINAS ELANCO / MSD  (bloco vet v1 - 03/11/2026)
#
# Tabelas: portal.vet_segmentos, vet_representantes, vet_cestas,
#          vet_cesta_itens, vet_metas, vw_vet_cesta_itens,
#          vw_vet_itens_fabricante.
#
# Regras:
# - /vet/lamina usa SEMPRE os cod_reps da sessao (nunca do navegador).
# - /admin/vet/* exige admin = true e grava em portal.acessos_log.
# - Nada e apagado: metas e cestas sao desativadas (ativo = false).
# - Itens podem estar em varias cestas e contam em todas.
# - Realizado da meta = vendas - devolucoes do COD_REP nos itens
#   da cesta, dentro do periodo da propria meta.
# ============================================================

class VetRepresentanteSalvar(BaseModel):
    cod_rep: int
    segmento: str
    ativo: bool = True


class VetCestaSalvar(BaseModel):
    id_cesta: int | None = None
    segmento: str
    nome: str
    descricao: str | None = None
    fabricante: str | None = None
    ativo: bool = True


class VetCestaItens(BaseModel):
    item_cods: list[int]


class VetMetaSalvar(BaseModel):
    id_meta: int | None = None
    id_cesta: int
    cod_rep: int
    tipo: str
    data_inicio: date
    data_fim: date
    valor_meta: float
    ativo: bool = True


class VetStatus(BaseModel):
    ativo: bool


VET_MAX_DIAS = 400


def vet_num(valor):
    return float(valor) if valor is not None else 0.0


def vet_validar_periodo(de, ate):
    if ate < de:
        raise HTTPException(
            status_code=400,
            detail="Periodo invalido."
        )

    if (ate - de).days > VET_MAX_DIAS:
        raise HTTPException(
            status_code=400,
            detail="Periodo maximo de 400 dias."
        )


def vet_id_segmento(cur, segmento):
    codigo = str(segmento or "").strip().upper()

    cur.execute("""
        SELECT id_segmento
        FROM portal.vet_segmentos
        WHERE codigo = %s
          AND ativo = true
    """, (codigo,))

    r = cur.fetchone()

    if not r:
        raise HTTPException(
            status_code=400,
            detail="Segmento invalido. Use ELANCO ou MSD."
        )

    return r[0]


def vet_nomes_itens(cur, item_cods):
    if not item_cods:
        return {}

    cur.execute("""
        SELECT DISTINCT ON (item_cod)
            item_cod,
            item,
            unidade
        FROM portal.vendas
        WHERE item_cod = ANY(%s::integer[])
        ORDER BY item_cod, dtemissao DESC
    """, (list(item_cods),))

    return {
        int(r[0]): {"item": r[1], "unidade": r[2]}
        for r in cur.fetchall()
    }


def vet_montar_lamina(cur, cod_reps, de, ate):
    """Lamina dos cod_reps informados (ja autorizados pelo chamador)."""

    cur.execute("""
        SELECT
            r.cod_rep,
            s.codigo,
            s.nome
        FROM portal.vet_representantes r
        JOIN portal.vet_segmentos s
          ON s.id_segmento = r.id_segmento
        WHERE r.ativo = true
          AND r.cod_rep = ANY(%s::integer[])
        ORDER BY s.codigo, r.cod_rep
    """, (list(cod_reps),))

    reps = cur.fetchall()

    if not reps:
        return []

    codigos = [int(r[0]) for r in reps]

    # Faturamento total de cada representante (todos os produtos)
    cur.execute("""
        SELECT
            cod_rep,
            MAX(representante),
            COALESCE(SUM(valor_total_item), 0),
            COALESCE(SUM(quantidade), 0),
            COUNT(
                DISTINCT CASE
                    WHEN cod_grupo IS NOT NULL
                     AND grupo_familiar IS NOT NULL
                     AND grupo_familiar <> 'SEM GRUPO INFORMADO'
                        THEN 'G:' || cod_grupo::text
                    ELSE 'C:' || cod_cliente::text
                END
            )
        FROM portal.vendas
        WHERE cod_rep = ANY(%s::integer[])
          AND dtemissao >= %s
          AND dtemissao <= %s
        GROUP BY cod_rep
    """, (codigos, de, ate))

    totais = {int(r[0]): r for r in cur.fetchall()}

    # Faturamento por grupo de produto
    cur.execute("""
        SELECT
            cod_rep,
            COALESCE(grupo, 'SEM GRUPO'),
            COALESCE(SUM(valor_total_item), 0)
        FROM portal.vendas
        WHERE cod_rep = ANY(%s::integer[])
          AND dtemissao >= %s
          AND dtemissao <= %s
        GROUP BY cod_rep, COALESCE(grupo, 'SEM GRUPO')
        ORDER BY cod_rep, 3 DESC
    """, (codigos, de, ate))

    grupos = {}

    for r in cur.fetchall():
        grupos.setdefault(int(r[0]), []).append({
            "grupo": r[1],
            "faturamento": vet_num(r[2])
        })

    # Metas que tocam o periodo, com realizado no periodo da propria meta
    cur.execute("""
        SELECT
            m.id_meta,
            m.cod_rep,
            c.id_cesta,
            c.nome,
            c.fabricante,
            m.tipo,
            m.data_inicio,
            m.data_fim,
            m.valor_meta,
            COALESCE(rz.realizado, 0),
            rz.unidades
        FROM portal.vet_metas m
        JOIN portal.vet_cestas c
          ON c.id_cesta = m.id_cesta
        LEFT JOIN LATERAL (
            SELECT
                SUM(
                    CASE WHEN m.tipo = 'VALOR'
                         THEN v.valor_total_item
                         ELSE v.quantidade
                    END
                ) AS realizado,
                STRING_AGG(DISTINCT v.unidade, ', ') AS unidades
            FROM portal.vendas v
            WHERE v.cod_rep = m.cod_rep
              AND v.dtemissao >= m.data_inicio
              AND v.dtemissao <= m.data_fim
              AND v.item_cod IN (
                    SELECT ci.item_cod
                    FROM portal.vw_vet_cesta_itens ci
                    WHERE ci.id_cesta = m.id_cesta
              )
        ) rz ON true
        WHERE m.ativo = true
          AND c.ativo = true
          AND m.cod_rep = ANY(%s::integer[])
          AND m.data_inicio <= %s
          AND m.data_fim >= %s
        ORDER BY m.cod_rep, m.tipo DESC, c.nome, m.data_inicio
    """, (codigos, ate, de))

    metas = {}

    for r in cur.fetchall():
        meta = vet_num(r[8])
        realizado = vet_num(r[9])

        metas.setdefault(int(r[1]), []).append({
            "id_meta": r[0],
            "id_cesta": r[2],
            "cesta": r[3],
            "fabricante": r[4],
            "tipo": r[5],
            "data_inicio": r[6],
            "data_fim": r[7],
            "meta": meta,
            "realizado": realizado,
            "percentual": (
                round(100.0 * realizado / meta, 1)
                if meta else None
            ),
            "unidades": (
                r[10] if r[5] == "QUANTIDADE" else None
            )
        })

    resultado = []

    for cod_rep, segmento, segmento_nome in reps:
        cod_rep = int(cod_rep)
        t = totais.get(cod_rep)

        resultado.append({
            "cod_rep": cod_rep,
            "representante": t[1] if t else None,
            "segmento": segmento,
            "segmento_nome": segmento_nome,
            "faturamento": vet_num(t[2]) if t else 0.0,
            "quantidade": vet_num(t[3]) if t else 0.0,
            "clientes": int(t[4]) if t else 0,
            "grupos": grupos.get(cod_rep, []),
            "metas": metas.get(cod_rep, [])
        })

    return resultado


def vet_data_referencia(cur):
    cur.execute("SELECT MAX(dtemissao) FROM portal.vendas")
    return cur.fetchone()[0]


# ------------------------------------------------------------
# LAMINA DO VENDEDOR (cod_reps da sessao)
# ------------------------------------------------------------

@app.get("/vet/lamina")
def vet_lamina(
    de: date,
    ate: date,
    authorization: str | None = Header(default=None)
):
    usuario = validar_sessao(
        authorization
    )

    vet_validar_periodo(de, ate)

    con = conectar_banco()
    cur = con.cursor()

    try:
        representantes = vet_montar_lamina(
            cur,
            usuario["cod_reps"],
            de,
            ate
        )

        data_ref = vet_data_referencia(cur)

    finally:
        con.close()

    return {
        "de": de,
        "ate": ate,
        "data_referencia": data_ref,
        "representantes": representantes
    }


# ------------------------------------------------------------
# ADMIN - LAMINA DO SEGMENTO INTEIRO
# ------------------------------------------------------------

@app.get("/admin/vet/lamina")
def admin_vet_lamina(
    segmento: str,
    de: date,
    ate: date,
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    vet_validar_periodo(de, ate)

    con = conectar_banco()
    cur = con.cursor()

    try:
        id_segmento = vet_id_segmento(cur, segmento)

        cur.execute("""
            SELECT cod_rep
            FROM portal.vet_representantes
            WHERE id_segmento = %s
              AND ativo = true
        """, (id_segmento,))

        codigos = [int(r[0]) for r in cur.fetchall()]

        representantes = vet_montar_lamina(
            cur,
            codigos,
            de,
            ate
        )

        data_ref = vet_data_referencia(cur)

    finally:
        con.close()

    return {
        "segmento": str(segmento).strip().upper(),
        "de": de,
        "ate": ate,
        "data_referencia": data_ref,
        "representantes": representantes
    }


# ------------------------------------------------------------
# ADMIN - CADASTRO (leitura)
# ------------------------------------------------------------

@app.get("/admin/vet/cadastro")
def admin_vet_cadastro(
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT id_segmento, codigo, nome, ativo
            FROM portal.vet_segmentos
            ORDER BY codigo
        """)

        segmentos = [
            {
                "id_segmento": r[0],
                "codigo": r[1],
                "nome": r[2],
                "ativo": bool(r[3])
            }
            for r in cur.fetchall()
        ]

        cur.execute("""
            SELECT
                r.cod_rep,
                s.codigo,
                r.ativo,
                (
                    SELECT MAX(v.representante)
                    FROM portal.vendas v
                    WHERE v.cod_rep = r.cod_rep
                ) AS representante
            FROM portal.vet_representantes r
            JOIN portal.vet_segmentos s
              ON s.id_segmento = r.id_segmento
            ORDER BY s.codigo, r.cod_rep
        """)

        representantes = [
            {
                "cod_rep": int(r[0]),
                "segmento": r[1],
                "ativo": bool(r[2]),
                "representante": r[3]
            }
            for r in cur.fetchall()
        ]

        cur.execute("""
            SELECT
                c.id_cesta,
                s.codigo,
                c.nome,
                c.descricao,
                c.fabricante,
                c.ativo,
                (
                    SELECT COUNT(*)
                    FROM portal.vw_vet_cesta_itens ci
                    WHERE ci.id_cesta = c.id_cesta
                ) AS itens,
                (
                    SELECT COUNT(*)
                    FROM portal.vet_metas m
                    WHERE m.id_cesta = c.id_cesta
                      AND m.ativo = true
                ) AS metas
            FROM portal.vet_cestas c
            JOIN portal.vet_segmentos s
              ON s.id_segmento = c.id_segmento
            ORDER BY s.codigo, c.nome
        """)

        cestas = [
            {
                "id_cesta": r[0],
                "segmento": r[1],
                "nome": r[2],
                "descricao": r[3],
                "fabricante": r[4],
                "ativo": bool(r[5]),
                "itens": int(r[6]),
                "metas": int(r[7])
            }
            for r in cur.fetchall()
        ]

        cur.execute("""
            SELECT fabricante, COUNT(*)
            FROM portal.vw_vet_itens_fabricante
            GROUP BY fabricante
            ORDER BY fabricante
        """)

        fabricantes = [
            {"fabricante": r[0], "itens": int(r[1])}
            for r in cur.fetchall()
        ]

    finally:
        con.close()

    return {
        "segmentos": segmentos,
        "representantes": representantes,
        "cestas": cestas,
        "fabricantes": fabricantes
    }


@app.get("/admin/vet/cestas/{id_cesta}/itens")
def admin_vet_cesta_itens(
    id_cesta: int,
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT fabricante
            FROM portal.vet_cestas
            WHERE id_cesta = %s
        """, (id_cesta,))

        cesta = cur.fetchone()

        if not cesta:
            raise HTTPException(
                status_code=404,
                detail="Cesta nao encontrada."
            )

        cur.execute("""
            SELECT
                ci.item_cod,
                EXISTS (
                    SELECT 1 FROM portal.vet_cesta_itens x
                    WHERE x.id_cesta = ci.id_cesta
                      AND x.item_cod = ci.item_cod
                ) AS manual,
                f.fabricante
            FROM portal.vw_vet_cesta_itens ci
            LEFT JOIN portal.vw_vet_itens_fabricante f
              ON f.item_cod = ci.item_cod
            WHERE ci.id_cesta = %s
            ORDER BY ci.item_cod
        """, (id_cesta,))

        linhas = cur.fetchall()

        nomes = vet_nomes_itens(
            cur,
            [r[0] for r in linhas]
        )

    finally:
        con.close()

    return {
        "id_cesta": id_cesta,
        "fabricante_cesta": cesta[0],
        "itens": [
            {
                "item_cod": int(r[0]),
                "origem": "MANUAL" if r[1] else "FABRICANTE",
                "fabricante": r[2],
                "item": nomes.get(int(r[0]), {}).get("item"),
                "unidade": nomes.get(int(r[0]), {}).get("unidade")
            }
            for r in linhas
        ]
    }


@app.get("/admin/vet/itens")
def admin_vet_pesquisar_itens(
    q: str,
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    termo = str(q or "").strip()

    if len(termo) < 2 or len(termo) > 100:
        raise HTTPException(
            status_code=400,
            detail="Pesquisa deve ter de 2 a 100 caracteres."
        )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT DISTINCT ON (v.item_cod)
                v.item_cod,
                v.item,
                v.unidade,
                v.grupo,
                f.fabricante
            FROM portal.vendas v
            LEFT JOIN portal.vw_vet_itens_fabricante f
              ON f.item_cod = v.item_cod
            WHERE v.item_cod IS NOT NULL
              AND (
                    v.item ILIKE %s
                    OR v.item_cod::text = %s
                  )
            ORDER BY v.item_cod, v.dtemissao DESC
            LIMIT 100
        """, ("%" + termo + "%", termo))

        linhas = cur.fetchall()

    finally:
        con.close()

    return [
        {
            "item_cod": int(r[0]),
            "item": r[1],
            "unidade": r[2],
            "grupo": r[3],
            "fabricante": r[4]
        }
        for r in linhas
    ]


@app.get("/admin/vet/metas")
def admin_vet_listar_metas(
    segmento: str | None = None,
    cod_rep: int | None = None,
    ano: int | None = None,
    incluir_inativas: bool = False,
    authorization: str | None = Header(default=None)
):
    exigir_admin(
        authorization
    )

    filtros = []
    parametros = []

    if segmento:
        filtros.append("s.codigo = %s")
        parametros.append(str(segmento).strip().upper())

    if cod_rep is not None:
        filtros.append("m.cod_rep = %s")
        parametros.append(cod_rep)

    if ano is not None:
        if ano < 2000 or ano > 2100:
            raise HTTPException(
                status_code=400,
                detail="Ano invalido."
            )

        filtros.append("m.data_inicio <= %s AND m.data_fim >= %s")
        parametros.extend([date(ano, 12, 31), date(ano, 1, 1)])

    if not incluir_inativas:
        filtros.append("m.ativo = true")

    where_sql = (
        "WHERE " + " AND ".join(filtros)
        if filtros else ""
    )

    con = conectar_banco()
    cur = con.cursor()

    try:
        cur.execute(
            f"""
                SELECT
                    m.id_meta,
                    s.codigo,
                    m.cod_rep,
                    m.id_cesta,
                    c.nome,
                    m.tipo,
                    m.data_inicio,
                    m.data_fim,
                    m.valor_meta,
                    m.ativo,
                    m.atualizado_em
                FROM portal.vet_metas m
                JOIN portal.vet_cestas c
                  ON c.id_cesta = m.id_cesta
                JOIN portal.vet_segmentos s
                  ON s.id_segmento = m.id_segmento
                {where_sql}
                ORDER BY s.codigo, m.cod_rep, c.nome, m.data_inicio
                LIMIT 5000
            """,
            parametros
        )

        linhas = cur.fetchall()

    finally:
        con.close()

    return [
        {
            "id_meta": r[0],
            "segmento": r[1],
            "cod_rep": int(r[2]),
            "id_cesta": r[3],
            "cesta": r[4],
            "tipo": r[5],
            "data_inicio": r[6],
            "data_fim": r[7],
            "valor_meta": vet_num(r[8]),
            "ativo": bool(r[9]),
            "atualizado_em": r[10]
        }
        for r in linhas
    ]


# ------------------------------------------------------------
# ADMIN - CADASTRO (gravacao)
# ------------------------------------------------------------

def vet_erro_banco(erro):
    estado = getattr(erro, "sqlstate", None)

    if estado == "23P01":
        return HTTPException(
            status_code=409,
            detail=(
                "Ja existe meta ativa desta cesta para este "
                "representante em periodo sobreposto."
            )
        )

    if estado == "23505":
        return HTTPException(
            status_code=409,
            detail="Registro duplicado."
        )

    if estado == "23503":
        return HTTPException(
            status_code=400,
            detail=(
                "Vinculo invalido: confira se o representante "
                "e a cesta sao do mesmo segmento."
            )
        )

    if estado == "23514":
        return HTTPException(
            status_code=400,
            detail="Dados fora das regras do cadastro."
        )

    return None


def vet_gravar(request, usuario, evento, detalhe, acao):
    """Executa acao(cur) numa transacao, com log e tratamento de erro."""

    con = conectar_banco()
    cur = con.cursor()

    try:
        resultado = acao(cur)

        registrar_log(
            evento,
            request=request,
            id_acesso=usuario["id_acesso"],
            cpf_hash=usuario["cpf_hash"],
            detalhe=detalhe(resultado),
            cur=cur
        )

        con.commit()

    except HTTPException:
        con.rollback()
        raise

    except psycopg.Error as erro:
        con.rollback()
        http = vet_erro_banco(erro)

        if http:
            raise http

        raise

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

    return resultado


@app.post("/admin/vet/representantes")
def admin_vet_salvar_representante(
    dados: VetRepresentanteSalvar,
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = exigir_admin(
        authorization
    )

    def acao(cur):
        codigos, nome = validar_cod_reps(
            cur,
            [dados.cod_rep]
        )

        id_segmento = vet_id_segmento(cur, dados.segmento)

        cur.execute("""
            SELECT id_segmento
            FROM portal.vet_representantes
            WHERE cod_rep = %s
        """, (codigos[0],))

        atual = cur.fetchone()

        if atual and atual[0] != id_segmento:
            cur.execute("""
                SELECT COUNT(*)
                FROM portal.vet_metas
                WHERE cod_rep = %s
            """, (codigos[0],))

            if cur.fetchone()[0] > 0:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Representante tem metas no segmento atual. "
                        "Desative-o e cadastre as metas novamente "
                        "antes de trocar o segmento."
                    )
                )

        cur.execute("""
            INSERT INTO portal.vet_representantes (
                cod_rep,
                id_segmento,
                ativo
            )
            VALUES (%s, %s, %s)
            ON CONFLICT (cod_rep) DO UPDATE
               SET id_segmento = EXCLUDED.id_segmento,
                   ativo = EXCLUDED.ativo
        """, (
            codigos[0],
            id_segmento,
            bool(dados.ativo)
        ))

        return {
            "cod_rep": codigos[0],
            "representante": nome,
            "segmento": str(dados.segmento).strip().upper(),
            "ativo": bool(dados.ativo)
        }

    resultado = vet_gravar(
        request,
        usuario,
        "ADMIN_VET_REP",
        lambda r: (
            f"cod_rep={r['cod_rep']}; segmento={r['segmento']}; "
            f"ativo={str(r['ativo']).lower()}"
        ),
        acao
    )

    return {"status": "ok", **resultado}


@app.post("/admin/vet/cestas")
def admin_vet_salvar_cesta(
    dados: VetCestaSalvar,
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = exigir_admin(
        authorization
    )

    nome = str(dados.nome or "").strip().upper()
    descricao = (str(dados.descricao).strip() or None) if dados.descricao else None
    fabricante = (
        str(dados.fabricante).strip().upper() or None
        if dados.fabricante else None
    )

    if not nome or len(nome) > 80:
        raise HTTPException(
            status_code=400,
            detail="Nome da cesta deve ter de 1 a 80 caracteres."
        )

    if descricao and len(descricao) > 300:
        raise HTTPException(
            status_code=400,
            detail="Descricao muito longa."
        )

    def acao(cur):
        id_segmento = vet_id_segmento(cur, dados.segmento)

        if fabricante:
            cur.execute("""
                SELECT 1
                FROM portal.vw_vet_itens_fabricante
                WHERE fabricante = %s
                LIMIT 1
            """, (fabricante,))

            if not cur.fetchone():
                raise HTTPException(
                    status_code=400,
                    detail="Fabricante sem itens cadastrados."
                )

        if dados.id_cesta is None:
            cur.execute("""
                INSERT INTO portal.vet_cestas (
                    id_segmento,
                    nome,
                    descricao,
                    fabricante,
                    ativo
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id_cesta
            """, (
                id_segmento,
                nome,
                descricao,
                fabricante,
                bool(dados.ativo)
            ))

        else:
            cur.execute("""
                SELECT id_segmento
                FROM portal.vet_cestas
                WHERE id_cesta = %s
            """, (dados.id_cesta,))

            atual = cur.fetchone()

            if not atual:
                raise HTTPException(
                    status_code=404,
                    detail="Cesta nao encontrada."
                )

            if atual[0] != id_segmento:
                raise HTTPException(
                    status_code=400,
                    detail="Nao e permitido trocar o segmento da cesta."
                )

            cur.execute("""
                UPDATE portal.vet_cestas
                   SET nome = %s,
                       descricao = %s,
                       fabricante = %s,
                       ativo = %s
                 WHERE id_cesta = %s
                RETURNING id_cesta
            """, (
                nome,
                descricao,
                fabricante,
                bool(dados.ativo),
                dados.id_cesta
            ))

        return {
            "id_cesta": cur.fetchone()[0],
            "segmento": str(dados.segmento).strip().upper(),
            "nome": nome,
            "fabricante": fabricante,
            "ativo": bool(dados.ativo)
        }

    resultado = vet_gravar(
        request,
        usuario,
        "ADMIN_VET_CESTA",
        lambda r: (
            f"id_cesta={r['id_cesta']}; nome={r['nome']}; "
            f"fabricante={r['fabricante'] or '-'}; "
            f"ativo={str(r['ativo']).lower()}"
        ),
        acao
    )

    return {"status": "ok", **resultado}


@app.post("/admin/vet/cestas/{id_cesta}/itens")
def admin_vet_salvar_itens(
    id_cesta: int,
    dados: VetCestaItens,
    request: Request,
    authorization: str | None = Header(default=None)
):
    """Substitui a lista MANUAL de itens da cesta.
    Itens que vem pelo fabricante da cesta nao sao afetados."""

    usuario = exigir_admin(
        authorization
    )

    itens = []

    for valor in dados.item_cods or []:
        if int(valor) <= 0:
            raise HTTPException(
                status_code=400,
                detail="Codigo de item invalido."
            )

        if int(valor) not in itens:
            itens.append(int(valor))

    if len(itens) > 2000:
        raise HTTPException(
            status_code=400,
            detail="Quantidade de itens acima do permitido."
        )

    def acao(cur):
        cur.execute("""
            SELECT id_cesta
            FROM portal.vet_cestas
            WHERE id_cesta = %s
        """, (id_cesta,))

        if not cur.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Cesta nao encontrada."
            )

        if itens:
            cur.execute("""
                SELECT x
                FROM unnest(%s::integer[]) AS x
                WHERE x NOT IN (
                    SELECT item_cod FROM portal.vet_itens_fabricante
                )
                  AND x NOT IN (
                    SELECT item_cod FROM portal.vendas
                    WHERE item_cod = ANY(%s::integer[])
                )
            """, (itens, itens))

            faltantes = [int(r[0]) for r in cur.fetchall()]

            if faltantes:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Item nao encontrado: "
                        + ", ".join(str(x) for x in faltantes[:20])
                    )
                )

        cur.execute("""
            DELETE FROM portal.vet_cesta_itens
            WHERE id_cesta = %s
              AND item_cod <> ALL(%s::integer[])
        """, (id_cesta, itens))

        removidos = cur.rowcount

        cur.execute("""
            INSERT INTO portal.vet_cesta_itens (id_cesta, item_cod)
            SELECT %s, x
            FROM unnest(%s::integer[]) AS x
            ON CONFLICT DO NOTHING
        """, (id_cesta, itens))

        incluidos = cur.rowcount

        return {
            "id_cesta": id_cesta,
            "itens_manuais": len(itens),
            "incluidos": incluidos,
            "removidos": removidos
        }

    resultado = vet_gravar(
        request,
        usuario,
        "ADMIN_VET_ITENS",
        lambda r: (
            f"id_cesta={r['id_cesta']}; total={r['itens_manuais']}; "
            f"incluidos={r['incluidos']}; removidos={r['removidos']}"
        ),
        acao
    )

    return {"status": "ok", **resultado}


@app.post("/admin/vet/metas")
def admin_vet_salvar_meta(
    dados: VetMetaSalvar,
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = exigir_admin(
        authorization
    )

    tipo = str(dados.tipo or "").strip().upper()

    if tipo not in ("VALOR", "QUANTIDADE"):
        raise HTTPException(
            status_code=400,
            detail="Tipo deve ser VALOR ou QUANTIDADE."
        )

    if dados.data_fim < dados.data_inicio:
        raise HTTPException(
            status_code=400,
            detail="Data final antes da data inicial."
        )

    if (dados.data_fim - dados.data_inicio).days > 800:
        raise HTTPException(
            status_code=400,
            detail="Periodo da meta muito longo."
        )

    if not (0 < dados.valor_meta < 1e15):
        raise HTTPException(
            status_code=400,
            detail="Valor da meta deve ser maior que zero."
        )

    valor = round(float(dados.valor_meta), 2)

    def acao(cur):
        cur.execute("""
            SELECT c.id_segmento, c.ativo, r.id_segmento, r.ativo
            FROM portal.vet_cestas c
            LEFT JOIN portal.vet_representantes r
              ON r.cod_rep = %s
            WHERE c.id_cesta = %s
        """, (dados.cod_rep, dados.id_cesta))

        r = cur.fetchone()

        if not r:
            raise HTTPException(
                status_code=404,
                detail="Cesta nao encontrada."
            )

        if r[2] is None:
            raise HTTPException(
                status_code=400,
                detail="Representante nao vinculado a ELANCO/MSD."
            )

        if r[0] != r[2]:
            raise HTTPException(
                status_code=400,
                detail="Cesta e representante sao de segmentos diferentes."
            )

        id_segmento = r[0]

        if dados.id_meta is None:
            cur.execute("""
                INSERT INTO portal.vet_metas (
                    id_cesta,
                    id_segmento,
                    cod_rep,
                    tipo,
                    data_inicio,
                    data_fim,
                    valor_meta,
                    ativo
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_meta
            """, (
                dados.id_cesta,
                id_segmento,
                dados.cod_rep,
                tipo,
                dados.data_inicio,
                dados.data_fim,
                valor,
                bool(dados.ativo)
            ))

        else:
            cur.execute("""
                UPDATE portal.vet_metas
                   SET id_cesta = %s,
                       id_segmento = %s,
                       cod_rep = %s,
                       tipo = %s,
                       data_inicio = %s,
                       data_fim = %s,
                       valor_meta = %s,
                       ativo = %s
                 WHERE id_meta = %s
                RETURNING id_meta
            """, (
                dados.id_cesta,
                id_segmento,
                dados.cod_rep,
                tipo,
                dados.data_inicio,
                dados.data_fim,
                valor,
                bool(dados.ativo),
                dados.id_meta
            ))

        linha = cur.fetchone()

        if not linha:
            raise HTTPException(
                status_code=404,
                detail="Meta nao encontrada."
            )

        aviso = None

        if tipo == "QUANTIDADE":
            cur.execute("""
                SELECT COUNT(DISTINCT v.unidade)
                FROM portal.vendas v
                WHERE v.item_cod IN (
                    SELECT item_cod FROM portal.vw_vet_cesta_itens
                    WHERE id_cesta = %s
                )
            """, (dados.id_cesta,))

            if cur.fetchone()[0] > 1:
                aviso = (
                    "Atencao: a cesta tem itens com unidades "
                    "diferentes; a soma de quantidade mistura unidades."
                )

        return {
            "id_meta": linha[0],
            "id_cesta": dados.id_cesta,
            "cod_rep": dados.cod_rep,
            "tipo": tipo,
            "data_inicio": dados.data_inicio,
            "data_fim": dados.data_fim,
            "valor_meta": valor,
            "ativo": bool(dados.ativo),
            "aviso": aviso
        }

    resultado = vet_gravar(
        request,
        usuario,
        "ADMIN_VET_META",
        lambda r: (
            f"id_meta={r['id_meta']}; id_cesta={r['id_cesta']}; "
            f"cod_rep={r['cod_rep']}; {r['tipo']}={r['valor_meta']}; "
            f"{r['data_inicio']}..{r['data_fim']}; "
            f"ativo={str(r['ativo']).lower()}"
        ),
        acao
    )

    return {"status": "ok", **resultado}


@app.post("/admin/vet/metas/{id_meta}/status")
def admin_vet_status_meta(
    id_meta: int,
    dados: VetStatus,
    request: Request,
    authorization: str | None = Header(default=None)
):
    usuario = exigir_admin(
        authorization
    )

    def acao(cur):
        cur.execute("""
            UPDATE portal.vet_metas
               SET ativo = %s
             WHERE id_meta = %s
            RETURNING id_meta
        """, (bool(dados.ativo), id_meta))

        if not cur.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Meta nao encontrada."
            )

        return {"id_meta": id_meta, "ativo": bool(dados.ativo)}

    resultado = vet_gravar(
        request,
        usuario,
        "ADMIN_VET_META",
        lambda r: (
            f"id_meta={r['id_meta']}; "
            f"ativo={str(r['ativo']).lower()}"
        ),
        acao
    )

    return {"status": "ok", **resultado}
