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


