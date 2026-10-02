import os
import re
import hmac
import json
import base64
import secrets
import hashlib
import psycopg

from pathlib import Path
from datetime import date, timedelta

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


app = FastAPI(
    title="Portal AgroHara API",
    version="2.0.0"
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
# ACESSOS - ARQUIVO DO GITHUB
# ============================================================

ACESSOS_PATH = Path(__file__).with_name("acessos.json")


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


def carregar_acessos():
    # No Render, preferimos manter a lista de acessos fora do repositorio
    # publico, na variavel PORTAL_ACESSOS_JSON. Na .60, o fallback continua
    # sendo o arquivo local acessos.json ja homologado.
    acessos_json = os.environ.get("PORTAL_ACESSOS_JSON")

    try:
        if acessos_json:
            dados = json.loads(acessos_json)
        else:
            if not ACESSOS_PATH.exists():
                raise RuntimeError(
                    "PORTAL_ACESSOS_JSON/acessos.json nao configurado."
                )

            dados = json.loads(
                ACESSOS_PATH.read_text(encoding="utf-8")
            )
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(
            "Configuracao de acessos invalida."
        ) from exc

    acessos = dados.get("acessos", [])

    if not isinstance(acessos, list):
        raise RuntimeError(
            "Estrutura de acessos.json invalida."
        )

    resultado = []

    for item in acessos:
        if not isinstance(item, dict):
            continue

        if item.get("ativo", True) is False:
            continue

        cpf_hash = str(
            item.get("cpf_hash", "")
        ).strip().lower()

        representante = str(
            item.get("representante", "")
        ).strip()

        cod_reps_brutos = item.get(
            "cod_reps",
            []
        )

        if not re.fullmatch(r"[0-9a-f]{64}", cpf_hash):
            continue

        if not representante:
            continue

        if not isinstance(cod_reps_brutos, list):
            continue

        cod_reps = []

        for valor in cod_reps_brutos:
            try:
                codigo = int(valor)
            except (TypeError, ValueError):
                continue

            if codigo not in cod_reps:
                cod_reps.append(codigo)

        if not cod_reps:
            continue

        resultado.append({
            "cpf_hash": cpf_hash,
            "representante": representante,
            "cod_reps": cod_reps,
            "perfil": str(
                item.get("perfil", "VENDEDOR")
            ).strip().upper() or "VENDEDOR"
        })

    return resultado


def buscar_acesso_por_hash(cpf_hash):
    for acesso in carregar_acessos():
        if hmac.compare_digest(
            acesso["cpf_hash"],
            cpf_hash
        ):
            return acesso

    return None


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
        "id_usuario": acesso["cod_reps"][0],
        "representante": acesso["representante"],
        "perfil": acesso["perfil"],
        "cod_reps": acesso["cod_reps"],
        "cpf_hash": cpf_hash
    }


# ============================================================
# AUTH - LOGIN POR CPF
# ============================================================

@app.post("/auth/login")
def login_cpf(dados: LoginCPF):
    try:
        cpf = normalizar_cpf(
            dados.cpf
        )

    except ValueError:
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

        con.commit()

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
            "perfil": acesso["perfil"]
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
        "data_referencia": data_referencia
    }




# ============================================================
# VENDAS
# ============================================================

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
    authorization: str | None = Header(default=None)
):
    usuario = validar_sessao(
        authorization
    )

    con = conectar_banco()
    cur = con.cursor()

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

    con.commit()
    con.close()

    return {
        "status": "ok",
        "mensagem": "Sessao encerrada."
    }
