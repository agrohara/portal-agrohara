import os
import re
import hmac
import secrets
import hashlib
import psycopg

from datetime import date, timedelta

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


app = FastAPI(
    title="Portal AgroHara API",
    version="1.0.0"
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

class SolicitarCodigo(BaseModel):
    telefone: str


class ValidarCodigo(BaseModel):
    telefone: str
    codigo: str


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
# TELEFONE
# ============================================================

def normalizar_telefone(valor):
    digitos = re.sub(r"\D", "", valor)

    if len(digitos) in (10, 11):
        digitos = "55" + digitos

    telefone = "+" + digitos

    if not re.fullmatch(
        r"\+[1-9][0-9]{7,14}",
        telefone
    ):
        raise ValueError(
            "Telefone invalido."
        )

    return telefone


# ============================================================
# OTP
# ============================================================

def gerar_hash_otp(codigo):
    pepper = os.environ.get("OTP_PEPPER")

    if not pepper:
        raise RuntimeError(
            "OTP_PEPPER nao configurado."
        )

    return hmac.new(
        pepper.encode("utf-8"),
        codigo.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


# ============================================================
# SESSAO
# ============================================================

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

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    con = conectar_banco()
    cur = con.cursor()

    cur.execute("""
        SELECT
            s.id_sessao,
            u.id_usuario,
            u.representestab,
            u.cod_rep,
            u.representante,
            u.perfil
        FROM portal.sessoes s

        INNER JOIN portal.usuarios u
            ON u.id_usuario = s.id_usuario

        WHERE s.token_hash = %s
          AND s.ativo = true
          AND s.revogado_em IS NULL
          AND s.expira_em > now()
          AND u.ativo = true

        LIMIT 1
    """, (token_hash,))

    usuario = cur.fetchone()

    if not usuario:
        con.close()

        raise HTTPException(
            status_code=401,
            detail="Sessao inexistente, expirada ou revogada."
        )

    cur.execute("""
        UPDATE portal.sessoes
           SET ultimo_acesso_em = now()
         WHERE id_sessao = %s
    """, (usuario[0],))

    con.commit()
    con.close()

    return {
        "id_sessao": usuario[0],
        "id_usuario": usuario[1],
        "representestab": usuario[2],
        "cod_rep": usuario[3],
        "representante": usuario[4],
        "perfil": usuario[5]
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
# AUTH - SOLICITAR CODIGO
# ============================================================

@app.post("/auth/request-code")
def solicitar_codigo(dados: SolicitarCodigo):

    resposta = {
        "status": "ok",
        "mensagem": (
            "Se o telefone estiver cadastrado, "
            "um codigo sera enviado."
        )
    }

    try:
        telefone = normalizar_telefone(
            dados.telefone
        )

    except ValueError:
        return resposta

    con = conectar_banco()
    cur = con.cursor()

    cur.execute("""
        SELECT
            id_usuario,
            representante
        FROM portal.usuarios
        WHERE telefone_e164 = %s
          AND ativo = true
        LIMIT 1
    """, (telefone,))

    usuario = cur.fetchone()

    if not usuario:
        con.close()
        return resposta

    id_usuario = usuario[0]

    cur.execute("""
        SELECT criado_em
        FROM portal.login_otp
        WHERE id_usuario = %s
        ORDER BY criado_em DESC
        LIMIT 1
    """, (id_usuario,))

    ultimo = cur.fetchone()

    if ultimo:
        cur.execute("""
            SELECT
                now() - %s < interval '1 minute'
        """, (ultimo[0],))

        muito_recente = cur.fetchone()[0]

        if muito_recente:
            con.close()
            return resposta

    codigo = f"{secrets.randbelow(1000000):06d}"

    codigo_hash = gerar_hash_otp(
        codigo
    )

    cur.execute("""
        UPDATE portal.login_otp
           SET ativo = false
         WHERE id_usuario = %s
           AND ativo = true
    """, (id_usuario,))

    cur.execute("""
        INSERT INTO portal.login_otp (
            id_usuario,
            codigo_hash,
            expira_em,
            tentativas,
            ativo
        )
        VALUES (
            %s,
            %s,
            now() + interval '5 minutes',
            0,
            true
        )
    """, (
        id_usuario,
        codigo_hash
    ))

    con.commit()
    con.close()

    # SOMENTE NA HOMOLOGACAO LOCAL.
    # Remover quando entrar o WhatsApp.
    print("")
    print("======================================")
    print(" OTP GERADO - TESTE LOCAL")
    print("======================================")
    print("USUARIO:", id_usuario)
    print("CODIGO:", codigo)
    print("VALIDADE: 5 minutos")
    print("======================================")
    print("")

    return resposta


# ============================================================
# AUTH - VALIDAR CODIGO
# ============================================================

@app.post("/auth/verify-code")
def validar_codigo(dados: ValidarCodigo):

    try:
        telefone = normalizar_telefone(
            dados.telefone
        )

    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Codigo ou usuario invalido."
        )

    codigo = dados.codigo.strip()

    if not re.fullmatch(r"[0-9]{6}", codigo):
        raise HTTPException(
            status_code=401,
            detail="Codigo ou usuario invalido."
        )

    con = conectar_banco()
    cur = con.cursor()

    # --------------------------------------------------------
    # USUARIO
    # --------------------------------------------------------

    cur.execute("""
        SELECT
            id_usuario,
            representestab,
            cod_rep,
            representante,
            perfil
        FROM portal.usuarios
        WHERE telefone_e164 = %s
          AND ativo = true
        LIMIT 1
    """, (telefone,))

    usuario = cur.fetchone()

    if not usuario:
        con.close()

        raise HTTPException(
            status_code=401,
            detail="Codigo ou usuario invalido."
        )

    id_usuario = usuario[0]

    # --------------------------------------------------------
    # OTP ATIVO
    # --------------------------------------------------------

    cur.execute("""
        SELECT
            id_otp,
            codigo_hash,
            expira_em,
            tentativas,
            utilizado_em,
            ativo,
            now()
        FROM portal.login_otp
        WHERE id_usuario = %s
          AND ativo = true
        ORDER BY criado_em DESC
        LIMIT 1
        FOR UPDATE
    """, (id_usuario,))

    otp = cur.fetchone()

    if not otp:
        con.rollback()
        con.close()

        raise HTTPException(
            status_code=401,
            detail="Codigo ou usuario invalido."
        )

    (
        id_otp,
        codigo_hash_banco,
        expira_em,
        tentativas,
        utilizado_em,
        ativo,
        agora
    ) = otp

    # --------------------------------------------------------
    # EXPIRACAO / USO / TENTATIVAS
    # --------------------------------------------------------

    if utilizado_em is not None or agora > expira_em:

        cur.execute("""
            UPDATE portal.login_otp
               SET ativo = false
             WHERE id_otp = %s
        """, (id_otp,))

        con.commit()
        con.close()

        raise HTTPException(
            status_code=401,
            detail="Codigo ou usuario invalido."
        )

    if tentativas >= 5:

        cur.execute("""
            UPDATE portal.login_otp
               SET ativo = false
             WHERE id_otp = %s
        """, (id_otp,))

        con.commit()
        con.close()

        raise HTTPException(
            status_code=401,
            detail="Codigo ou usuario invalido."
        )

    # --------------------------------------------------------
    # COMPARACAO HMAC
    # --------------------------------------------------------

    codigo_hash_digitado = gerar_hash_otp(
        codigo
    )

    codigo_correto = hmac.compare_digest(
        codigo_hash_digitado,
        codigo_hash_banco
    )

    if not codigo_correto:

        nova_tentativa = tentativas + 1

        cur.execute("""
            UPDATE portal.login_otp
               SET tentativas = %s,
                   ativo = CASE
                       WHEN %s >= 5 THEN false
                       ELSE true
                   END
             WHERE id_otp = %s
        """, (
            nova_tentativa,
            nova_tentativa,
            id_otp
        ))

        con.commit()
        con.close()

        raise HTTPException(
            status_code=401,
            detail="Codigo ou usuario invalido."
        )

    # --------------------------------------------------------
    # OTP UTILIZADO
    # --------------------------------------------------------

    cur.execute("""
        UPDATE portal.login_otp
           SET utilizado_em = now(),
               ativo = false
         WHERE id_otp = %s
    """, (id_otp,))

    # --------------------------------------------------------
    # REVOGA SESSOES ANTIGAS
    # --------------------------------------------------------

    cur.execute("""
        UPDATE portal.sessoes
           SET ativo = false,
               revogado_em = COALESCE(
                   revogado_em,
                   now()
               )
         WHERE id_usuario = %s
           AND ativo = true
    """, (id_usuario,))

    # --------------------------------------------------------
    # NOVA SESSAO
    # --------------------------------------------------------

    token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

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
        id_usuario,
        token_hash
    ))

    sessao = cur.fetchone()

    con.commit()
    con.close()

    return {
        "status": "ok",
        "access_token": token,
        "token_type": "bearer",
        "expires_at": sessao[1],
        "usuario": {
            "id_usuario": usuario[0],
            "representante": usuario[3],
            "perfil": usuario[4]
        }
    }


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

                WHERE representestab = %s
                  AND cod_rep = %s
                  {filtro_sql}
            """,
            [
                usuario["representestab"],
                usuario["cod_rep"],
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

            WHERE representestab = %s
              AND cod_rep = %s
              AND dtemissao >= %s
              AND dtemissao <= %s

            ORDER BY
                dtemissao,
                estab,
                seqnota,
                seqnotaitem
        """, (
            usuario["representestab"],
            usuario["cod_rep"],
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
