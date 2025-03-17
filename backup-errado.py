import re
from flask import Flask, jsonify, request
from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash

# CADASTRO

from flask import request

@app.route('/cadastro', methods=['GET'])
def cadastro():
    tipo_usuario = request.args.get('tipo', type=int) # Essa linha utiliza 'request.args.get' para adquirir o valor do tipo armazenado no banco de dados, vimos sobre esse código no site: https://stackoverflow.com/questions/34671217/in-flask-what-is-request-args-and-how-is-it-used

    cur = con.cursor()

    if tipo_usuario == 2:
        cur.execute("SELECT id_usuario, nome, e_mail, senha, tipo FROM usuario WHERE tipo = 2")
    elif tipo_usuario == 3:
        cur.execute("SELECT id_usuario, nome, e_mail, senha, tipo FROM usuario WHERE tipo = 3")
    else:
        cur.execute("SELECT id_usuario, nome, e_mail, senha, tipo FROM usuario")

    usuarios = cur.fetchall()

    doador_dic = []
    ong_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        e_mail = usuario[2]
        senha = usuario[3]
        tipo = usuario[4]

        if tipo == 3:
            cur.execute(
                "SELECT nome, e_mail, senha FROM usuario WHERE id_usuario = ?",
                (id_usuario,))

            doador_dic.append({
                'id_usuario': id_usuario,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha
            })
        elif tipo == 2:
            cur.execute(
                "SELECT cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco FROM usuario WHERE id_usuario = ?",
                (id_usuario,))
            ong_info = cur.fetchone()

            ong_dic.append({
                'id_usuario': id_usuario,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha,
                'cnpj': ong_info[0],
                'categoria': ong_info[1],
                'descricao_da_causa': ong_info[2],
                'cep': ong_info[3],
                'chave_pix': ong_info[4],
                'num_agencia': ong_info[5],
                'num_conta': ong_info[6],
                'nome_banco': ong_info[7]
            })

    if doador_dic:
        return jsonify(mensagem='Registro de Cadastro de Doadores', doadores=doador_dic)
    elif ong_dic:
        return jsonify(mensagem='Registro de Cadastro de ONGs', ongs=ong_dic)
    else:
        return jsonify(mensagem='Nenhum dado encontrado')


def validar_senha(senha):
    padrao = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%¨&*])(?=.*\d).{8,}$'

    if re.fullmatch(padrao, senha):
        return True
    else:
        return False

@app.route('/cadastro', methods=['POST'])
def cadastro_post():
    tipo_usuario = request.args.get('tipo', type=int) # Essa linha utiliza 'request.args.get' para adquirir o valor do tipo armazenado no banco de dados, vimos sobre esse código no site: https://stackoverflow.com/questions/34671217/in-flask-what-is-request-args-and-how-is-it-used
    data = request.get_json()
    nome = data.get('nome')
    e_mail = data.get('e_mail')
    senha = data.get('senha')
    cnpj = data.get('cnpj')
    categoria = data.get('categoria')
    descricao_da_causa = data.get('descricao_da_causa')
    cep = data.get('cep')
    chave_pix = data.get('chave_pix')
    num_agencia = data.get('num_agencia')
    num_conta = data.get('num_conta')
    nome_banco = data.get('nome_banco')

    if not validar_senha(senha):
        return jsonify('A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'), 401

    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))

    if cursor.fetchone():
        return jsonify({"error": "E-mail já cadastrado!"}), 400

    senha = generate_password_hash(senha).decode('utf-8')

    if tipo_usuario == 3:
        cursor.execute("INSERT INTO USUARIO(NOME, E_MAIL, SENHA) VALUES (?, ?, ?)",
                   (nome, e_mail, senha))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Registro realizado com sucesso!",
            'usuario': {
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha
            }
        })

    elif tipo_usuario == 2:
        cursor.execute("INSERT INTO USUARIO(NOME, E_MAIL, SENHA, CNPJ, CATEGORIA, DESCRICAO_DA_CAUSA, CEP, CHAVE_PIX, NUM_AGENCIA, NUM_CONTA, NOME_BANCO, ATIVO) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, 1))
        con.commit()
        cursor.close()
        return jsonify({
            'message': "Registro realizado com sucesso!",
            'usuario': {
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha,
                'cnpj': cnpj,
                'categoria': categoria,
                'descricao_da_causa': descricao_da_causa,
                'cep': cep,
                'chave_pix': chave_pix,
                'num_agencia': num_agencia,
                'num_conta': num_conta,
                'nome_banco': nome_banco
            }
        })


@app.route('/cadastro/<int:id>', methods=['PUT'])
def cadastro_put(id):
    tipo_usuario = request.args.get('tipo', type=int) # Essa linha utiliza 'request.args.get' para adquirir o valor do tipo armazenado no banco de dados, vimos sobre esse código no site: https://stackoverflow.com/questions/34671217/in-flask-what-is-request-args-and-how-is-it-used
    cursor = con.cursor()
    cursor.execute("select id_usuario, nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, tipo from usuario WHERE id_usuario = ?", (id,))
    usuario = cursor.fetchone()

    tipo_usuario = usuario[12]
    senha_armazenada = usuario[3]

    if not usuario:
        cursor.close()
        return jsonify({"Registro não encontrado."})

    if tipo_usuario == 3:
        data = request.get_json()
        nome = data.get('nome')
        e_mail = data.get('e_mail')
        senha = data.get('senha')

        cursor = con.cursor()

        cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))

        if cursor.fetchone():
            return jsonify({"error": "E-mail já cadastrado!"}), 400

        if senha_armazenada != senha:
            if not validar_senha(senha):
                return jsonify(
                    'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.')

            senha = generate_password_hash(senha).decode('utf-8')

        cursor.execute("UPDATE usuario SET NOME = ?, E_MAIL = ?, SENHA = ? WHERE ID_USUARIO = ?",
                       (nome, e_mail, senha, id))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Cadastro atualizado com sucesso!",
            'usuario': {
                'id_usuario': id,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha
            }
        })

    elif tipo_usuario == 2:
        data = request.get_json()
        nome = data.get('nome')
        e_mail = data.get('e_mail')
        senha = data.get('senha')
        cnpj = data.get('cnpj')
        categoria = data.get('categoria')
        descricao_da_causa = data.get('descricao_da_causa')
        cep = data.get('cep')
        chave_pix = data.get('chave_pix')
        num_agencia = data.get('num_agencia')
        num_conta = data.get('num_conta')
        nome_banco = data.get('nome_banco')

        cursor = con.cursor()

        cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))

        if cursor.fetchone():
            return jsonify({"error": "E-mail já cadastrado!"}), 400

        if senha_armazenada != senha:
            if not validar_senha(senha):
                return jsonify(
                    'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.')

            senha = generate_password_hash(senha).decode('utf-8')

        cursor.execute("UPDATE usuario SET NOME = ?, E_MAIL = ?, SENHA = ?, CNPJ = ?, CATEGORIA = ?, DESCRICAO_DA_CAUSA = ?, CEP = ?, CHAVE_PIX = ?, NUM_AGENCIA = ?, NUM_CONTA = ?, NOME_BANCO = ? WHERE ID_USUARIO = ?",
                       (nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, id))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Cadastro atualizado com sucesso!",
            'usuario': {
                'id_usuario': id,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha,
                'cnpj': cnpj,
                'categoria': categoria,
                'descricao_da_causa': descricao_da_causa,
                'cep': cep,
                'chave_pix': chave_pix,
                'num_agencia': num_agencia,
                'num_conta': num_conta,
                'nome_banco': nome_banco
            }
        })
    return jsonify({
            'message': "Cadastro atualizado com sucesso!"})

# NÃO FUNCIONAL (ENTRETANTO, TAMBÉM NÃO É IMPORTANTE)
@app.route('/cadastro/<int:id>', methods=['DELETE'])
def deletar_cadastro(id):
    tipo_usuario = request.args.get('tipo', type=int) # Essa linha utiliza 'request.args.get' para adquirir o valor do tipo armazenado no banco de dados, vimos sobre esse código no site: https://stackoverflow.com/questions/34671217/in-flask-what-is-request-args-and-how-is-it-used
    cursor = con.cursor()

    if tipo_usuario == 3:
        cursor.execute("SELECT 1 FROM usuario WHERE ID_USUARIO = ?", (id,))
        if not cursor.fetchone():
            cursor.close()
            return jsonify({"error": "Registro não encontrado."}), 404

        cursor.execute("DELETE FROM usuario WHERE ID_USUARIO = ?", (id,))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Cadastro excluído com sucesso!",
            'id_usuario': id
        })

    elif tipo_usuario == 2:
        cursor.execute("SELECT 1 FROM usuario WHERE ID_USUARIO = ?", (id,))
        if not cursor.fetchone():
            cursor.close()
            return jsonify({"error": "Registro não encontrado."}), 404

        cursor.execute("DELETE FROM usuario WHERE ID_USUARIO = ?", (id,))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Cadastro excluído com sucesso!",
            'id_usuario': id
        })


# LOGIN

tentativas = 0
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    nome = data.get('nome')
    e_mail = data.get('e_mail')
    senha = data.get('senha')

    global tentativas

    cursor = con.cursor()
    cursor.execute("select nome, e_mail, senha, tipo, id_usuario, ativo from usuario WHERE e_mail = ?", (e_mail,))
    login_data = cursor.fetchone()

    if login_data[5] != 0:
        if not login_data:
            cursor.close()
            return jsonify({'erro': "Credenciais não encontradas"}), 400

        senha_hash = login_data[2]

        if check_password_hash(senha_hash, senha):
            if login_data[3] == 2:
                return jsonify({
                    'message': "Login feito com sucesso!"
                })
            if login_data[3] == 3:
                return jsonify({
                    'message': "Login feito com sucesso!"
                })
            else:
                return jsonify({
                    'message': "Login feito com sucesso!"
                })
        if login_data[3] != 1:
            tentativas = tentativas + 1

            if tentativas == 3:
                cursor = con.cursor()
                cursor.execute("update usuario set ativo = 0 where id_usuario = ?", (login_data[4],))

                con.commit()
                cursor.close()

                return jsonify({
                    'message': "Usuário Inativo!"
                })

        return jsonify({
                'message': "Erro no login!"
            })
    return jsonify({
        'message': "Usuário Inativo!"
    })
