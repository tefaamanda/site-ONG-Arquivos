import fdb
class Usuario:
    def __init__(self, id_usuario, nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, endereco, complemento):
        self.id_usuario = id_usuario
        self.nome = nome
        self.e_mail = e_mail
        self.senha = senha
        self.cnpj = cnpj
        self.categoria = categoria
        self.descricao_da_causa = descricao_da_causa
        self.cep = cep
        self.chave_pix = chave_pix
        self.num_agencia = num_agencia
        self.num_conta = num_conta
        self.nome_banco = nome_banco
        self.endereco = endereco
        self.complemento = complemento