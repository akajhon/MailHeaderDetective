<p align="center">
    <img src="https://github.com/akajhon/MailHeaderDetective/blob/main/readme/detective_big.png" alt="Mail Header Detective logo" width="250" height="250">
</p>

# MailHeaderDetective
 

O Mail Header Detective é uma ferramenta de análise de cabeçalhos de e-mails escrita em Python. Foi projetada para auxiliar na investigação de incidentes de segurança relacionados a e-mails, facilitando a análise e a coleta de informações de cabeçalhos de e-mails.

## Funcionalidades

O Mail Header Detective é capaz de:

- Analisar o cabeçalho de um e-mail e extrair informações pertinentes.
- Verificar a reputação dos IPs encontrados nos cabeçalhos, consultando várias APIs, como VirusTotal, Hybrid-Analysis, Maltiverse e PhishTank.
- Identificar atrasos entre cada salto na entrega de um e-mail, analisando os dados de timestamp no cabeçalho do e-mail. Isso pode ajudar a identificar quaisquer atrasos anormais ou possíveis problemas no processo de entrega do e-mail.
- Rastrear a origem de um e-mail. Ao analisar cuidadosamente os campos "Received" no cabeçalho do e-mail, a ferramenta é capaz de identificar o endereço IP e, consequentemente, o servidor de onde o e-mail se originou.
- Identificar o país de origem de um e-mail, mapeando o endereço IP para o seu país. Isso pode ser particularmente útil para identificar e-mails de spam ou em investigações de forense digital.
- Executar em uma interface gráfica de usuário para facilitar o uso.
- Realizar integrações com APIs. O MHD pode identificar endereços IP, endereços de e-mail e URLs nos metadados do e-mail e enviá-los para serviços como VirusTotal, Hunter.io, Maltiverse, CheckPhish, Phishtank, entre outros, para uma análise detalhada.

Em resumo, o "Mail Header Detective" é uma poderosa ferramenta que pode ajudar a dissecar cabeçalhos de e-mail complexos, fornecendo insights úteis e informações valiosas sobre a jornada do e-mail do remetente ao destinatário.

## Requisitos

Para executar o Mail Header Detective, você precisa:

- Python 3.8+
- Pacotes Python: httpx, os, python-dotenv, concurrent.futures, dnspython, extract_msg, Flask, geoip2, IPy, maltiverse, pygal, python_dateutil e gunicorn

## Rodando Localmente

Clone o repositório para sua máquina local:

```bash
git clone https://github.com/akajhon/MailHeaderDetective.git
```

Navegue até o diretório do projeto e instale as dependências necessárias:

```bash
cd MailHeaderDetective
pip install -r requirements.txt
```

Execute o script principal:

```bash
python server.py -d
```

Acesse a aplicação:

```bash
https://127.0.0.1:8080
```

## Rodando com Docker-Compose

Clone o repositório para sua máquina local:

```bash
git clone https://github.com/akajhon/MailHeaderDetective.git
```

Navegue até o diretório do projeto:

```bash
cd MailHeaderDetective
```

Inicie o container com o comando:

```bash
docker-compose up -d
```

Acesse a aplicação:

```bash
https://127.0.0.1:8080
```

## Chaves de API

Para uma execução completa, é necessário criar o arquivo .env para armazenar as chaves das API's:

```bash
touch .env
```

O arquivo deve ser colocado dentro do diretório `mhd/modules` e deve ter a seguinte estrutura:

```bash
ABUSEIPDB = <sua_chave_de_API>
IPQUALITYSCORE = <sua_chave_de_API>
VIRUSTOTAL = <sua_chave_de_API>
MALTIVERSE = <sua_chave_de_API>
HYBRIDANALYSIS = <sua_chave_de_API>
```

## Inspiração

Este projeto foi criado com o intuito de melhorar e continuar o desenvolvimento do projeto `email-header-analyzer`, disponível em:

```bash
https://github.com/cyberdefenders/email-header-analyzer
```

## Como usar

Para usar o Mail Header Detective, você precisa fornecer o arquivo .msg ou .eml do e-mail que deseja analisar.

## Contribuindo

Contribuições para o Mail Header Detective são bem-vindas! Sinta-se à vontade para abrir um problema ou enviar um Pull Request.

## Licença

O Mail Header Detective é licenciado sob a licença MIT.

## Contato

Se você tiver alguma dúvida ou feedback, pode entrar em contato comigo através do GitHub!
