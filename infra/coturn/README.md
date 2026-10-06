# Coturn para chamadas CriptoSend

Use Coturn `4.18.0-r0` ou superior em um host publico com UDP/TCP 3478, TLS
5349 e a faixa UDP 49160-49200 liberados. O arquivo
`turnserver.conf.example` ativa credenciais REST temporarias; ele e apenas um
modelo e nao contem segredo valido.

1. Gere um segredo aleatorio de pelo menos 32 bytes no gerenciador de segredos.
2. Renderize uma copia privada do arquivo de configuracao, substituindo realm,
   IP publico, certificados e `static-auth-secret`.
3. Configure no backend o mesmo segredo em `RTC_TURN_SHARED_SECRET` e as URLs
   publicas em `RTC_TURN_URLS`, por exemplo
   `turn:turn.example.com:3478,turns:turn.example.com:5349`.
4. Reinicie o backend e valide que `/calls/ice-config`, autenticado, retorna uma
   credencial cujo nome comeca com o timestamp de expiracao.
5. Teste uma chamada entre redes diferentes (por exemplo, Wi-Fi e 4G/5G) e
   confirme no `chrome://webrtc-internals` que o par selecionado pode usar
   candidato `relay`.

Nao grave `static-auth-secret`, certificados privados ou a resposta autenticada
da rota de ICE em logs. A implantacao do host, DNS e certificados fica fora do
repositorio porque depende da infraestrutura de producao.
