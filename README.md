# Radar Local na Vercel

Envie index.html, gateway.mjs, handler.mjs, package.json e vercel.json à raiz do repositório. Na Vercel selecione Other, raiz ./ e deixe os comandos e o diretório de saída nos padrões. Use um plano adequado ao uso comercial.

Adicione em Production as variáveis MAPS_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET e PANEL_PASSWORD. Escolha uma senha aleatória exclusiva com 24 caracteres ou mais. Mantenha a exposição automática de variáveis de sistema ligada para que o painel receba VERCEL_PROJECT_PRODUCTION_URL. Use o domínio de produção gerado pela Vercel. Clique em Entrar. O login é radar e a senha é PANEL_PASSWORD. A página de interface é acessível pelo URL, mas busca, conexão e envio exigem a senha. Não envie segredos ao GitHub.

No Google Cloud, ative Places API (New) e Gmail API, configure o faturamento para Places e restrinja a chave a essa API. Use um cliente OAuth Aplicação Web e cadastre https://SEU-DOMINIO.vercel.app/api/callback como URI de redirecionamento autorizado. Troque SEU-DOMINIO pelo domínio de produção exibido pela Vercel. Em teste externo, adicione seu Gmail como utilizador de teste. Se alterar as variáveis depois do deploy, faça Redeploy.

Use o filtro de cidade e segmento. Confirme as empresas sem site e preencha o endereço de email de quem autorizou o contacto. Envie individualmente. O app não lê a caixa de entrada. O Google processa as pesquisas e os envios. Resultados de pesquisa não são guardados. A autorização do Gmail expira e é guardada em cookie cifrado. Use apenas uma aba para enviar. A prevenção de repetição nesta sessão cobre os últimos dez destinatários e não funciona como histórico permanente.

