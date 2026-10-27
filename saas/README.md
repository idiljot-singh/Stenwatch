# Stenwatch hosted dashboard (demo)

Hybrid design: the pipeline stays local, only ranked Findings with aliased asset names are uploaded. Read `docs/adr/0001-hybrid-saas-on-azure.md` first. **Demo only: not certified, do not upload real organisation data.**

## Try it locally
```
cd saas
python -m venv .venv && .venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py seed "Example Organisation" you@example.com   # prints the tenant key once
python -c "import keyring; keyring.set_password('stenwatch','STENWATCH_TENANT_KEY',input('key: '))"
set STENWATCH_DEV_USER=you@example.com
.venv\Scripts\flask --app app run
# in another terminal, from the repo root:
python saas/upload.py http://127.0.0.1:5000
```
The first upload creates a local-only alias key (`STENWATCH_ALIAS_KEY`, never sent). Open http://127.0.0.1:5000. Tests: `.venv\Scripts\python test_app.py`.

## Deploy to Azure (EU region)
Prerequisites: Azure for Students account, Azure CLI, `az login`. Do these in the Azure Portal first: **Cost Management → Budgets → add a small budget with an email alert.**

```
az group create -n stenwatch-rg -l swedencentral
az webapp up -g stenwatch-rg -n <unique-name> -l swedencentral --sku F1 --runtime "PYTHON:3.12"
az webapp config set -g stenwatch-rg -n <unique-name> --min-tls-version 1.2 --ftps-state Disabled --startup-file "gunicorn --bind=0.0.0.0 --workers=1 app:app"
az webapp update -g stenwatch-rg -n <unique-name> --https-only true
az webapp config appsettings set -g stenwatch-rg -n <unique-name> --settings STENWATCH_TRUST_EASYAUTH=1 STENWATCH_DB=/home/data.db
```
One worker on purpose: the rate limiter is in memory and storage is one SQLite file.

**Sign-in (Easy Auth):** Portal → the Web App → Authentication → Add identity provider → Microsoft → "Require authentication", **this directory only (single tenant)**. Then **exclude the API paths** so the upload agent (which uses the tenant key, not a browser login) can reach them: Authentication → Edit → excluded paths `/api/findings` and `/api/tenant`. Without that step uploads get redirected to a login page.

**Seed the tenant on the server:** `az webapp ssh -g stenwatch-rg -n <unique-name>`, then `cd /home/site/wwwroot && python app.py seed "Example Organisation" <your-entra-email>`. Store the printed key in Credential Manager as above, then `python saas/upload.py https://<unique-name>.azurewebsites.net`.

## Erase data
`curl -X DELETE -H "X-Tenant-Key: <key>" https://<unique-name>.azurewebsites.net/api/tenant`

## Clean up
`az group delete -n stenwatch-rg` removes everything.
