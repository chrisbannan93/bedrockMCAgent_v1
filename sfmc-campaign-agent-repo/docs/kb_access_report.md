# KB access attempt report

Attempted to access the external KB repo from this environment using GitHub and raw GitHub endpoints.

## Commands and results

```bash
git clone https://github.com/chrisbannan93/dodo-bedrock-kb /workspace/bedrockMCAgent_v1/dodo-bedrock-kb
```

Result:

```
Cloning into '/workspace/bedrockMCAgent_v1/dodo-bedrock-kb'...
fatal: unable to access 'https://github.com/chrisbannan93/dodo-bedrock-kb/': CONNECT tunnel failed, response 403
```

```bash
curl -I https://raw.githubusercontent.com/chrisbannan93/dodo-bedrock-kb/main/README.md
```

Result:

```
HTTP/1.1 403 Forbidden
content-length: 9
content-type: text/plain
date: Thu, 15 Jan 2026 04:57:17 GMT
server: envoy
connection: close

curl: (56) CONNECT tunnel failed, response 403
```
