# OpenHail examples

## 1. One-shot version check

    echo '{"jsonrpc":"2.0","id":1,"method":"system.version"}' | openhail serve

## 2. Drive it from an AI agent

Any LLM with a shell tool can operate OpenHail. The method list is self-describing:

    echo '{"jsonrpc":"2.0","id":1,"method":"system.methods"}' | openhail serve

Then an agent can list recent mail:

    {"jsonrpc":"2.0","id":2,"method":"mail.list","params":{"account":"fastmail","limit":10}}

## 3. Local provider setup (self-hosted Dovecot / Stalwart / Mailcow)

    export OPENHAIL_PASSWORD='...'
    openhail account add --name home --imap mail.example.net:993 --smtp mail.example.net:587 --user me@example.net
    openhail sync --account home --limit 50
    openhail list --account home

## 4. Proton Bridge (local TLS on 127.0.0.1)

Proton Bridge terminates TLS locally, so OpenHail connects the normal way:

    openhail account add --name proton --imap 127.0.0.1:1143 --smtp 127.0.0.1:1025 --user you@proton.me

Bridge generates a self-signed certificate; trust it in the system store.

## 5. Search across a synced mailbox

    openhail search --account fastmail --query "invoice 4471"