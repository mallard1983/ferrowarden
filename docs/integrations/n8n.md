<img src="../../branding/assets/png/banners/ferrowarden-docs-header.png" width="100%" alt="">

# Using Ferrowarden from n8n

The [HTTP Request node](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/) can call Ferrowarden like any other JSON API. A workflow then holds an agent key and `{{vault:name}}` placeholders instead of the credential values themselves. Ferrowarden substitutes the values and forwards the request.

This page assumes a running Ferrowarden with at least one agent key (see the [setup guide](../setup.md) and [`POST /v1/admin/keys`](../api-reference.md#post-v1adminkeys)). Replace `https://ferrowarden.example.lan` below with your base URL, including the `api_prefix` if the operator has set one.

## Store the agent key

1. In n8n, create a credential of type **Header Auth**.
2. Set **Name** to `X-Agent-Key` and **Value** to the agent key's token.
3. Use this credential in every HTTP Request node that calls Ferrowarden: set **Authentication** to **Generic Credential Type**, **Generic Auth Type** to **Header Auth**, and pick the credential.

The agent key is scoped by its policy: it can reach the credentials and methods the operator allowed, and it does not open the vault or any other service.

## List the credentials the key can use

Add an HTTP Request node:

| Setting | Value |
|---|---|
| Method | `GET` |
| URL | `https://ferrowarden.example.lan/v1/credentials?detail=true` |
| Authentication | the Header Auth credential above |

The response is a list of credential names with ready-made placeholders, for example `{{vault:'Example Service (prod)'}}`. Copy placeholders as they are rather than writing the quoting yourself.

## Forward a call with a placeholder in a header

Add a second HTTP Request node:

| Setting | Value |
|---|---|
| Method | `POST` |
| URL | `https://ferrowarden.example.lan/v1/forward` |
| Authentication | the Header Auth credential above |
| Send Body | on, **Body Content Type** `JSON`, **Specify Body** `Using JSON` |

JSON body:

```json
{
  "request": {
    "method": "GET",
    "url": "https://api.example.com/v1/items",
    "headers": {
      "Authorization": "Bearer {{vault:example_api_token}}"
    }
  }
}
```

Ferrowarden replaces the placeholder with the credential value, sends the request to `api.example.com`, and returns an object with the target's `status`, `headers`, `body` and `body_encoding`. The `body` is a string: use n8n's `JSON.parse` in a following Code or Set node if the target answers with JSON. A `200` from Ferrowarden means the request was forwarded; the target's own status is in `status`.

### Keep placeholders out of expressions

n8n evaluates `{{ ... }}` in a field that is in **Expression** mode, so `{{vault:example_api_token}}` would be read as an n8n expression and fail. Leave the field in **Fixed** mode when it holds a placeholder. If you must mix n8n expressions with a placeholder in one field, write the placeholder as an expression that returns the literal text:

```
{{ '{{vault:example_api_token}}' }}
```

## What Ferrowarden checks

A request is refused, and nothing is sent, when the method or credential is outside the key's policy (`403`), the credential is not bound to the target host (`403`), or a placeholder does not parse or names an unknown credential (`422`). The response body names the problem, so n8n's **Always Output Data** and an error branch are worth enabling on the node. See the [API reference](../api-reference.md) for every status.

## The OpenAPI specification

Ferrowarden publishes an [OpenAPI 3.1 description](../openapi.yaml) and serves it at `GET /v1/openapi.json` to a caller who sends a key. An agent key receives the agent operations; the admin key receives all of them.

n8n's HTTP Request node does not import an OpenAPI document. It can import a cURL command (the **Import cURL** button), and the specification is useful as the reference for the request and response shapes while you build the nodes. Features of n8n can change between versions, so check the [n8n documentation](https://docs.n8n.io/) for what your version supports.
