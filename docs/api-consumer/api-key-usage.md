# API Key Usage

A user may pass their API key in one of several ways. In order of precedence:

## HTTP Header

Pass the API key into the `X-Api-Key` header:

```bash
curl -H 'X-Api-Key: DEMO_KEY' 'http://example.com/api'
```

## GET Query Param

Pass the API key into the `api_key` GET query string parameter:

```bash
curl 'http://example.com/api?api_key=DEMO_KEY'
```

_Note:_ The GET query parameter may be used for non-GET requests (such as POST and PUT).

## HTTP Basic Auth Username

As an alternative, pass the API key as the username (with an empty password) using HTTP basic authentication:

```bash
curl 'http://DEMO_KEY@example.com/api'
```
