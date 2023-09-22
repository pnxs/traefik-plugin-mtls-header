# mTLS Header Plugin

[![Build Status](https://github.com/pnxs/traefik-plugin-mtls-header/workflows/Main/badge.svg?branch=main)](https://github.com/pnxs/traefik-plugin-mtls-header/actions)
[![Build Status](https://github.com/pnxs/traefik-plugin-mtls-header/workflows/Go%20Matrix/badge.svg?branch=main)](https://github.com/pnxs/traefik-plugin-mtls-header/actions)

This plugin allows to set custom headers from http.Request and client certificate (if provided) using text/template.

## Configuration

Example:
Given a client certificate with the common name "mtls_client" the following configuration
will insert this http-header: "X-Client-CN: CN=mtls_client".
```yml
testData:
  headers:
    X-Client-CN: 'CN=[[.Cert.Subject.CommonName]]'
  encodeUrl: false
```
