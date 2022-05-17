PoC of proxy server for SNI (TLS)
----


This PoC code accepts TLS connections and parses the TLS header.
Then connects to the real server instead of the client and sends the response back to the client.


In SNI-enabled TLS, the header contains the server name to connect to in plaintext.

### Usage

*server*
```
# sudo ruby main.rb
```

*client*
```
curl -s --verbose --resolve example.com:443:127.0.0.1 https://example.com:443/
```

### References

- [rfc8446](https://datatracker.ietf.org/doc/html/rfc8446)
  - [4. Handshake Protocol](https://datatracker.ietf.org/doc/html/rfc8446#page-24)
- [Encrypt it or lose it: how encrypted SNI works](https://blog.cloudflare.com//encrypted-sni/)
