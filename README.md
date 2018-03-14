# jwt

General purpose JWT library for Crystal.

Current support for:
[x] RSA
[ ] Anything else

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  jwt:
    github: randomstate/jwt
```

## Usage

```crystal
require "jwt"
```

### Generating a Token

```crystal
builder = JWT::Builder.new
builder.issuer = "me"
builder.subject = "subject"
builder.audience = "my-app"

builder.header["src"] = "multisite-1"
builder.payload["username"] = "flyingkitty2019"

jwt = builder.generate
```

### Decoding a Token

```crystal
jwt = JWT::Token.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE1MjEwNjI1MjMsIm5iZiI6MTUyMTA1ODkyMywiaWF0IjoxNTIxMDU4OTIzLCJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20ifQ==.MhN4Yiq5Ivevp-XHmPUdecpLWuRu2-IcgMHHfj7hR_VXQtIPqe54uuSwd2")

issuer = jwt.headers["iss"]
username = jwt.payload["username"]
# etc
```

### Validating Token Claims

```crystal
jwt = JWT::Token.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE1MjEwNjI1MjMsIm5iZiI6MTUyMTA1ODkyMywiaWF0IjoxNTIxMDU4OTIzLCJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20ifQ==.MhN4Yiq5Ivevp-XHmPUdecpLWuRu2-IcgMHHfj7hR_VXQtIPqe54uuSwd2")


validator = JWT::Validator.new
validator.issuer = "must be me"
validator.custom "username" do | username |
  next(username == "the_only_allowed_username")
end

validator.validate(token) # Returns true or false
validator.validate(token, true) # true or raises an exception because in strict mode - this will supply a reason for the failure
```

### Verifying a Token using an RSA Algorithm

```crystal
jwt = JWT::Token.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE1MjEwNjI1MjMsIm5iZiI6MTUyMTA1ODkyMywiaWF0IjoxNTIxMDU4OTIzLCJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20ifQ==.MhN4Yiq5Ivevp-XHmPUdecpLWuRu2-IcgMHHfj7hR_VXQtIPqe54uuSwd2")

pem = "-----BEGIN RSA PUBLIC KEY----- #..."
rsa = OpenSSL::RSA(pem, true)

JWT::Verifier::RSA.verify(token, rsa, JWT::Algorithm::RS256)

```

## Contributing

1. Fork it ( https://github.com/randomstate/jwt/fork )
2. Create your feature branch (git checkout -b feature/my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin feature/my-new-feature)
5. Create a new Pull Request

## Contributors

- [cimrie](https://github.com/cimrie) Connor Imrie - creator, maintainer
