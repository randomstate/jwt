require "../spec_helper"

builder = JWT::Builder.new
token = builder.generate
token.payload["email"] = "john@example.com"
rsa = OpenSSL::RSA.new 1024

describe JWT::Verifier::RSA do
  it "can verify RS256-signed token" do
    signed = token.encode(rsa, JWT::Algorithm::RS256)

    decoded = JWT::Token.decode(signed)
    JWT::Verifier::RSA.verify(decoded, rsa.public_key, JWT::Algorithm::RS256).should be_true
  end

  it "can verify RS384-signed token" do
    signed = token.encode(rsa, JWT::Algorithm::RS384)

    decoded = JWT::Token.decode(signed)
    JWT::Verifier::RSA.verify(decoded, rsa.public_key, JWT::Algorithm::RS384).should be_true
  end

  it "can verify RS512-signed token" do
    signed = token.encode(rsa, JWT::Algorithm::RS512)

    decoded = JWT::Token.decode(signed)
    JWT::Verifier::RSA.verify(decoded, rsa.public_key, JWT::Algorithm::RS512).should be_true
  end

  it "can verify RSA public key of x509 cert" do
    my_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRhNWZiMGJkZTJlMzUwMmZkZTE1YzAwMWE0MWIxYzkxNDc4MTI0NzYifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vdGF4ZmluZGVyLWFmNTA5IiwiYXVkIjoidGF4ZmluZGVyLWFmNTA5IiwiYXV0aF90aW1lIjoxNTIwNzc3MzMyLCJ1c2VyX2lkIjoiRkVrem1ueTdTZ2V6YXdjM25ZQ2ozdWp2dGltMiIsInN1YiI6IkZFa3ptbnk3U2dlemF3YzNuWUNqM3VqdnRpbTIiLCJpYXQiOjE1MjEwNjUyNTIsImV4cCI6MTUyMTA2ODg1MiwiZW1haWwiOiJjb25ub3JAcmFuZG9tc3RhdGUuY28udWsiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZW1haWwiOlsiY29ubm9yQHJhbmRvbXN0YXRlLmNvLnVrIl19LCJzaWduX2luX3Byb3ZpZGVyIjoicGFzc3dvcmQifX0.ae-caU8-O3ttNvt3h29zBDM-CN7O9TzBx1iYODZwMsuSioCgfQ1R-dQnXpZ_s0bLaxcg2RBxhbfrVemkFy8FkJBilOulTK6TxVvXtcQsj8-Lv-IH8JX83NJufOS8YEsNWFgMvHzjKLNC5N9dANvmXzMig5pVt0PuNY6ofc5ouLN6N_GzzU4ZWVU2pjVIFatWW15UqESkyELW4RnYP_IFLycfMJsYYurlH5VMJbs-rHUpQLq8SX8_9J712UXIWwFG-z7pouCULtm7GYKDKFzsm4ogezx2iFgmenonceDFoQO2aj5zv1rUIJD5UaLtEEYIfgUXxuQp6NPCDXAvrP0JNQ"
    jwt = JWT::Token.decode(my_token)

    x509 = OpenSSL::X509::Certificate.new "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIbN0FxOkbgV8wDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcx\nMDAyMjIwOTMyWhcNMTkxMDAzMTAyNDMyWjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAIl4Bq5h6cEvvzCW/oer7T5WCdSa3ErR2lDbtyonlJibn3QD\n2Nl+w7opdJrALNfJY9G1THhmxBGS61w5Xi7XO6eEfxyciUPYExmLoEhOMIyxNLoe\nfXzC7MfMuwrVJq7FeyqE+j5Fudfm32vrIILZKHO8NmRlVfcFzAyZPgmV+B9e8LKz\n1L779b1NQ8aurP2Ld8nTQLYQxRDkI1OkDm+0abd6OP2LJdVQBFBk05MyhDhcw+L/\nsD5pvcgZ1fHYnOZsXVu3GM4vDHB/ABylVt33HIxVX2NSUOlUkfwpeeSq1UImoBTn\numbnx2deMXGD/WDZGl8KtpgVNATltmuPCduem/cCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAGqF3nVCYQDPpMZzQRHHsAxfrIj6H/QHKvSZjkwLW3ae\nkDeFAqXA/m1bXEOuLNoygGFPYHZ65GjRGY8fOXd4d1WYRsllXhex3fTjZ1DeEGX2\n4LKfMv7f2gdLUfnVI2wuo+nLwplNpXvjVGm4l27yPpcdonNH1Ulkkerrz+Pusj3l\n7kSfXjjzD7MSNtIvQxtca4sHsiUtpnxiwhhLs3FrxqghTYBak6GkiCJjWQ8tRXJ8\nfMU7wOKOIWgp68d67WkiqVjrwwTqgujYOYpgBNWPL4iAvdztns017gV1c/f1epOh\nStGCRh0K5RAE4y34ROmDdmKWVVrZ88s0oEzPfsjAZx8=\n-----END CERTIFICATE-----\n"
    public_key = x509.public_key

    JWT::Verifier::RSA.verify(jwt, public_key, JWT::Algorithm::RS256).should be_true
  end
end
