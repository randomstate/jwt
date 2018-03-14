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
end
