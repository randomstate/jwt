require "./spec_helper"
require "../src/jwt/*"

describe Jwt::Token do
  it "can decode token into components" do
    headers = JSON.parse({"alg" => "RS256", "type" => "JWT"}.to_json).as_h
    payload = JSON.parse({"foo" => "bar"}.to_json).as_h

    jwt = Jwt::Token.new(headers, payload)

    key = OpenSSL::RSA.new 1024
    token = jwt.encode(key, Jwt::Algorithm::RS256).to_s

    decoded_jwt = Jwt::Token.decode(token)

    decoded_jwt.headers.should eq headers
    decoded_jwt.payload.should eq payload
    decoded_jwt.signature.should_not be_nil
  end

  it "can encode unencrypted token" do
    builder = Jwt::Builder.new
    builder.issuer = "Me!"

    jwt = builder.generate

    token = jwt.encode
    decoded_jwt = Jwt::Token.decode(token)

    decoded_jwt.payload["iss"].should eq "Me!"
  end

  it "can have headers and/or payload set after creation" do
    jwt = Jwt::Builder.new.generate

    jwt.headers["alg"] = "RS256"

    key = OpenSSL::RSA.new 1024
    token = jwt.encode(key, Jwt::Algorithm::RS256).to_s

    decoded_jwt = Jwt::Token.decode(token)
    decoded_jwt.headers["alg"].should eq "RS256"
  end

  it "can verify token signature" do
    # jwt =
  end

  it "can verify token claims" do
  end
end
