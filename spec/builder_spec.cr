require "./spec_helper"

describe Jwt::Builder do
  it "can create a jwt token" do
    builder = Jwt::Builder.new

    builder.issuer = "me"
    builder.subject = "subject"
    builder.audience = "myapp"
    builder.expires_at = Time.now + 5.hours
    builder.not_before = Time.now
    builder.issued_at = Time.now

    builder.claims["name"] = "John Doe"

    token = builder.generate

    token.payload["name"].should eq "John Doe"
  end

  it "does not add optional nil claims and headers" do
    builder = Jwt::Builder.new

    builder.issuer = nil
    builder.subject = "subject"
    builder.audience = "myapp"
    builder.expires_at = Time.now + 5.hours
    builder.not_before = Time.now
    builder.issued_at = Time.now

    token = builder.generate

    token.payload.has_key?("iss").should be_false
  end
end
