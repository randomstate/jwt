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
  end

  it "does not add optional nil claims and headers" do
  end
end
