require "./spec_helper"

describe JWT::Builder do
  it "can create a jwt token" do
    builder = JWT::Builder.new

    builder.issuer = "me"
    builder.subject = "subject"
    builder.audience = "myapp"
    builder.expires_at = Time.now + 5.hours
    builder.not_before = Time.now
    builder.issued_at = Time.now

    builder.payload["name"] = "John Doe"

    token = builder.generate

    token.payload["name"].should eq "John Doe"
  end

  it "does not add optional nil claims and headers" do
    builder = JWT::Builder.new

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
