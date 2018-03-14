require "./spec_helper"

validator = Jwt::Validator.new
validator.issuer = "me"
validator.audience = "also me"
validator.subject = "what do you know, me"

def get_builder
  builder = Jwt::Builder.new
  builder.issuer = "me"
  builder.audience = "also me"
  builder.subject = "what do you know, me"

  builder
end

describe Jwt::Validator do
  it "can validate a valid jwt token" do
    valid = get_builder.generate
    validator.validate(valid).should be_true
  end

  it "checks issuer" do
    builder = get_builder
    builder.issuer = "not me"
    invalid_issuer = builder.generate
    validator.validate(invalid_issuer).should be_false
  end

  it "checks subject" do
    builder = get_builder
    builder.subject = "you"
    invalid_subject = builder.generate
    validator.validate(invalid_subject).should be_false
  end

  it "checks audience" do
    builder = get_builder
    builder.audience = "also not me"
    invalid_audience = builder.generate
    validator.validate(invalid_audience).should be_false
  end

  it "checks expire time" do
    builder = get_builder
    builder.expires_at = Time.now - 1.day
    invalid_expires_at = builder.generate
    validator.validate(invalid_expires_at).should be_false
  end

  it "checks not_before time" do
    builder = get_builder
    builder.not_before = Time.now + 5.days
    invalid_not_before = builder.generate
    validator.validate(invalid_not_before).should be_false
  end

  it "checks issued_at time" do
    builder = get_builder
    builder.issued_at = Time.now + 3.days
    invalid_issued_at = builder.generate
    validator.validate(invalid_issued_at).should be_false
  end

  it "can account for clock skew" do
    builder = get_builder
    builder.issued_at = Time.now + 1.minute
    builder.expires_at = Time.now + 1.minute + 1.second
    builder.not_before = Time.now + 1.minute

    skewed_token = builder.generate

    validator.current_time = Time.now + 1.minute
    validator.validate(skewed_token).should be_true

    # Without skew:
    validator.current_time = Time.now
    validator.validate(skewed_token).should be_false
  end

  it "can validate custom payload claims using callbacks" do
    validator = Jwt::Validator.new
    builder = get_builder
    token = builder.generate

    token.payload["email"] = "john@example.com"

    validator.custom "email" do |value|
      next(value == "email")
    end

    validator.validate(token).should be_false

    validator.custom "email" do |value|
      next(value == "john@example.com")
    end

    validator.validate(token).should be_true
  end

  it "can validate custom header claims using callbacks" do
    validator = Jwt::Validator.new
    builder = get_builder
    token = builder.generate

    token.headers["email"] = "john@example.com"

    validator.custom "email", :header do |value|
      next(value == "email")
    end

    validator.validate(token).should be_false

    validator.custom "email", :header do |value|
      next(value == "john@example.com")
    end

    validator.validate(token).should be_true
  end
end
