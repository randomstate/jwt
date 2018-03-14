module Jwt
  class Builder
    # Headers
    property type : (String | Nil) = "JWT"
    property content_type : (String | Nil)
    getter algorithm : String

    # Claims
    property issuer : (String | Nil)
    property subject : (String | Nil)
    property audience : (String | Nil)
    property expires_at : (Time | Nil)
    property not_before : (Time | Nil)
    property issued_at : (Time | Nil)
    property jwt_id : (String | Nil)

    # Custom
    getter headers
    getter claims

    def initialize
      @headers = Hash(String, JSON::Type).new
      @claims = Hash(String, JSON::Type).new
      @algorithm = "none"
    end

    private def set_claim(claim : String, value : (Time | Nil))
      if !value.nil?
        @claims[claim] = value.epoch
      end
    end

    private def set_claim(claim : String, value : (String | Nil))
      if !value.nil?
        @claims[claim] = value
      end
    end

    def generate
      @headers["typ"] = @type
      @headers["cty"] = @content_type

      set_claim "iss", @issuer
      set_claim "sub", @subject
      set_claim "aud", @audience

      set_claim "exp", @expires_at
      set_claim "nbf", @not_before
      set_claim "iat", @issued_at

      @claims["jti"] = @jwt_id

      Jwt::Token.new @headers, @claims
    end
  end
end
