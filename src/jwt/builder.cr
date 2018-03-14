module JWT
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
    getter payload

    property expiry_window

    def initialize(@current_time : Time = Time.now, @expiry_window : Time::Span = 1.hour)
      @headers = Hash(String, JSON::Type).new
      @payload = Hash(String, JSON::Type).new
      @algorithm = "none"
    end

    private def set_payload_claim(claim : String, value : (Time | Nil), fallback : Time)
      if !value.nil?
        @payload[claim] = value.epoch
      else
        @payload[claim] = fallback.epoch
      end
    end

    private def set_payload_claim(claim : String, value : (String | Nil))
      if !value.nil?
        @payload[claim] = value
      end
    end

    private def set_claim_on(claim : String, value : (String | Nil), on : Hash(String, JSON::Type))
      if !value.nil?
        on[claim] = value
      end
    end

    private def set_header(claim : String, value : (String | Nil))
      set_claim_on claim, value, @headers
    end

    def generate
      set_header "typ", @type
      set_header "cty", @content_type

      set_payload_claim "iss", @issuer
      set_payload_claim "sub", @subject
      set_payload_claim "aud", @audience

      set_payload_claim "exp", @expires_at, @current_time + @expiry_window
      set_payload_claim "nbf", @not_before, @current_time
      set_payload_claim "iat", @issued_at, @current_time

      set_payload_claim "jti", @jwt_id

      JWT::Token.new @headers, @payload
    end
  end
end
