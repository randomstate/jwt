module Jwt
  class ValidationError < Exception
  end

  class Validator
    property current_time : Time

    property issuer : (String | Nil)
    property audience : (String | Nil)
    property subject : (String | Nil)

    def initialize(current_time : (Time | Nil) = nil)
      if current_time.nil?
        @current_time = Time.now
      else
        @current_time = current_time
      end

      @custom = Hash(String, Proc(JSON::Type, Bool)).new
      @custom_headers = Hash(String, Proc(JSON::Type, Bool)).new
    end

    def custom(key : String, &block)
      custom(key, :payload, &block)
    end

    def custom(key : String, part : Symbol = :payload, &block)
      case part
      when :header
        @custom_headers[key] = ->(value : JSON::Type) {
          yield
        }
      else
        @custom[key] = ->(value : JSON::Type) {
          yield
        }
      end
    end

    private def validate_payload_claim(claim : (String | Nil), key : String, token : Token)
      if !claim.nil?
        raise ValidationError.new "Claim \"#{key}\" is invalid. Expected \"#{claim}\", got: \"#{token.payload[key]}\"" unless claim == token.payload[key]
      end

      return true
    end

    def validate(token : Token, with_exceptions? : Bool = false)
      begin
        # validate iss, aud, sub
        validate_payload_claim(@issuer, "iss", token)
        validate_payload_claim(@audience, "aud", token)
        validate_payload_claim(@subject, "sub", token)

        # validate time
        raise ValidationError.new "'Expires at' time has passed." unless Time.epoch(token.payload["exp"].as(Int64)) > @current_time
        raise ValidationError.new "'Not before' time has not yet passed." unless Time.epoch(token.payload["nbf"].as(Int64)) < @current_time
        raise ValidationError.new "'Issued at' time has not yet passed." unless Time.epoch(token.payload["iat"].as(Int64)) < @current_time

        # validate custom headers
        # validate custom payload
        true
      rescue error : ValidationError
        unless !with_exceptions?
          raise error
        end

        false
      end
    end
  end
end
