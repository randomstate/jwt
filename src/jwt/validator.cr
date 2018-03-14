module JWT
  class ValidationError < Exception
  end

  class Validator
    property current_time : Time

    property issuer : (String | Nil)
    property audience : (String | Nil)
    property subject : (String | Nil)
    property jwt_id : (String | Nil)

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

    def custom(key : String, part : Symbol = :payload, &block : JSON::Type -> Bool)
      case part
      when :header
        @custom_headers[key] = block
      else
        @custom[key] = block
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
        validate_payload_claim(@jwt_id, "jti", token)

        # validate time
        raise ValidationError.new "'Expires at' time has passed." unless Time.epoch(token.payload["exp"].as(Int64)) > @current_time
        raise ValidationError.new "'Not before' time has not yet passed." unless Time.epoch(token.payload["nbf"].as(Int64)) < @current_time
        raise ValidationError.new "'Issued at' time has not yet passed." unless Time.epoch(token.payload["iat"].as(Int64)) < @current_time

        # validate custom headers
        @custom_headers.each do |key, validator|
          header_value = token.headers[key]
          raise ValidationError.new "Validation failed for header #{key}" unless validator.call(header_value.as(JSON::Type))
        end

        # validate custom payload
        @custom.each do |key, validator|
          payload_value = token.payload[key]
          raise ValidationError.new "Validation failed for payload claim #{key}" unless validator.call(payload_value.as(JSON::Type))
        end

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
