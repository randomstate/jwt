require "openssl_ext"
require "json"
require "../jwt"

module JWT
  class Token
    getter headers
    getter payload
    getter signature : Slice(UInt8)

    property headers64 : String = ""
    property payload64 : String = ""
    property signature64 : String = ""

    def initialize(@headers : Hash(String, JSON::Type), @payload : Hash(String, JSON::Type), signature : (Slice(UInt8) | Nil) = nil)
      @signature = encode.to_slice

      if !signature.nil?
        @signature = signature
      end
    end

    def encode(io : IO, key : OpenSSL::RSA, algorithm : JWT::Algorithm)
      @headers["alg"] = algorithm.to_s
      encode io

      signature = ""

      signer = Token.get_digest_for(algorithm)

      if !signer.nil?
        signature_part = key.sign(signer, io.to_s)
        signature = Base64.urlsafe_encode(signature_part)
      end

      io << '.' << signature
    end

    def encode(key : OpenSSL::RSA, algorithm : JWT::Algorithm)
      io = IO::Memory.new
      encode(io, key, algorithm)
      io.to_s
    end

    def encode(io : IO)
      headers_part = @headers.to_json
      payload_part = @payload.to_json

      io << Base64.urlsafe_encode(headers_part) << '.' << Base64.urlsafe_encode(payload_part)
    end

    def encode
      io = IO::Memory.new
      encode(io)
      io.to_s
    end

    def self.decode(token : String)
      parts = token.split('.')

      raise JWTError.new "Invalid JWT Token. Must have at least two parts." unless (parts.size >= 2 && parts.size <= 3)

      headers = decode_part_to_json(parts[0])
      payload = decode_part_to_json(parts[1])

      signature = nil
      if parts.size > 2
        signature = Base64.decode(parts[2])
      end

      new(headers, payload, signature).tap do |token|
        token.headers64 = parts[0]
        token.payload64 = parts[1]
        unless signature.nil?
          token.signature64 = parts[2]
        end
      end
    end

    def self.get_digest_for(name : JWT::Algorithm)
      algo = case name
             when Algorithm::RS256
               "sha256"
             when Algorithm::RS384
               "sha384"
             when Algorithm::RS512
               "sha512"
             else
               "none"
             end

      if algo === "none"
        return nil
      end

      OpenSSL::Digest.new algo
    end

    private def self.decode_part_to_json(b64_string : String)
      raise JWTError.new "Invalid JSON in #{b64_string}" unless json = JSON.parse(Base64.decode_string(b64_string)).as_h
      json
    end
  end
end
