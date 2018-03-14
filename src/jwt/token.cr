require "openssl_ext"
require "json"
require "../jwt"

module JWT
  class Token
    getter headers
    getter payload
    getter signature

    def initialize(@headers : Hash(String, JSON::Type), @payload : Hash(String, JSON::Type), @signature : (Slice(UInt8) | Nil) = nil)
    end

    def encode(io : IO, key : OpenSSL::RSA, algorithm : JWT::Algorithm)
      encode io

      signature = ""

      signer = digest(algorithm)

      if !signer.nil?
        signature_part = key.sign(signer, io.to_s.to_slice).to_s
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
      headers_part = @headers.to_json.to_s
      payload_part = @payload.to_json.to_s

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

      headers = decode_part_to_json(parts.shift)
      payload = decode_part_to_json(parts.shift)

      signature = nil
      if parts.size == 1
        signature = Base64.decode(parts.shift)
      end

      new(headers, payload, signature)
    end

    private def self.decode_part_to_json(b64_string : String)
      raise JWTError.new "Invalid JSON in #{b64_string}" unless json = JSON.parse(Base64.decode_string(b64_string)).as_h
      json
    end

    private def digest(name : JWT::Algorithm) : (OpenSSL::Digest | Nil)
      algo = case name
             when Algorithm::RS256
               "sha256"
             else
               "none"
             end

      if algo === "none"
        return nil
      end

      OpenSSL::Digest.new algo
    end
  end
end
