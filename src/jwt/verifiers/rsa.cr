module JWT::Verifier
  module RSA
    def self.verify(token : JWT::Token, public_key : OpenSSL::RSA, algorithm : JWT::Algorithm)
      signature = token.signature

      if signature.nil?
        return false
      end

      unencrypted = token.encode
      digest = Token.get_digest_for(algorithm)

      if digest.nil?
        return false
      end

      public_key.verify(digest, signature, unencrypted)
    end
  end
end
