# frozen_string_literal: true
require 'net/http'
require 'uri'

class JsonWebToken
  def self.verify(token)
    JWT.decode(token, nil,
               true, # Verify the signature of this token
               algorithms: 'RS256',
               iss: 'https://greedy.au.auth0.com/',
               verify_iss: true,
               aud: 'https://greedy.au.auth0.com/api/v2/',
               verify_aud: true) do |header|
      jwks_hash[header['kid']]
    end
  end

  def self.verify_id(token)
    JWT.decode(token, nil,
               true, # Verify the signature of this token
               algorithms: 'RS256',
               iss: 'https://greedy.au.auth0.com/',
               verify_iss: true,
               aud: 'sMtJgmTT4V09OyX74fEzfV0c9fLjMP1L',
               verify_aud: true) do |header|
      jwks_hash[header['kid']]
    end
  end

  def self.jwks_hash
    jwks_raw = Net::HTTP.get URI("https://greedy.au.auth0.com/.well-known/jwks.json")
    jwks_keys = Array(JSON.parse(jwks_raw)['keys'])
    Hash[
      jwks_keys
      .map do |k|
        [
          k['kid'],
          OpenSSL::X509::Certificate.new(
            Base64.decode64(k['x5c'].first)
          ).public_key
        ]
      end
    ]
  end
end

