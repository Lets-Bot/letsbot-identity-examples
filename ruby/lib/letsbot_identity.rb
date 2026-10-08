# frozen_string_literal: true

require "jwt"

# LetsBot In-App Chat identity token: JWT, HS256, signed with the app's Identity Secret.
module LetsbotIdentity
  MAX_TTL = 7 * 24 * 60 * 60
  DEFAULT_TTL = 24 * 60 * 60

  module_function

  def create_token(user_id:, secret:, ttl: DEFAULT_TTL, name: nil, email: nil, phone: nil, now: Time.now.to_i)
    raise ArgumentError, "Identity Secret is missing" if secret.nil? || secret.empty?

    sub = user_id.to_s.strip
    raise ArgumentError, "user_id must be 1-191 characters" if sub.empty? || sub.length > 191
    raise ArgumentError, "ttl must be between 1 and 604800 seconds" unless ttl.is_a?(Integer) && ttl.between?(1, MAX_TTL)

    claims = { sub: sub, iat: now, exp: now + ttl, name: name, email: email, phone: phone }
    claims.reject! { |_, value| value.nil? || value == "" }
    JWT.encode(claims, secret, "HS256")
  end
end
