# frozen_string_literal: true

require "json"
require_relative "lib/letsbot_identity"

# Rack endpoint: GET /api/letsbot/identity-token. Works the same inside Rails (controller) or Sinatra (route).
class IdentityTokenApp
  # Placeholder authentication — replace with your own session (e.g. current_user in Rails).
  DEMO_SESSIONS = {
    "demo-session" => { id: "user-42", name: "Sara", email: "sara@example.com", phone: "+966501234567" }
  }.freeze

  def initialize(secret: ENV.fetch("LETSBOT_IDENTITY_SECRET", ""))
    @secret = secret
  end

  def call(env)
    headers = { "content-type" => "application/json", "cache-control" => "no-store" }
    return [404, headers, []] unless env["REQUEST_METHOD"] == "GET" && env["PATH_INFO"] == "/api/letsbot/identity-token"

    user = DEMO_SESSIONS[env.fetch("HTTP_AUTHORIZATION", "").sub(/\ABearer\s+/i, "")]
    return [401, headers, ['{"error":"unauthenticated"}']] unless user

    now = Time.now.to_i
    ttl = LetsbotIdentity::DEFAULT_TTL # 24 h recommended, 7 days max
    token = LetsbotIdentity.create_token(user_id: user[:id], secret: @secret, ttl: ttl, now: now,
                                         name: user[:name], email: user[:email], phone: user[:phone])
    [200, headers, [JSON.generate(token: token, expires_at: now + ttl)]]
  end
end
