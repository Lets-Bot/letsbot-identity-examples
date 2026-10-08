# frozen_string_literal: true

require "minitest/autorun"
require "base64"
require "json"
require "openssl"
require_relative "../app"

class IdentityTest < Minitest::Test
  SECRET = "letsbot-test-identity-secret-0123456789"

  # Independent HS256 check (no JWT library).
  def verify_hs256(token, secret)
    h, p, s = token.split(".")
    return nil unless JSON.parse(Base64.urlsafe_decode64(h))["alg"] == "HS256"

    expected = OpenSSL::HMAC.digest("SHA256", secret, "#{h}.#{p}")
    return nil unless OpenSSL.fixed_length_secure_compare(expected, Base64.urlsafe_decode64(s))

    JSON.parse(Base64.urlsafe_decode64(p))
  end

  def test_token_verifies_with_sub_iat_exp
    token = LetsbotIdentity.create_token(user_id: 42, secret: SECRET, now: 1_791_446_400, phone: "")
    assert_equal({ "sub" => "42", "iat" => 1_791_446_400, "exp" => 1_791_532_800 }, verify_hs256(token, SECRET))
    assert_nil verify_hs256(token, "#{SECRET}x")

    decoded, = JWT.decode(token, SECRET, true, algorithm: "HS256", verify_expiration: false)
    assert_equal "42", decoded["sub"]
  end

  def test_rejects_bad_input
    assert_raises(ArgumentError) { LetsbotIdentity.create_token(user_id: "u", secret: "") }
    assert_raises(ArgumentError) { LetsbotIdentity.create_token(user_id: " ", secret: SECRET) }
    assert_raises(ArgumentError) { LetsbotIdentity.create_token(user_id: "x" * 192, secret: SECRET) }
    assert_raises(ArgumentError) { LetsbotIdentity.create_token(user_id: "u", secret: SECRET, ttl: 604_801) }
  end

  def test_endpoint
    app = IdentityTokenApp.new(secret: SECRET)
    status, = app.call("REQUEST_METHOD" => "GET", "PATH_INFO" => "/api/letsbot/identity-token")
    assert_equal 401, status

    status, headers, body = app.call("REQUEST_METHOD" => "GET", "PATH_INFO" => "/api/letsbot/identity-token",
                                     "HTTP_AUTHORIZATION" => "Bearer demo-session")
    assert_equal 200, status
    assert_equal "no-store", headers["cache-control"]
    json = JSON.parse(body.join)
    claims = verify_hs256(json["token"], SECRET)
    assert_equal "user-42", claims["sub"]
    assert_equal 86_400, claims["exp"] - claims["iat"]
    assert_equal claims["exp"], json["expires_at"]
  end
end
