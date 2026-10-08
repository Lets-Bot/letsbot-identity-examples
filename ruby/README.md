# Ruby (`jwt` gem)

- `lib/letsbot_identity.rb` — `LetsbotIdentity.create_token(user_id:, secret:, ttl:, name:, email:, phone:)`
- `app.rb` / `config.ru` — Rack `GET /api/letsbot/identity-token` (placeholder auth — replace with your own)

Rails:

```ruby
class LetsbotIdentityTokensController < ApplicationController
  before_action :authenticate_user!

  def show
    token = LetsbotIdentity.create_token(user_id: current_user.id, secret: ENV.fetch("LETSBOT_IDENTITY_SECRET"),
                                         name: current_user.name, email: current_user.email)
    response.headers["Cache-Control"] = "no-store"
    render json: { token: token }
  end
end
# routes.rb: get "/api/letsbot/identity-token", to: "letsbot_identity_tokens#show"
```

## Run

```bash
bundle install
bundle exec ruby test/identity_test.rb
LETSBOT_IDENTITY_SECRET=... bundle exec rackup
curl -H 'Authorization: Bearer demo-session' http://localhost:9292/api/letsbot/identity-token
```
