$LOAD_PATH.unshift File.expand_path(File.dirname(__FILE__))

require './boot'
require 'yaml/store'
require_relative 'lib/secrets'
require_relative 'lib/urls'
require_relative 'lib/token'
require_relative 'lib/simple_api'
require_relative 'lib/store'
require 'securerandom'

Dotenv.load

if !ENV["REDIS_URL"].nil?
  STORE_CLASS = Store::Redis
else
  STORE_CLASS = Store::LocalYaml
end

class App < Sinatra::Application
  configure do
    urls = Urls.for_env
    secrets = Secrets.for_env

    use Rack::Session::Cookie

    use OmniAuth::Builder do
      provider :salesloft, secrets.app_id, secrets.app_secret,
      client_options: {
        site: urls.site_url,
        authorize_url: urls.authorize_url,
        token_url: urls.token_url
      },
      origin_param: 'return_to' # support ?return_to=blah param
    end

    set :protection, except: :frame_options
  end

  helpers do
    # Shared decrypt step used by every slot route. Returns [tenant_id, integration_id, unique_id, decrypted]
    def decrypt_portal_payload!
      tenant_id = request.params["tenant_id"]
      integration_id = request.params["integration_id"]
      unique_id = SecureRandom.uuid()
      store = STORE_CLASS.new(tenant_id, integration_id)
      store.save_unique_id!(unique_id)
      secret = store.get_property(:secret)
      jwk = JOSE::JWK.from_oct(Digest::SHA256.digest(secret))
      payload = jwk.block_decrypt(request.params["payload"])[0]
      decrypted = JSON.parse(payload)
      [tenant_id, integration_id, unique_id, decrypted]
    end

    # "Complete Action" link — relevant mainly to Custom Step integrations, but harmless elsewhere
    def action_button_html(tenant_id, integration_id, decrypted)
      return "" unless (id = decrypted.dig("action", "id"))
      nonce = decrypted.fetch("nonce")
      origin = decrypted.fetch("origin")
      <<-HTML
      <div>
        <a href="/#{tenant_id}/#{integration_id}/complete/action/#{id}/#{nonce}?origin=#{origin}">Complete Action</a>
      </div>
      HTML
    end

    # Shared "insert HTML into editor" demo button + postMessage wiring — relevant to Email/Template Editor
    def insert_html_demo(decrypted, unique_id, integration_id, metadata)
      <<-HTML
      <p><a id="insertSomeHtml" href="#">Insert some HTML</a></p>
      <script type="text/javascript" src="/buttons.js"></script>
      <script type="text/javascript">
        window.json = #{request.params.merge(decrypted: decrypted, unique_id: unique_id, metadata: metadata).to_json}
        document.getElementById("insertSomeHtml").onclick = () => {
          let str = "<strong>SalesLoft</strong><span> HTML demo</span>";
          if (json.decrypted.person) {
            str += ` <strong>Person:</strong><span>${json.decrypted.person.id}</span>`;
          }
          window.parent.postMessage({event: "insertHtml", html: `<span>${str}</span>`, nonce: json.decrypted.nonce, unique_id: json.unique_id, integration_id: json.integration_id, metadata: json.metadata}, json.decrypted.origin);
          return false;
        };
      </script>
      HTML
    end

    def debug_details(request_params, decrypted, unique_id, metadata)
      <<-HTML
      <details>
        <summary>Raw payload (debug)</summary>
        <pre>#{request_params.merge(decrypted: decrypted, unique_id: unique_id, metadata: metadata).to_json}</pre>
      </details>
      HTML
    end

    def card_wrapper(inner_html)
      <<-HTML
      <html>
        <body style="font-family: sans-serif;">
          #{inner_html}
        </body>
      </html>
      HTML
    end
  end

  get '/auth/failure' do
    request.inspect
  end

  # ---------------------------------------------------------------------
  # Original generic echo route — left in place for quick raw-payload debugging
  # ---------------------------------------------------------------------
  post '/portal/echo' do
    tenant_id, integration_id, unique_id, decrypted = decrypt_portal_payload!
    metadata = "{\"time_added\": \"#{Time.now}\", \"additional_notes\": \"Some notes :)\"}"

    card_wrapper(<<-HTML)
      #{action_button_html(tenant_id, integration_id, decrypted)}
      <p><a href="/other">Other Page</a></p>
      #{insert_html_demo(decrypted, unique_id, integration_id, metadata)}
      #{debug_details(request.params, decrypted, unique_id, metadata)}
    HTML
  end

  # ---------------------------------------------------------------------
  # Full Page Integration — no special postMessage capabilities per the docs;
  # just confirms the app loaded full-page and shows session identifiers.
  # ---------------------------------------------------------------------
  post '/portal/full-page' do
    tenant_id, integration_id, unique_id, decrypted = decrypt_portal_payload!
    metadata = "{\"time_added\": \"#{Time.now}\"}"

    card_wrapper(<<-HTML)
      <div style="border: 1px solid #ddd; border-radius: 8px; padding: 24px; max-width: 480px;">
        <h2 style="margin-top:0;">Full Page Integration — Test View</h2>
        <p style="color:#666;">This route has no special Salesloft frontend capabilities — it's just embedded as a full page.</p>
        <p><strong>Tenant ID:</strong> #{tenant_id}</p>
        <p><strong>Integration ID:</strong> #{integration_id}</p>
      </div>
      #{debug_details(request.params, decrypted, unique_id, metadata)}
    HTML
  end

  # ---------------------------------------------------------------------
  # Person Smart Panel Integration — 320px tall, fluid width. Renders person + account context.
  # ---------------------------------------------------------------------
  post '/portal/person-panel' do
    tenant_id, integration_id, unique_id, decrypted = decrypt_portal_payload!
    metadata = "{\"time_added\": \"#{Time.now}\", \"additional_notes\": \"Some notes :)\"}"
    person = decrypted["person"]
    account = decrypted["account"]

    summary_card = ""
    if person
      summary_card = <<-HTML
        <div style="border: 1px solid #ddd; border-radius: 8px; padding: 16px; max-width: 360px;">
          <h2 style="margin: 0 0 4px;">#{person["display_name"]}</h2>
          <p style="margin: 0 0 12px; color: #666;">#{person["title"] || "No title on file"}</p>
          <p style="margin: 4px 0;"><strong>Email:</strong> #{person["email_address"]}</p>
          <p style="margin: 4px 0;"><strong>Phone:</strong> #{person["phone"] || "—"}</p>
          #{account ? "<p style='margin: 4px 0;'><strong>Account:</strong> #{account["name"]}</p>" : ""}
          <p style="margin: 4px 0;"><strong>Last contacted:</strong> #{person["last_contacted_at"] || "Never"}</p>
        </div>
      HTML
    end

    card_wrapper(<<-HTML)
      #{summary_card}
      #{action_button_html(tenant_id, integration_id, decrypted)}
      #{insert_html_demo(decrypted, unique_id, integration_id, metadata)}
      #{debug_details(request.params, decrypted, unique_id, metadata)}
    HTML
  end

  # ---------------------------------------------------------------------
  # Account Smart Panel Integration — 320px tall, fluid width. Renders account context.
  # NOTE: haven't independently confirmed the exact payload shape Salesloft sends for this
  # slot type (docs don't spell out the JSON schema) — this defensively checks for "account"
  # and falls back gracefully if fields are missing. Verify against the real payload once tested.
  # ---------------------------------------------------------------------
  post '/portal/account-panel' do
    tenant_id, integration_id, unique_id, decrypted = decrypt_portal_payload!
    metadata = "{\"time_added\": \"#{Time.now}\"}"
    account = decrypted["account"]

    summary_card = ""
    if account
      summary_card = <<-HTML
        <div style="border: 1px solid #ddd; border-radius: 8px; padding: 16px; max-width: 360px;">
          <h2 style="margin: 0 0 4px;">#{account["name"]}</h2>
          <p style="margin: 0 0 12px; color: #666;">#{account["industry"] || "No industry on file"}</p>
          <p style="margin: 4px 0;"><strong>Website:</strong> #{account["website"] || "—"}</p>
          <p style="margin: 4px 0;"><strong>Phone:</strong> #{account["phone"] || "—"}</p>
          <p style="margin: 4px 0;"><strong>Size:</strong> #{account.dig("counts", "people") || "—"} people tracked</p>
          <p style="margin: 4px 0;"><strong>Last contacted:</strong> #{account["last_contacted_at"] || "Never"}</p>
        </div>
      HTML
    else
      summary_card = "<p>No account context present in this payload.</p>"
    end

    card_wrapper(<<-HTML)
      #{summary_card}
      #{debug_details(request.params, decrypted, unique_id, metadata)}
    HTML
  end

  # ---------------------------------------------------------------------
  # Custom Step Integration — ~598x400px. Surfaces step_type/task_type and the
  # action-completion flow (Complete Action link + postMessage("completedAction")).
  # ---------------------------------------------------------------------
  post '/portal/custom-step' do
    tenant_id, integration_id, unique_id, decrypted = decrypt_portal_payload!
    metadata = "{\"time_added\": \"#{Time.now}\"}"
    step_type = request.params["step_type"]
    task_type = request.params["task_type"]
    person = decrypted["person"]

    card_wrapper(<<-HTML)
      <div style="border: 1px solid #ddd; border-radius: 8px; padding: 16px; max-width: 560px;">
        <h2 style="margin-top:0;">Custom Step — Test View</h2>
        <p style="margin: 4px 0;"><strong>Step type:</strong> #{step_type.nil? || step_type.empty? ? "—" : step_type}</p>
        <p style="margin: 4px 0;"><strong>Task type:</strong> #{task_type.nil? || task_type.empty? ? "—" : task_type}</p>
        #{person ? "<p style='margin: 4px 0;'><strong>Person:</strong> #{person["display_name"]}</p>" : ""}
        #{action_button_html(tenant_id, integration_id, decrypted)}
        <p style="color:#666; font-size: 0.9em;">After calling the Complete Action API, this route also demonstrates telling the frontend immediately via <code>postMessage({event: "completedAction", ...})</code> — see the action link's target route below.</p>
      </div>
      #{debug_details(request.params, decrypted, unique_id, metadata)}
    HTML
  end

  # ---------------------------------------------------------------------
  # Email & Template Editor Integration — 798x450px popup. Demonstrates the
  # insertHtml postMessage event used to insert content into the editor.
  # ---------------------------------------------------------------------
  post '/portal/email-editor' do
    tenant_id, integration_id, unique_id, decrypted = decrypt_portal_payload!
    metadata = "{\"time_added\": \"#{Time.now}\"}"

    # Default message shown for review/editing before insertion into the email body.
    # NOTE: "{{name}}" here is left as literal placeholder text — it will NOT automatically
    # resolve to a Salesloft merge field unless it matches Salesloft's actual token syntax.
    # Verify the correct merge-field format if you want it to auto-populate the recipient's name.
    default_message = <<~MSG
      Hi {{name}},

      I noticed that you recently paid us a visit. We're so excited that you've decided to join the Jedi and take a path on the light side. This will bring balance to the force and help to ensure that our future is secure.

      If you wouldn't mind, we really appreciate it if you would cancel Order 66 and stop mentoring Anakin. His a catalyst for our future destruction and our survival is dependent upon him choosing to remain a part of the Jedi Knight.

      Thank you for your attention to this matter.
    MSG

    card_wrapper(<<-HTML)
      <div style="border: 1px solid #ddd; border-radius: 8px; padding: 16px; max-width: 720px;">
        <h2 style="margin-top:0;">Email &amp; Template Editor — Test View</h2>
        <p style="color:#666; margin-top:0;">Review or edit the message below, then click Insert to add it to the email body.</p>
        <textarea id="emailDraft" rows="12" style="width: 100%; font-family: sans-serif; font-size: 14px; padding: 8px; box-sizing: border-box;">#{default_message.strip}</textarea>
        <p><button id="insertEmailHtml" type="button">Insert into Email</button></p>
      </div>

      <script type="text/javascript">
        window.json = #{request.params.merge(decrypted: decrypted, unique_id: unique_id, metadata: metadata).to_json}
        document.getElementById("insertEmailHtml").onclick = () => {
          const text = document.getElementById("emailDraft").value;
          const html = text
            .split("\\n\\n")
            .map(p => `<p>${p.replace(/\\n/g, "<br>")}</p>`)
            .join("");

          // Matching the documented shape exactly: event, html, nonce only.
          // (Previously also sent unique_id/integration_id/metadata, which the docs example
          // doesn't include -- testing whether the extra fields were causing Salesloft's
          // listener to silently ignore the message.)
          window.parent.postMessage({event: "insertHtml", html: html, nonce: json.decrypted.nonce}, json.decrypted.origin);
        };
      </script>
      #{debug_details(request.params, decrypted, unique_id, metadata)}
    HTML
  end

  get '/other' do
    <<-HTML
      <html>
        <body>
          <p>On the other page. There's nothing to do here.</p>

          <script type="text/javascript" src="/buttons.js"></script>
        </body>
      </html>
    HTML
  end

  get '/:tenant_id/:integration_id/complete/action/:id/:nonce' do
    tenant_id = params.fetch(:tenant_id)
    integration_id = params.fetch(:integration_id)
    id = params.fetch(:id)
    nonce = params.fetch(:nonce)
    origin = params.fetch(:origin)
    store = STORE_CLASS.new(tenant_id, integration_id)
    token = Token.new(store).access_token
    api = SimpleApi.new(access_token: token)

    # The action must be completed through the API
    result = api.complete_action(id)

    <<-HTML
    <html>
      <body>
        <div>Completed #{id}</div>

        <pre>#{result.to_json}</pre>

        <script type="text/javascript">
          window.parent.postMessage({event: "completedAction", actionId: #{id}, nonce: '#{nonce}'}, "#{origin}");
        </script>
      </body>
    </html>
    HTML
  end

  # Handle receiving a succesful OAuth. We must store the credentials and the secret in
  #   such a way that can be retrieved using the tenant / integration ID
  get '/auth/salesloft/callback' do
    credentials = request.env['omniauth.auth'][:credentials]
    tenant_id = request.env['omniauth.strategy'].access_token["tenant_id"]
    integration_id = request.env['omniauth.strategy'].access_token["integration_id"]
    store = STORE_CLASS.new(tenant_id, integration_id)
    store.save_credentials!(credentials)
    store.save_secret!(request.env['omniauth.strategy'].access_token["secret"])

    origin = request.env['omniauth.origin']
    redirect origin.nil? ? '/success' : origin
  end
end
