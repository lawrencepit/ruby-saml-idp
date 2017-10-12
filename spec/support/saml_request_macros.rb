module SamlRequestMacros

  def make_saml_request(requested_saml_acs_url = "https://foo.example.com/saml/consume")
    auth_request = OneLogin::RubySaml::Authrequest.new
    auth_url = auth_request.create(saml_settings(saml_acs_url: requested_saml_acs_url))
    CGI.unescape(auth_url.split("=").last)
  end

  def saml_settings(options = {})
    settings = OneLogin::RubySaml::Settings.new
    settings.assertion_consumer_service_url = options[:saml_acs_url] || "https://foo.example.com/saml/consume"
    settings.issuer = options[:issuer] || "http://example.com/issuer"
    settings.idp_sso_target_url = options[:idp_sso_target_url] || "http://idp.com/saml/idp"
    settings.idp_cert_fingerprint = SamlIdp::Default::FINGERPRINT
    settings.name_identifier_format = SamlIdp::Default::NAME_ID_FORMAT
    settings
  end

  def prepare_saml_request(xml)
    deflated = deflate(xml)
    encode(deflated)
  end

  def encode(encoded)
    Base64.encode64(encoded).gsub(/\n/, "")
  end

  def deflate(inflated)
    Zlib::Deflate.deflate(inflated, 9)[2..-5]
  end

end
