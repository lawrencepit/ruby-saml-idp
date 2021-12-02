module SamlIdp
  module Controller
    require 'openssl'
    require 'base64'
    require 'time'

    attr_accessor :x509_certificate, :secret_key, :algorithm
    attr_accessor :saml_acs_url

    def x509_certificate
      return @x509_certificate if defined?(@x509_certificate)
      @x509_certificate = SamlIdp.config.x509_certificate
    end

    def secret_key
      return @secret_key if defined?(@secret_key)
      @secret_key = SamlIdp.config.secret_key
    end

    def algorithm
      return @algorithm if defined?(@algorithm)
      self.algorithm = SamlIdp.config.algorithm
      @algorithm
    end

    def algorithm=(algorithm)
      @algorithm = algorithm
      if algorithm.is_a?(Symbol)
        @algorithm = case algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        else
          OpenSSL::Digest::SHA1
        end
      end
      @algorithm
    end

    def algorithm_name
      algorithm.to_s.split('::').last.downcase
    end

    protected

      def validate_saml_request(saml_request = params[:SAMLRequest])
        decode_SAMLRequest(saml_request) rescue false
      end

      def decode_SAMLRequest(saml_request)
        zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        @saml_request = zstream.inflate(Base64.decode64(saml_request))
        zstream.finish
        zstream.close
        @saml_request_id = @saml_request[/ID=['"](.+?)['"]/, 1]
        @saml_acs_url = @saml_request[/AssertionConsumerServiceURL=['"](.+?)['"]/, 1]
      end

      def encode_SAMLResponse(nameID, opts = {})
        now = Time.now.utc
        response_id, reference_id = SecureRandom.uuid, SecureRandom.uuid
        audience_uri = opts[:audience_uri] || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
        issuer_uri = opts[:issuer_uri] || (defined?(request) && request.url) || "http://example.com"
        attributes_statement = attributes(opts[:attributes_provider], nameID)

        assertion = <<-XML.gsub(/\n\t/, " ").gsub(/>\s*</, "><")
          <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0">
            <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">#{issuer_uri}</saml2:Issuer>
            <saml2:Subject>
              <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{nameID}</saml2:NameID>
              <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml2:SubjectConfirmationData#{@saml_request_id.present? ? %[ InResponseTo="#{@saml_request_id}"] : ""} NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{@saml_acs_url}">
              </saml2:SubjectConfirmationData>
              </saml2:SubjectConfirmation>
            </saml2:Subject>
            <saml2:Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}">
              <saml2:AudienceRestriction>
                <saml2:Audience>#{audience_uri}</saml2:Audience>
              </saml2:AudienceRestriction>
            </saml2:Conditions>
            #{attributes_statement}
            <saml2:AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}">
              <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:federation:authentication:windows</saml2:AuthnContextClassRef>
              </saml2:AuthnContext>
            </saml2:AuthnStatement>
          </saml2:Assertion>
        XML

        digest_value = Base64.encode64(algorithm.digest(assertion.strip)).gsub(/\n/, '')

        signed_info = <<-XML.gsub(/\n\t/, " ").gsub(/>\s*</, "><")
          <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod>
            <ds:Reference URI="#_#{reference_id}">
              <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>
              </ds:Transforms>
              <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod>
              <ds:DigestValue>#{digest_value}</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
        XML

        signature_value = sign(signed_info.strip).gsub(/\n/, '')

        signature = <<-XML.gsub(/\n\t/, " ").gsub(/>\s*</, "><")
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            #{signed_info}
            <ds:SignatureValue>#{signature_value}</ds:SignatureValue>
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
              <ds:X509Data><ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate></ds:X509Data>
            </KeyInfo>
          </ds:Signature>
        XML

        assertion_and_signature = assertion.sub(/Issuer\>\<saml2:Subject/, "Issuer>#{signature}<saml2:Subject")

        xml = <<-XML.gsub(/\n\t/, " ").gsub(/>\s*</, "><")
          <saml2p:Response Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{@saml_acs_url}" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema">
            <saml2:Issuer>"#{issuer_uri}"</saml2:Issuer>
            <saml2p:Status>
              <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
            </saml2p:Status>
            #{assertion_and_signature}
          </saml2p:Response>
        XML

        Base64.encode64(xml)
      end

    private

      def sign(data)
        key = OpenSSL::PKey::RSA.new(self.secret_key)
        Base64.encode64(key.sign(algorithm.new, data))
      end

      def attributes(provider, nameID)
        provider ? provider : %[<saml2:AttributeStatement><saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml2:AttributeValue>#{nameID}</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement>]
      end
  end
end
