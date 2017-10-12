# encoding: utf-8
require 'logger'

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
        xml_doc  = Nokogiri::XML(@saml_request)do |config|
          # Strict parsing; raise an error when parsing malformed documents
          config.strict
        end
        auth_request = xml_doc.xpath('//samlp:AuthnRequest').first
        @saml_request_id = auth_request['ID']
        @saml_acs_url = auth_request['AssertionConsumerServiceURL']
      end

      def encode_SAMLResponse(nameID, opts = {})
        now = Time.now.utc
        encoded_saml_acs_url = @saml_acs_url.encode(xml: :attr)

        response_id, reference_id = SecureRandom.uuid, SecureRandom.uuid
        audience_uri = opts[:audience_uri] || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
        issuer_uri = opts[:issuer_uri] || (defined?(request) && request.url) || "http://example.com"
        attributes_statement = attributes(opts[:attributes_provider], nameID)

        assertion = %[<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0"><saml:Issuer Format="urn:oasis:names:SAML:2.0:nameid-format:entity">#{issuer_uri}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{nameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="#{@saml_request_id}" NotOnOrAfter="#{(now+3*60).iso8601}" Recipient=#{encoded_saml_acs_url}></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><saml:AudienceRestriction><saml:Audience>#{audience_uri}</saml:Audience></saml:AudienceRestriction></saml:Conditions>#{attributes_statement}<saml:AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:federation:authentication:windows</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>]

        digest_value = Base64.encode64(algorithm.digest(assertion)).gsub(/\n/, '')

        signed_info = %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod><ds:Reference URI="#_#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]

        signature_value = sign(signed_info).gsub(/\n/, '')

        signature = %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature>]

        assertion_and_signature = assertion.sub(/Issuer\>\<saml:Subject/, "Issuer>#{signature}<saml:Subject")

        xml = %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination=#{encoded_saml_acs_url} Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="#{@saml_request_id}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]

        Base64.encode64(xml)
      end

    private

      def sign(data)
        key = OpenSSL::PKey::RSA.new(self.secret_key)
        Base64.encode64(key.sign(algorithm.new, data))
      end

      def attributes(provider, nameID)
        provider ? provider : %[<saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>#{nameID}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>]
      end
  end
end
