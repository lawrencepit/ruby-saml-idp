# encoding: utf-8
require 'spec_helper'

describe SamlIdp::Controller do
  include SamlIdp::Controller

  def params
    @params ||= {}
  end

  it "should find the SAML ACS URL" do
    requested_saml_acs_url = "https://example.com/saml/consume"
    params[:SAMLRequest] = make_saml_request(requested_saml_acs_url)
    validate_saml_request
    expect(saml_acs_url).to eq(requested_saml_acs_url)
  end

  context "SAML Responses" do
    before(:each) do
      params[:SAMLRequest] = make_saml_request
      validate_saml_request
    end

    it "should create a SAML Response" do
      saml_response = encode_SAMLResponse("foo@example.com")
      response = OneLogin::RubySaml::Response.new(saml_response)
      expect(response.name_id).to eq("foo@example.com")
      expect(response.issuer).to eq("http://example.com")
      response.settings = saml_settings
      expect(response.is_valid?).to be true
    end

    it "should handle custom attribute objects" do
      provider = double(to_s: %[<saml:AttributeStatement><saml:Attribute Name="organization"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Organization name</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>])

      default_attributes = %[<saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>foo@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>]


      saml_response = encode_SAMLResponse("foo@example.com", { attributes_provider: provider })
      response = OneLogin::RubySaml::Response.new(saml_response)
      expect(response.response).to include provider.to_s
      expect(response.response).to_not include default_attributes
    end

    [:sha1, :sha256, :sha384, :sha512].each do |algorithm_name|
      it "should create a SAML Response using the #{algorithm_name} algorithm" do
        self.algorithm = algorithm_name
        saml_response = encode_SAMLResponse("foo@example.com")
        response = OneLogin::RubySaml::Response.new(saml_response)
        expect(response.name_id).to eq("foo@example.com")
        expect(response.issuer).to eq("http://example.com")
        response.settings = saml_settings
        expect(response.is_valid?).to be true
      end
    end
  end
end
