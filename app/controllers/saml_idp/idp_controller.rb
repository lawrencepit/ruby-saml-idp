# encoding: utf-8
module SamlIdp
  class IdpController < ActionController::Base
    include SamlIdp::Controller

    unloadable

    protect_from_forgery

    before_filter :validate_saml_request
    skip_before_filter :validate_saml_request, :only => [:logout]
    before_filter :validate_saml_slo_request, :only => [:logout]

    def new
      render :template => "saml_idp/idp/new"
    end

    def create
      unless params[:email].blank? && params[:password].blank?
        person = idp_authenticate(params[:email], params[:password])
        if person.nil?
          @saml_idp_fail_msg = "Incorrect email or password."
        else
          @saml_response = idp_make_saml_response(person)
          render :template => "saml_idp/idp/saml_post", :layout => false
          return
        end
      end
      render :template => "saml_idp/idp/new"
    end

    def logout
      _person, _logout = idp_slo_authenticate(params[:name_id])
      if _person && _logout
        @saml_slo_response = idp_make_saml_slo_response(_person)
      else
        @saml_idp_fail_msg = 'User not found'
        logger.error "User with email #{params[:name_id]} not found"
        @saml_slo_response = encode_SAML_SLO_Response(params[:name_id])
      end
      render :template => "saml_idp/idp/saml_slo_post", :layout => false
    end

    protected

      def idp_authenticate(email, password)
        raise "Not implemented"
      end

      def idp_make_saml_response(person)
        raise "Not implemented"
      end

      def idp_slo_authenticate(email)
        raise "Not implemented"
      end

      def idp_make_saml_slo_response(person)
        raise "Not implemented"
      end

  end
end
