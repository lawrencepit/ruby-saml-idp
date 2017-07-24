# encoding: utf-8
module SamlIdp
  class IdpController < ActionController::Base
    include SamlIdp::Controller

    unloadable

    protect_from_forgery

    if Rails.version.to_i < 4
      before_filter :validate_saml_request
    else
      before_action :validate_saml_request
    end

    def new
      render :template => "saml_idp/idp/new"
    end

    def create
      if !params[:email].blank? && !params[:password].blank?
        person = idp_authenticate(params[:email], params[:password])
        if person.nil?
          @saml_idp_fail_msg = "Incorrect email or password."
        else
          @saml_response = idp_make_saml_response(person)
          render :template => "saml_idp/idp/saml_post", :layout => false
          return
        end
      else
        @saml_idp_fail_msg = "Please enter your email and password."
      end
      render :template => "saml_idp/idp/new"
    end

    protected

      def idp_authenticate(email, password)
        raise "Not implemented"
      end

      def idp_make_saml_response(person)
        raise "Not implemented"
      end

  end
end
