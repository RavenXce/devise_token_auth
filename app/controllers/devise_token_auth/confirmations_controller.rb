module DeviseTokenAuth
  class ConfirmationsController < DeviseTokenAuth::ApplicationController
    # this action is responsible for regenerating confirmation tokens and
    # sending emails
    def create
      unless params[:email]
        return render json: {
                          success: false,
                          errors: [I18n.t("devise_token_auth.confirmations.missing_email")]
                      }, status: 400
      end

      # give redirect value from params priority
      redirect_url = params[:confirm_success_url]

      # fall back to default value if provided
      redirect_url ||= DeviseTokenAuth.default_confirm_success_url

      # success redirect url is required
      unless redirect_url
        return render json: {
                          status: 'error',
                          data:   @resource.as_json,
                          errors: [I18n.t("devise_token_auth.confirmations.missing_confirm_success_url")]
                      }, status: 400
      end

      # if whitelist is set, validate redirect_url against whitelist
      if DeviseTokenAuth.redirect_whitelist
        unless DeviseTokenAuth.redirect_whitelist.include?(redirect_url)
          return render json: {
                            status: 'error',
                            data:   @resource.as_json,
                            errors: [I18n.t("devise_token_auth.confirmations.redirect_url_not_allowed", redirect_url: redirect_url)]
                        }, status: 400
        end
      end

      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(:email)
        email = params[:email].downcase
      else
        email = params[:email]
      end

      q = "uid = ? AND provider='email'"

      # fix for mysql default case insensitivity
      if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
        q = "BINARY uid = ? AND provider='email'"
      end

      @resource = resource_class.where(q, email).first

      errors = nil
      error_status = 400

      if @resource
        if @resource.confirmed?
          errors = [I18n.t("devise_token_auth.confirmations.already_confirmed", email: email)]
        else
          @resource.send_confirmation_instructions({
                                                       client_config: params[:config_name],
                                                       redirect_url: redirect_url
                                                   })
          yield if block_given?

          if @resource.errors.empty?
            render json: {
                       success: true,
                       message: I18n.t("devise_token_auth.confirmations.email_sent", email: email)
                   }
          else
            errors = @resource.errors
          end
        end
      else
        errors = [I18n.t("devise_token_auth.confirmations.user_not_found", email: email)]
        error_status = 404
      end

      if errors
        render json: {
                   success: false,
                   errors: errors,
               }, status: error_status
      end
    end

    def show
      @resource = resource_class.confirm_by_token(params[:confirmation_token])

      if @resource and @resource.id
        # create client id
        client_id  = SecureRandom.urlsafe_base64(nil, false)
        token      = SecureRandom.urlsafe_base64(nil, false)
        token_hash = BCrypt::Password.create(token)
        expiry     = (Time.now + DeviseTokenAuth.token_lifespan).to_i

        @resource.tokens[client_id] = {
          token:  token_hash,
          expiry: expiry
        }

        @resource.save!

        yield if block_given?

        redirect_to(@resource.build_auth_url(params[:redirect_url], {
          token:                        token,
          client_id:                    client_id,
          account_confirmation_success: true,
          config:                       params[:config]
        }))
      else
        raise ActionController::RoutingError.new('Not Found')
      end
    end
  end
end
