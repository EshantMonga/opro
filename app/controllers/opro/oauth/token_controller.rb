# This controller is where clients can exchange
# codes and refresh_tokens for access_tokens

class Opro::Oauth::TokenController < OproController
  before_filter :opro_authenticate_user!, except: [:create]
  skip_before_filter :verify_authenticity_token, only: [:create]
  skip_before_filter :authenticate_user!, only: [:create]

  def create
    # Find the client application
    application = Opro::Oauth::ClientApp.authenticate(
      params[:client_id], params[:client_secret])
    auth_grant = auth_grant_for(application, params)
    if application.present? && auth_grant.present?
      auth_grant.refresh!
      json_obj = {
        access_token: auth_grant.access_token,
        token_type: 'bearer',
        refresh_token: auth_grant.refresh_token,
        expires_in: auth_grant.expires_in
      }
      render json: json_obj
    else
      render_error debug_msg(params, application)
    end
  end

  private

  def auth_grant_for(application, params)
    if params[:code]
      Opro::Oauth::AuthGrant.find_by_code_app(params[:code], application)
    elsif params[:refresh_token]
      Opro::Oauth::AuthGrant.find_by_refresh_app(params[:refresh_token], application)
    end
  end

  def debug_msg(options, app)
    "Could not find a user that belongs to this application"
  end

  def render_error(msg)
    render :json => {:error => msg }, :status => :unauthorized
  end
end
