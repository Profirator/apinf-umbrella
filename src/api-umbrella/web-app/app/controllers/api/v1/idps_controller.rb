class Api::V1::IdpsController < Api::V1::BaseController
  respond_to :json

  skip_after_action :verify_authorized, :only => [:index]
  after_action :verify_policy_scoped, :only => [:index]

  def index
    @idps = policy_scope(Idp).order_by(datatables_sort_array)
  
    if(params[:start].present?)
      @idps = @idps.skip(params["start"].to_i)
    end

    if(params[:length].present?)
      @idps = @idps.limit(params["length"].to_i)
    end

    @idps_count = @idps.count
  end

  def create
    @idp = Idp.new
    save!
    respond_with(:api_v1, @idp, :root => "idp")
  end

  def show
    @idp = Idp.find(params[:id])
    authorize(@idp)
  end

  def update
    @idp = Idp.find(params[:id])
    save!
    respond_with(:api_v1, @idp, :root => "idp")
  end

  def destroy
    @idp = Idp.find(params[:id])
    authorize(@idp)
    @idp.destroy
    respond_with(:api_v1, @idp, :root => "idp")
  end

  private

  def save!
    authorize(@idp) unless(@idp.new_record?)
    @idp.assign_attributes(idp_params)
    authorize(@idp)
    @idp.save
  end

  def idp_params
    params.require(:idp).permit([
      :type,
      :endpoint,
      :public_key,
      :secret,
      :organization_id
    ])
  rescue => e
    logger.error("Parameters error: #{e}")
    ActionController::Parameters.new({}).permit!
  end
end
