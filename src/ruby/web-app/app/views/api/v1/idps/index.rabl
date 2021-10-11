object false

node(:draw) { params[:draw].to_i }
node(:recordsTotal) { @idps.count }
node(:recordsFiltered) { @idps.count }
node :data do
  @idps.map do |idp|
    idp.serializable_hash
  end
end
