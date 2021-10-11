require "common_validations"

class Idp
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Paranoia
  include Mongoid::Userstamp
  include Mongoid::Delorean::Trackable

  # Fields
  field :_id, :type => String, :overwrite => true, :default => lambda { SecureRandom.uuid }
  field :type, :type => String
  field :endpoint, :type => String
  field :organization_id, :type => String
  field :public_key, :type => String
  field :secret, :type => String

  # Validations
  validates :type,
    :inclusion => { :in => ["keycloak", "keyrock"] }
  validates :endpoint,
    :presence => true

  def self.sorted
    order_by(:endpoint.asc)
  end
  
  def attributes_hash
    Hash[self.attributes]
  end
end