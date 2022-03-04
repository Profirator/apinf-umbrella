local config = require "api-umbrella.proxy.models.file_config"
local ishare = require "api-umbrella.utils.ishare"
local cjson = require "cjson"

-- Checks if a table with a list of values contains a specific element
local function has_value (tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

-- Builds a table/array with the required policies
local function build_required_policies()
   local policies = {}
   local policy = {}

   -- Get action from HTTP method
   local method = string.upper(ngx.req.get_method())
   if method ~= "POST" then
      return nil, "Only POST request is supported for Sidecar-Proxy Enpoint Configuration Service [HTTP method: "..method.."]"
   end

   -- Only /endpoint path is supported
   local in_uri = string.gsub(ngx.var.request_uri, "?.*", "") -- Stripped query args
   local check_endpoint = string.match(in_uri, ".*/endpoint")
   if not check_endpoint then
      return nil, "Only /endpoint path is supported"
   end
   check_endpoint = string.match(in_uri, ".*/endpoint(/.*)")
   if check_endpoint then
      return nil, "No parameters for /endpoint path are supported"
   end

   -- Validate body
   ngx.req.read_body()
   local body_data = ngx.req.get_body_data()
   local body_json = cjson.decode(body_data)
   if (not body_json["authType"]) or (body_json["authType" ~= "iShare"]) then
      return nil, "Only 'iShare' authType supported"
   end
   if (not body_json["authCredentials"]) then
      return nil, "Missing parameter 'authCredentials'"
   end
   if (not body_json["authCredentials"]["iShareIdpId"]) then
      return nil, "Missing EORI of token endpoint (parameter: iShareIdpId)"
   end
   
   -- Resource object
   policy.target = {}
   policy.target.resource = {}
   policy.target.resource.type = "EndpointConfig"

   local identifier = {}
   table.insert(identifier, "*")
   policy.target.resource.identifiers = identifier

   local attrs = {}
   table.insert(attrs, "*")
   policy.target.resource.attributes = attrs

   -- Action
   policy.target.actions = {}
   table.insert(policy.target.actions, method )

   -- Set permit rule
   policy.rules = {}
   local rule = {}
   rule.effect = "Permit"
   table.insert(policy.rules, rule)

   -- Add policy to array
   table.insert(policies, policy)
   
   return policies, nil

end

-- Get delegation evidence from external authorisation registry
local function get_delegation_evidence_ext(issuer, target, policies, token_url, ar_eori, delegation_url, prev_steps)
   local del_evi = {}

   -- Get token at external AR
   local local_eori = config["jws"]["identifier"]
   local token, err = ishare.get_token(token_url, local_eori, local_eori, ar_eori)
   if err then
      return nil, err
   end
   
   -- Get delegation evidence from external AR
   del_evi, err = ishare.get_delegation_evidence(issuer, target, policies, delegation_url, token, prev_steps)
   if err then
      return nil, err
   end

   return del_evi, nil
end

-- Validate policies for incoming Sidecar-Proxy Auth Endpoint Service request
return function(settings, user)
   
   -- If this API does not require Sidecar-Proxy Authorization endpoint configuration service authorisation, continue on
   if (not settings) or (not settings["auth_mode"]) or settings["auth_mode"] ~= "sidecar_proxy_auth_endpoint_config_ishare" then
      return nil
   end
   

   -- Check for required config parameters for AR
   local err, err_data = ishare.check_config_ar()
   if err then
      return err, err_data
   end

   -- Validate incoming iSHARE JWT 
   local err = ishare.validate_ishare_jwt(user["api_key"])
   if err then
      return "policy_validation_failed", {
	       validation_error = "Authorization JWT could not be validated: "..err
      }
   end

   -- Build required policy from incoming request
   local req_policies, err = build_required_policies()
   if err then
      return "policy_validation_failed", {
	       validation_error = err
      }
   end

   -- Enforce M2M interaction
   -- Check that JWT was issued by local EORI, otherwise throw error
   local local_eori = config["jws"]["identifier"]
   if local_eori ~= user["iss"] then
      return "policy_validation_failed", {
	 validation_error = "Authorization JWT was not issued by local authority"
      }
   end

   -- Check for policy at local AR
   local local_token_url = config["authorisation_registry"]["token_endpoint"]
   local local_ar_eori = config["authorisation_registry"]["identifier"]
   local local_delegation_url = config["authorisation_registry"]["delegation_endpoint"]
   local local_delegation_evidence, err = get_delegation_evidence_ext(local_eori, user["sub"], req_policies, local_token_url, local_ar_eori, local_delegation_url, nil)
   if err then
      return "policy_validation_failed", {
	 validation_error = "Error when retrieving policies from local AR: "..err
      }
   end

   -- Compare policy target subject with authCredentials token endpoint EORI
   if (not local_delegation_evidence["target"]) or (not local_delegation_evidence["target"]["accessSubject"]) then
      return "policy_validation_failed", {
	 validation_error = "Missing target access subject in local policy"
      }
   end
   local targetsub = local_delegation_evidence["target"]["accessSubject"]
   ngx.req.read_body()
   local body_data = ngx.req.get_body_data()
   local body_json = cjson.decode(body_data)
   local endpoint_eori =  body_json["authCredentials"]["iShareIdpId"]
   if targetsub ~= endpoint_eori then
      return "policy_validation_failed", {
	 validation_error = "Authorization /token endpoint EORI (parameter: iShareIdpId) does not match policy access subject EORI"
      }
   end

   -- Policy validated, access granted
end
