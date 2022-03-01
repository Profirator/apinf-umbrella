local config = require "api-umbrella.proxy.models.file_config"
local ngsi = require "api-umbrella.utils.ngsi"
local ishare = require "api-umbrella.utils.ishare"
local cjson = require "cjson"

-- Extract the policy parameters from the URI
local function get_policy_parameters()

   -- Obtain HTTP method
   local method, err = ngsi.get_request_action()
   if err then
      return nil, nil, nil, nil, err
   end

   -- Check target of operation (entity, subscription, notification)
   -- Will also validate the request
   local op_target, err = ngsi.check_operation_target(method, nil)
   if err then
      return nil, nil, nil, nil, err
   end

   -- Get entity ID
   local entity_id, err = ngsi.get_ngsi_entity_id(method, op_target)
   if err then
      return nil, nil, nil, nil, err
   end
   -- Policy requires ID as array
   local entities = {}
   table.insert(entities, entity_id)
   
   -- Get entity type
   local entity_type, err = ngsi.get_ngsi_entity_type(method, entity_id, op_target)
   if err then
      return nil, nil, nil, nil, err
   end
   
   -- Get attributes
   local attrs, err = ngsi.get_ngsi_entity_attributes(method, entity_id, op_target)
   if err then
      return nil, nil, nil, nil, err
   end
   
   -- Return policy parameters
   return entity_type, entities, attrs, method, nil
   
end

-- Checks if a table with a list of values contains a specific element
local function has_value (tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

-- Builds the required policy based on the incoming request
local function build_policy()
   local policy = {}

   -- Get policy parameters
   local ent_type, entities, attrs, method, err = get_policy_parameters()
   if err then
      return nil, err
   end
   
   -- Build policy object
   policy.target = {}
   policy.target.resource = {}
   if ent_type then
      policy.target.resource.type = ent_type
   end
   if entities then
      policy.target.resource.identifiers = entities
   end
   if attrs then
      policy.target.resource.attributes = attrs
   end
   policy.target.actions = {}
   table.insert(policy.target.actions, method )
   policy.rules = {}
   local rule = {}
   rule.effect = "Permit"
   table.insert(policy.rules, rule)
   
   return policy, nil
end

-- Get delegation evidence from external authorisation registry
local function get_delegation_evidence_ext(issuer, target, policy, token_url, ar_eori, delegation_url, prev_steps)
   local del_evi = {}

   -- Get token at external AR
   local local_eori = config["jws"]["identifier"]
   local token, err = ishare.get_token(token_url, local_eori, local_eori, ar_eori)
   if err then
      return nil, err
   end
   
   -- Get delegation evidence from external AR
   del_evi, err = ishare.get_delegation_evidence(issuer, target, policy, delegation_url, token, prev_steps)
   if err then
      return nil, err
   end

   return del_evi, nil
end

-- Compare user policy with required policy
local function compare_policy(user_policies, req_policy, user_policy_target, req_policy_target)

   -- Check if user IDs are equal
   if user_policy_target ~= req_policy_target then
      return nil, "User IDs do not match: "..user_policy_target.." != "..req_policy_target
   end

   -- Iterate over user policies
   local policy_found = nil
   for user_policy_index, user_policy in ipairs(user_policies) do
      local actions_ok, attrs_ok, type_ok, ids_ok = true, true, true, true
      
      -- Compare policy parameter: action
      local user_actions = user_policy.target.actions
      local req_actions = req_policy.target.actions
      for index, value in ipairs(req_actions) do
	 if not has_value(user_actions, value) then
	    -- Missing action in policy
	    --return "User policy does not contain action "..value
	    actions_ok = false
	 end
      end

      -- Compare policy parameter: attributes
      local user_attrs = user_policy.target.resource.attributes
      local req_attrs = req_policy.target.resource.attributes
      for index, value in ipairs(req_attrs) do
	 if not has_value(user_attrs, value) then
	    -- Missing required attribute
	    --return "User policy does not contain required attribute: "..value
	    attrs_ok = false
	 end
      end
      
      -- Compare policy parameter: type
      local user_type = user_policy.target.resource.type
      local req_type = req_policy.target.resource.type
      if user_type ~= req_type then
	 -- Wrong resource/entity type
	 --return "User policy resource is not of required type: "..req_type.." != "..user_type
	 type_ok = false
      end
      
      -- Compare policy parameter: identifier
      local user_ids = user_policy.target.resource.identifiers
      local req_ids = req_policy.target.resource.identifiers
      -- Check for exact entity IDs
      for index, value in ipairs(req_ids) do
	 if not has_value(user_ids, value) then
	    -- Missing required identifier
	    --return "User policy does not contain required identifier: "..value
	    ids_ok = false
	 end
      end

      -- Policy ok?
      if actions_ok and attrs_ok and type_ok and ids_ok then
	 return user_policy, nil
      end
   end
   
   return nil, "None of the user policies matched required policy for this action"
end

-- Check for Permit rule in policy
local function check_permit_policy(local_user_policy, notBefore, notAfter)

   -- Check for Permit rule
   local rules = local_user_policy.rules
   local found = false
   for index, value in ipairs(rules) do
      if value["effect"] and value["effect"] == "Permit" then
	 found = true
	 break
      end
   end
   if not found then
      return "No Permit rule found in policy"
   end

   -- Check expiration of policy
   local now = os.time()
   if now < notBefore or now >= notAfter then
      return "Policy has expired or is not yet valid"
   end
   
   return nil
end

-- Validate policies for incoming NGSI-LD compliant request
return function(settings, user)

   -- If this API does not require CB attribute based authorisation, continue on
   if (not settings or not settings["auth_mode"] or not string.find(settings["auth_mode"], "cb_attr")) then
      return nil
   end

   -- Check CB attribute based authorisation type
   -- Currently only supported: cb_attr_ishare_auto
   -- TODO: Change this part when further types will be implemented
   if settings["auth_mode"] ~= "cb_attr_ishare_auto" then
      ngx.log(ngx.ERR, "CB attribute based authorisation type not supported: ", settings["auth_mode"])
      return "policy_validation_failed", {
	 validation_error = "Internal error"
      }
   end

   -- Check for required config parameters
   if ( (not config["jws"]) or (not config["jws"]["private_key"]) or (not config["jws"]["x5c"]) ) then
      ngx.log(ngx.ERR, "Missing JWS information (PrivateKey+Certificates) in config")
      return "policy_validation_failed", {
	 validation_error = "Internal error"
      }
   end
   if (not config["jws"]) or (not config["jws"]["identifier"]) then
      ngx.log(ngx.ERR, "Missing local identifier information in jws config")
      return "policy_validation_failed", {
	 validation_error = "Internal error"
      }
   end
   if (not config["authorisation_registry"]) or (not config["authorisation_registry"]["identifier"]) then
      ngx.log(ngx.ERR, "Missing identifier information in AR config")
      return "policy_validation_failed", {
	 validation_error = "Internal error"
      }
   end
   local local_ar_eori = config["authorisation_registry"]["identifier"]
   if not config["authorisation_registry"]["host"] then
      ngx.log(ngx.ERR, "Missing local authorisation registry host information in config")
      return "policy_validation_failed", {
	 validation_error = "Internal error"
      }
   end
   local local_ar_host = config["authorisation_registry"]["host"]
   local local_token_url = config["authorisation_registry"]["token_endpoint"]
   local local_delegation_url = config["authorisation_registry"]["delegation_endpoint"]
   if not local_token_url then
      ngx.log(ngx.ERR, "Missing local authorisation registry /token endpoint information in config")
      return "policy_validation_failed", {
	 validation_error = "Internal error"
      }
   end
   if not local_delegation_url then
      ngx.log(ngx.ERR, "Missing local authorisation registry /delegation endpoint information in config")
      return "policy_validation_failed", {
	 validation_error = "Internal error"
      }
   end
      
   

   -- Validate incoming iSHARE JWT 
   local err = ishare.validate_ishare_jwt(user["api_key"])
   if err then
      return "policy_validation_failed", {
	 validation_error = "User JWT could not be validated: "..err
      }
   end
   
   -- Build required policy from incoming request
   local req_policy, err = build_policy()
   if err then
      return "policy_validation_failed", {
	 validation_error = err
      }
   end
   local req_policies = {}
   table.insert(req_policies, req_policy)
   
   -- Check for user policy
   local user_policy = {}
   local user_policies = nil
   local user_policy_issuer = nil
   local user_policy_targetsub = nil
   local del_notBefore = nil
   local del_notAfter = nil
   if user["delegation_evidence"] and user["delegation_evidence"]["policySets"] then
      -- Policy already provided in JWT
      if user["delegation_evidence"]["policySets"][1] and user["delegation_evidence"]["policySets"][1]["policies"] then
	 user_policies = user["delegation_evidence"]["policySets"][1]["policies"]
	 user_policy_issuer = user["delegation_evidence"]["policyIssuer"]
	 user_policy_targetsub = user["delegation_evidence"]["target"]["accessSubject"]
	 del_notBefore = user["delegation_evidence"]["notBefore"]
	 del_notAfter = user["delegation_evidence"]["notOnOrAfter"]
      else
	 return "policy_validation_failed", {
	    validation_error = "User policy could not be found in JWT"
         }
      end
   elseif user["authorisation_registry"] then
      -- AR info provided in JWT, get user policy from AR
      local token_url = user["authorisation_registry"]["token_endpoint"]
      local delegation_url = user["authorisation_registry"]["delegation_endpoint"]
      local ar_eori = user["authorisation_registry"]["identifier"]
      local issuer = user["iss"]
      local target = user["sub"]
      local api_key = user["api_key"]
      local user_del_evi = {}
      user_del_evi, err = get_delegation_evidence_ext(issuer, target, req_policy, token_url, ar_eori, delegation_url, api_key)
      if err then
	 return "policy_validation_failed", {
	    validation_error = "Error when retrieving delegation evidence from user AR: "..err
         }
      end
      if user_del_evi["policySets"] and user_del_evi["policySets"][1] and user_del_evi["policySets"][1]["policies"] then
	 user_policies = user_del_evi["policySets"][1]["policies"]
	 user_policy_issuer = user_del_evi["policyIssuer"]
	 user_policy_targetsub = user_del_evi["target"]["accessSubject"]
	 del_notBefore = user_del_evi["notBefore"]
	 del_notAfter = user_del_evi["notOnOrAfter"]
      else
	 return "policy_validation_failed", {
	    validation_error = "User policy could not be found in user AR response"
         }
      end
   else
      -- Info in JWT missing
      return "policy_validation_failed", {
	 validation_error = "No policies or authorisation registry info in JWT"
      }
   end

   -- Compare user policy with required policy
   user_policy, err = compare_policy(user_policies, req_policy, user_policy_targetsub, user["sub"])
   if err then
      return "policy_validation_failed", {
	 validation_error = "Unauthorized user policy: "..err
      }
   end

   -- Check if policy permits access (permit rule, expiration date)
   err = check_permit_policy(user_policy, del_notBefore, del_notAfter)
   if err then
      return "policy_validation_failed", {
	 validation_error = "Unauthorized user policy: "..err
      }
   end
   
   -- Check issuer of user policy:
   --   * If local EORI, the user is authorized
   --   * If different EORI, then ask local AR for policy issued by local EORI to user's EORI
   local local_eori = config["jws"]["identifier"]
   if local_eori ~= user_policy_issuer then
      -- Policy was not issued by local authority
      -- Check at local AR for policy delegation
      local local_user_del_evi, err = get_delegation_evidence_ext(local_eori, user_policy_issuer, req_policy, local_token_url, local_ar_eori, local_delegation_url, nil)
      if err then
	 return "policy_validation_failed", {
	    validation_error = "Error when retrieving policies from local AR: "..err
         }
      end
      if local_user_del_evi["policySets"] and local_user_del_evi["policySets"][1] and local_user_del_evi["policySets"][1]["policies"] and local_user_del_evi["policySets"][1]["policies"][1] then
	 local local_user_policy = local_user_del_evi["policySets"][1]["policies"][1]
	 err = check_permit_policy(local_user_policy, local_user_del_evi["notBefore"], local_user_del_evi["notOnOrAfter"])
	 if err then
	    return "policy_validation_failed", {
	       validation_error = "Local AR policy not authorized: "..err
            }
	 end
      else
	 return "policy_validation_failed", {
	    validation_error = "Policy could not be found in local AR response"
         }
      end
   else
      -- User policy claims to be issued by local authority
      -- No uirther steps required? Access granted!
   end

   -- Policy validated, access granted
end

