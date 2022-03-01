local config = require "api-umbrella.proxy.models.file_config"
local ngsi = require "api-umbrella.utils.ngsi"
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

   -- Get policy parameters from NGSI request
   local parameters, err = ngsi.get_ngsi_parameters()
   if err then
      return nil, err
   end

   -- Build array of required policies based on iSHARE format
   for ngsi_params_index, ngsi_params in ipairs(parameters) do
      -- Policy
      local policy = {}

      -- Resource object
      policy.target = {}
      policy.target.resource = {}
      policy.target.resource.type = ngsi_params.entity_type
      policy.target.resource.identifiers = ngsi_params.identifier
      policy.target.resource.attributes = ngsi_params.attributes

      -- Set action depending on operation type
      -- For single entity operations it is the HTTP method
      -- Otherwise extend by operation type
      policy.target.actions = {}
      local method = ngsi_params.method
      if ngsi_params.operation_type == ngsi.OP_TYPE_SUBSCRIPTION then
	       method = method..":Subscription"
      elseif ngsi_params.operation_type == ngsi.OP_TYPE_NOTIFICATION then
	       method = method..":Notification"
      elseif ngsi_params.operation_type == ngsi.OP_TYPE_BATCH then
	       method = method..":Batch"
      end
      table.insert(policy.target.actions, method )

      -- Set permit rule
      policy.rules = {}
      local rule = {}
      rule.effect = "Permit"
      table.insert(policy.rules, rule)

      -- Add policy to array
      table.insert(policies, policy)
   end

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

-- Compare user policies with required policies
-- Returns all matching user policies
-- Returns error, if there is no user policy for any of the required policies
local function compare_policies(user_policies, req_policies, user_policy_target, req_policy_target)

   -- Check if user IDs are equal
   if user_policy_target ~= req_policy_target then
      return nil, "User IDs do not match: "..user_policy_target.." != "..req_policy_target
   end

   -- Iterate over required policies
   -- Add matching user policy to array
   local matching_policies = {}
   for req_policy_index, req_policy in ipairs(req_policies) do
      local matching_policy_found = false
      
      -- Iterate over user policies, find policy matching this required policy
      -- If none is found, throw error
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
	          if (not has_value(user_attrs, "*")) and (not has_value(user_attrs, value)) then
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
	          if (not has_value(user_attrs, "*")) and (not has_value(user_ids, value)) then
	             -- Missing required identifier
	             --return "User policy does not contain required identifier: "..value
	             ids_ok = false
	          end
	       end
	 
	       -- Policy ok?
	       if actions_ok and attrs_ok and type_ok and ids_ok then
	          --return user_policy, nil
	          table.insert(matching_policies, user_policy)
	          matching_policy_found = true
	       end
      end -- End user policy iteration

      if not matching_policy_found then
	       return nil, "None of the user policies matched a required policy for this action"
      end
      
   end -- End required policy iteration
   
   --return nil, "None of the user policies matched required policy for this action"
   return matching_policies, nil
end

-- Check for Permit rule in required user/org policies
local function check_permit_policies(policies, notBefore, notAfter)

   -- Check expiration of policies
   local now = os.time()
   if now < notBefore or now >= notAfter then
      return "Policy has expired or is not yet valid"
   end
   
   -- Iterate over user policies, find policy matching this required policy
   -- If none is found, throw error
   for policy_index, policy in ipairs(policies) do
      -- Check for Permit rule
      local rules = policy.rules
      local found = false
      for index, value in ipairs(rules) do
	       if value["effect"] and value["effect"] == "Permit" then
	          found = true
	          break
	       end
      end
      if not found then
	       return "No Permit rule found in one of the user/organisation policies required for this request"
      end
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
   local local_eori = config["jws"]["identifier"]
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
   local req_policies, err = build_required_policies()
   if err then
      return "policy_validation_failed", {
	       validation_error = err
      }
   end
   
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
      user_del_evi, err = get_delegation_evidence_ext(issuer, target, req_policies, token_url, ar_eori, delegation_url, api_key)
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
      -- Info in JWT missing, assuming M2M
      -- Therefore no user policy and skip to next step for organisational policy
      -- Set issuer to JWT target subject, so that in next step we check the AR
      -- whether there is a policy issued by local EORI to the JWT subject
      user_policy_issuer = user["sub"]

      -- Check that JWT was issued by local EORI, otherwise throw error
      if local_eori ~= user["iss"] then
	       return "policy_validation_failed", {
	          validation_error = "No policies or authorisation registry info in JWT, or JWT was not issued by local authority"
	       }
      end
   end

   -- Validate user policy if available
   if user_policies then
      -- Compare user policy with required policy
      matching_policies, err = compare_policies(user_policies, req_policies, user_policy_targetsub, user["sub"])
      if err then
	       return "policy_validation_failed", {
	          validation_error = "Unauthorized user policy: "..err
				 }
      end

      -- Check if policies permit access (permit rule, expiration date)
      err = check_permit_policies(matching_policies, del_notBefore, del_notAfter)
      if err then
	       return "policy_validation_failed", {
	          validation_error = "Unauthorized user policy: "..err
				 }
      end
   end
   
   -- Check issuer of user policy or JWT:
   --   * If local EORI, the user/requester is authorized
   --   * If different EORI, then ask local AR for policy issued by local EORI to user's EORI
   if local_eori ~= user_policy_issuer then
      -- User policy was not issued by local authority or there was no user policy
      -- Check at local AR for policy issued by local EORI
      local local_user_del_evi, err = get_delegation_evidence_ext(local_eori, user_policy_issuer, req_policies, local_token_url, local_ar_eori, local_delegation_url, nil)
      if err then
	       return "policy_validation_failed", {
	          validation_error = "Error when retrieving policies from local AR: "..err
         }
      end
      if local_user_del_evi["policySets"] and local_user_del_evi["policySets"][1] and local_user_del_evi["policySets"][1]["policies"] then
	       local local_user_policies = local_user_del_evi["policySets"][1]["policies"]
	       err = check_permit_policies(local_user_policies, local_user_del_evi["notBefore"], local_user_del_evi["notOnOrAfter"])
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

