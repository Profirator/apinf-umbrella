local config = require "api-umbrella.proxy.models.file_config"
local types = require "pl.types"
local stringx = require "pl.stringx"
local plutils = require "pl.utils"
local jwt = require "resty.jwt"
local x509 = require("resty.openssl.x509")
local http = require "resty.http"

local startswith = stringx.startswith
local split = plutils.split
local is_empty = types.is_empty
local cjson = require "cjson"

-- Set rootCA if provided in config
local isTrustCASet = false
if config["jws"] and config["jws"]["root_ca_file"] then
   jwt:set_trusted_certs_file(config["jws"]["root_ca_file"])
   isTrustCASet = true
end

-- Get entity type from entity ID
-- Requires Entity ID in this format: urn:XXX:<TYPE>:XXX
local function get_type_from_entity_id(entity_id)
   local entity_type = string.match(entity_id, "urn:.+:(.+):.+")
   return entity_type
end

-- Extract the policy parameters from the URI
local function get_policy_parameters(method)
   local entity_type = ""
   local entities = {}
   local attrs = {}
   
   -- Check method
   if not (method == "PATCH" or method == "GET" or method == "DELETE" or method == "POST") then
      return nil, nil, nil, "HTTP method "..method.." not supported for CB attribute based authorisation"
   end

   -- Get request URI and strip query args
   --local in_uri = ngx.var.request_uri
   local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")
   
   -- Get request body, args and headers
   ngx.req.read_body()
   local body_data = ngx.req.get_body_data()
   local post_args = ngx.req.get_post_args()
   local uri_args = ngx.req.get_uri_args()
   local req_headers = ngx.req.get_headers()

   if method == "PATCH" then
      -- PATCH request for updating entity attributes
      -- Check NGSI-LD compliance of URI
      local check_ent = string.match(in_uri, ".*/entities/.+/attrs/*.*")
      local check_sub = string.match(in_uri, ".*/subscriptions/.+")
      if not check_ent and not check_sub then
	 return nil, nil, nil, "No NGSI-LD compliant PATCH request"
      end
      -- TODO: Implement batch update via ngsi-ld/v1/entityOperations/upsert and ngsi-ld/v1/entityOperations/update

      -- Get entity ID
      local entity_id = string.match(in_uri, ".*/entities/(.+)/attrs.*")
      local sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
      if check_sub and sub_id and (string.len(sub_id) > 0) then
	 -- PATCH subscription
	 entity_id = sub_id
      elseif not entity_id or not (string.len(entity_id) > 0) then
	 -- PATCH entity: No entity ID specified, throw error
	 return nil, nil, nil, "No entity ID specified for PATCH request"
      end
      table.insert(entities, entity_id)

      -- Get entity type
      entity_type = get_type_from_entity_id(entity_id)
      if check_sub then
	 -- PATCH subscription: fixed entity type
	 entity_type = "Subscription"
      elseif not entity_type or not (string.len(entity_type) > 0) then
	 -- PATCH entity: no type determined, throw error
	 return nil, nil, nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
      end
      
      -- Get attribute from URI
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	 -- PATCH entity: Get attribute from URL
	 table.insert(attrs, attr)
      elseif check_sub then
	 -- PATCH subscription: allow for all attributes
	 table.insert(attrs, "*")
      elseif req_headers and req_headers["Content-Type"] and req_headers["Content-Type"] == "application/json" then
	 -- PATCH entity: Get attributes from body, if specified and not in URI
	 local body_json = cjson.decode(body_data)
	 for index, value in pairs(body_json) do
	    table.insert(attrs, index)
	 end
      end
      
      return entity_type, entities, attrs, nil
   elseif method == "DELETE" then
      -- DELETE request for deleting entities (or attributes)
      -- Check NGSI-LD compliance of URI (lua does not support non-capturing groups)
      local check_ent = string.match(in_uri, ".*/entities/.+/?a?t?t?r?s?/?.*")
      local check_sub = string.match(in_uri, ".*/subscriptions/.+")
      if not check_ent and not check_sub then
	 return nil, nil, nil, "No NGSI-LD compliant DELETE request"
      end
      -- TODO: Implement batch update via ngsi-ld/v1/entityOperations/delete

      -- Get entity ID
      local entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      local sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
      if check_sub and sub_id and (string.len(sub_id) > 0) then
	 -- DELETE subscription
	 entity_id = sub_id
      elseif not entity_id or not (string.len(entity_id) > 0) then
	 -- DELETE entity: No entity ID specified, throw error
	 return nil, nil, nil, "No entity ID specified for DELETE request"
      end
      table.insert(entities, entity_id)

      -- Get entity type
      entity_type = get_type_from_entity_id(entity_id)
      if check_sub then
	 -- DELETE subscription: fixed entity type
	 entity_type = "Subscription"
      elseif not entity_type or not (string.len(entity_type) > 0) then
	 -- DELETE entity: no type determined, throw error
	 return nil, nil, nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
      end

      -- Get attribute from URI
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	 table.insert(attrs, attr)
      else
	 -- Deleting whole entity, set wildcard for attributes
	 -- Also for delete subscription
	 table.insert(attrs, "*")
      end

      return entity_type, entities, attrs, nil
   elseif method == "GET" then
      -- GET request for reading entities attributes
      -- Check NGSI-LD compliance of URI
      local check_ent = string.match(in_uri, ".*/entities/*.*")
      local check_sub = string.match(in_uri, ".*/subscriptions/*.*")
      if not check_ent and not check_sub then
	 return nil, nil, nil, "No NGSI-LD compliant GET request"
      end

      -- Get entity ID
      local entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      local sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
      if check_sub and sub_id and (string.len(sub_id) > 0) then
	 -- GET subscriptions: retrieve specific subscription
	 entity_id = sub_id
      elseif check_sub or not entity_id or not (string.len(entity_id) > 0) then
	 -- No entity/subscription ID specified, requesting all entities/subscriptions
	 entity_id = "*"
      end
      table.insert(entities, entity_id)

      -- Get entity type if specified
      -- Otherwise use wildcard 
      entity_type = "*"
      if check_sub then
	 -- GET subscription: fixed type
	 entity_type = "Subscription"
      elseif uri_args and uri_args["type"] then
	 entity_type = uri_args["type"]
      elseif post_args and post_args["type"] then
	 entity_type = post_args["type"]
      elseif not check_sub and entity_id ~= "*" then
	 entity_type = get_type_from_entity_id(entity_id)
	 if not entity_type or not (string.len(entity_type) > 0) then
	    return nil, nil, nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
	 end
      else
	 -- TODO: Wildcard not supported at AR for type? For the moment throw error if type not specified
	 return nil, nil, nil, "No type specified for GET request"
      end

      -- Set wildcard for attributes
      table.insert(attrs, "*")

      return entity_type, entities, attrs, nil
   elseif method == "POST" then
      -- POST request for creating entities or subscriptions
      -- Check NGSI-LD compliance of URI
      local check_ent = string.match(in_uri, ".*/entities/*.*")
      local check_sub = string.match(in_uri, ".*/subscriptions/*")
      if not check_ent and not check_sub then
	 return nil, nil, nil, "No NGSI-LD compliant POST request"
      end
      -- TODO: Implement batch create via ngsi-ld/v1/entityOperations/upsert and ngsi-ld/v1/entityOperations/create

      -- Get entity ID
      local body_json = cjson.decode(body_data)
      local entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      if check_sub then
	 -- POST subscription has no ID
	 entity_id = "*"
      elseif not entity_id or not (string.len(entity_id) > 0) then
	 -- POST entity: No entity ID specified in URI, obtaining from payload
	 if not body_json["id"] then
	    return nil, nil, nil, "Missing entity ID in payload of POST request"
	 end
	 entity_id = body_json["id"]
      end
      table.insert(entities, entity_id)

      -- Get entity type from payload or entity ID
      if body_json and body_json["type"] then
	 entity_type = body_json["type"]
      elseif check_sub then
	 -- POST subscription has fixed type
	 entity_type = "Subscription"
      else
	 entity_type = get_type_from_entity_id(entity_id)
	 if not entity_type or not (string.len(entity_type) > 0) then
	    return nil, nil, nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
	 end
      end

      -- Get attribute
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	 -- Attribute part of URI, creating single attribute for entity
	 table.insert(attrs, attr)
      else
	 -- Whole entity to be created, wildcard for attributes
	 -- Also for POST subscription
	 table.insert(attrs, "*")
      end

      return entity_type, entities, attrs, nil
   end 

end

-- Generate random string with characters and digits
local function random_string(l)
   local chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
   local length = l
   local randomString = ''
   
   math.randomseed(os.time())
   
   local charTable = {}
   for c in chars:gmatch"." do
      table.insert(charTable, c)
   end
   
   for i = 1, length do
      randomString = randomString .. charTable[math.random(1, #charTable)]
   end
   
   return randomString
   
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

-- Send request
local function request(url, options)

   local httpc = http.new()
   -- httpc:set_timeout(45000)
   local res, err =  httpc:request_uri(url, options)

   local msg = ""
   if not res then
      msg = "Empty response on request to "..url
      return nil, msg 
   elseif (res.status ~= 200 and res.status ~= 201) then
      msg = "Request to "..url.." not ok, received status code "..res.status
      if res.reason then
	 msg = msg..", Reason: "..res.reason
      end
      if res.body then
	 msg = msg..", Body: "..res.body
      end 
      return nil, msg
   elseif err then
      return nil, err
   end

   return res, nil
end

-- Builds the required policy based on the incoming request
local function build_policy()
   local policy = {}

   -- Get HTTP method
   local in_method = string.upper(ngx.req.get_method())
   
   -- Get policy parameters
   local ent_type, entities, attrs, err = get_policy_parameters(in_method)
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
   table.insert(policy.target.actions, in_method )
   policy.rules = {}
   local rule = {}
   rule.effect = "Permit"
   table.insert(policy.rules, rule)
   
   return policy, nil
end

-- Get token from AR
local function get_token(token_url, iss, sub, aud)
   -- Get certificates and key
   local private_key = config["jws"]["private_key"]
   local x5c_certs = config["jws"]["x5c"]

   -- Build JWT Header
   local header = {
      typ = "JWT",
      alg = "RS256",
      x5c = x5c_certs
   }
   
   -- Build JWT Payload
   local now = os.time()
   local full_aud = {}
   table.insert(full_aud, aud)
   table.insert(full_aud, token_url)
   local payload = {
      iss = iss,
      sub = sub,
      aud = full_aud,
      jti = random_string(32), 
      exp = now+30, 
      iat = now
   }
   
   -- Sign JWS
   local unsigned_jwt = {
      header = header,
      payload = payload
   }
   local signed_jwt = jwt:sign(private_key, unsigned_jwt)

   -- Send request to token_url
   local ssl = false
   local tquery = "grant_type=client_credentials&scope=iSHARE&client_id="..iss.."&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion="..signed_jwt
   local headers = {}
   headers["Content-Type"] = "application/x-www-form-urlencoded"
   headers["Content-Length"] = string.len(tquery)
   local options = {
      method = "POST",
      body = tquery,
      headers = headers,
      ssl_verify = ssl,
   } -- query = tquery
   local res, err = request(token_url, options)
   if err then
      return nil, "Error when retrieving token: "..err
   end
   
   -- Get token from response
   local res_body = cjson.decode(res.body)
   local access_token = res_body["access_token"]
   if not access_token then
      return nil, "access_token not found in response: "..res_body
   end
   return access_token, nil
   
end

-- Get delegation evidence
local function get_delegation_evidence(issuer, target, policy, delegation_url, access_token, prev_steps)

   -- Build payload body of request
   local payload = {
      delegationRequest = {
	 policyIssuer = issuer,
	 target = {
	    accessSubject = target
	 },
	 policySets = {}
      }
   }
   if prev_steps then
      payload["prev_steps"] = {}
      table.insert(payload["prev_steps"], prev_steps)
   end
   local policies = {}
   table.insert(policies, policy)
   table.insert(payload.delegationRequest.policySets, {})
   payload.delegationRequest.policySets[1] = {
      policies = policies
   }

   -- Build header of request
   local headers = {}
   headers["Content-Type"] = "application/json"
   headers["Authorization"] = "Bearer "..access_token
   
   -- Send request to /delegation endpoint of AR at delegation_url
   local ssl = false
   local options = {
      method = "POST",
      body = cjson.encode(payload),
      headers = headers,
      ssl_verify = ssl,
   }
   local res, err = request(delegation_url, options)
   if err then
      return nil, "Error when retrieving delegation evidence: "..err
   end

   -- Get delegation_token from response
   local res_body = cjson.decode(res.body)
   local delegation_token = res_body["delegation_token"]
   
   if not delegation_token then
      return nil, "delegation_token not found in response: "..res_body
   end

   -- Decode delegation_token
   local decoded_token = jwt:load_jwt(delegation_token)
   if not decoded_token["valid"] then
      return nil, "The received delegation JWT is not valid"
   end
   
   -- Get delegation evidence
   if not decoded_token["payload"] and not decoded_token["payload"]["delegationEvidence"] then
      return nil, "The received delegation JWT contains no delegationEvidence"
   end
   
   return decoded_token["payload"]["delegationEvidence"], nil
end

-- Get delegation evidence from external authorisation registry
local function get_delegation_evidence_ext(issuer, target, policy, token_url, ar_eori, delegation_url, prev_steps)
   local del_evi = {}

   -- Get token at external AR
   local local_eori = config["jws"]["identifier"]
   local token, err = get_token(token_url, local_eori, local_eori, ar_eori)
   if err then
      return nil, err
   end
   
   -- Get delegation evidence from external AR
   del_evi, err = get_delegation_evidence(issuer, target, policy, delegation_url, token, prev_steps)
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

-- Validate the incoming JWT
local function validate_token(token)

   -- Decode JWT without validation to extract header params first
   local decoded_token = jwt:load_jwt(token)
   local header = decoded_token["header"]

   -- Check for RS256 header to be iSHARE compliant
   if header["alg"] ~= "RS256" then
      return "RS256 algorithm must be used and specified in JWT header"
   end

   -- Check for x5c header
   if not header["x5c"] then
      return "JWT must contain x5c header parameter"
   end
   
   -- Get first certificate
   local cert = header["x5c"][1]
   local pub_key = "-----BEGIN CERTIFICATE-----\n"..cert.."\n-----END CERTIFICATE-----\n"
   
   -- Compare policy issuer with certificate subject
   local cr, err = x509.new(pub_key)
   if not err then
      local subname, err = cr:get_subject_name()
      if err then
	 return "Error when retrieving subject name from certificate: "..err
      end
      local serialnumber, pos, err = subname:find("serialNumber")
      if err then
	 return "Error when retrieving serial number from certificate: "..err
      end
      if not serialnumber then
	 return "Empty serial number in certificate"
      end
      local certsub = serialnumber.blob
      local payload = decoded_token["payload"]
      local issuer = payload['iss']
      if certsub ~= issuer then
	 return "Certificate serial number "..certsub.." does not equal policy issuer "..issuer
      end
   else
      return "Error when loading certificate: "..err
   end
   
   -- Verify signature
   -- If Root CA file is set, the verification will include validation of the cert chain
   local jwt_obj = nil
   if not isTrustCASet then
      jwt_obj = jwt:verify(pub_key, token)
   else
      jwt_obj = jwt:verify(nil, token)
   end
   if not jwt_obj["valid"] then
      return "User policy JWT is not valid"
   end
   if not jwt_obj["verified"] then
      return "Verification failed: "..jwt_obj["reason"]
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
      
   

   -- Validate incoming JWT
   local err = validate_token(user["api_key"])
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

