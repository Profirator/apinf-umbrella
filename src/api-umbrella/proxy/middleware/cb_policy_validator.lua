local config = require "api-umbrella.proxy.models.file_config"
local types = require "pl.types"
local stringx = require "pl.stringx"
local plutils = require "pl.utils"
local jwt = require "resty.jwt"
local http = require "resty.http"

local startswith = stringx.startswith
local split = plutils.split
local is_empty = types.is_empty
local cjson = require "cjson"

-- Get entity type from entity ID
-- Requires Entity ID in this format: urn:XXX:<TYPE>:XXX
local function get_type_from_entity_id(entity_id)
   entity_type = string.match(entity_id, "urn:.+:(.+):.+")
   return entity_type
end

-- Extract the policy parameters from the URI
local function get_policy_parameters(method)
   local entity_type = ""
   local entities = {}
   local attrs = {}
   
   -- Check method
   if not (method == "PATCH" or method == "GET") then
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
      local check = string.match(in_uri, ".*/entities/.+/attrs/*.*")
      if not check then
	 return nil, nil, nil, "No NGSI-LD compliant PATCH request"
      end
      -- TODO: Implement batch update via ngsi-ld/v1/entityOperations/upsert and ngsi-ld/v1/entityOperations/update

      -- Get entity ID
      local entity_id = string.match(in_uri, ".*/entities/(.+)/attrs.*")
      if not entity_id or not (string.len(entity_id) > 0) then
	 -- No entity specified, throw error
	 return nil, nil, nil, "No entity ID specified for PATCH request"
      end
      table.insert(entities, entity_id)

      -- Get entity type
      entity_type = get_type_from_entity_id(entity_id)
      if not entity_type or not (string.len(entity_type) > 0) then
	 return nil, nil, nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
      end
      
      -- Get attribute from URI
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	 table.insert(attrs, attr)
      elseif req_headers and req_headers["Content-Type"] and req_headers["Content-Type"] == "application/json" then
	 -- Get attributes from body, if specified and not in URI
	 local body_json = cjson.decode(body_data)
	 ngx.log(ngx.ERR, "[DEBUG] PATCH Request body data (decoded): ", cjson.encode(body_json))
	 for index, value in pairs(body_json) do
	    table.insert(attrs, index)
	 end
      end
      
      
      

      return entity_type, entities, attrs, nil
   elseif method == "GET" then
      -- GET request for reading entities attributes
      -- Check NGSI-LD compliance of URI
      local check = string.match(in_uri, ".*/entities/*.*")
      if not check then
	 return nil, nil, nil, "No NGSI-LD compliant GET request"
      end

      -- Get entity ID
      local entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      if not entity_id or not (string.len(entity_id) > 0) then
	 -- No entity specified, requesting all entities
	 entity_id = "*"
      end
      table.insert(entities, entity_id)

      -- Get entity type if specified
      -- Otherwise use wildcard 
      entity_type = "*"
      if uri_args and uri_args["type"] then
	 entity_type = uri_args["type"]
      elseif post_args and post_args["type"] then
	 entity_type = post_args["type"]
      elseif entity_id ~= "*" then
	 entity_type = get_type_from_entity_id(entity_id)
	 if not entity_type or not (string.len(entity_type) > 0) then
	    return nil, nil, nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
	 end
      else
	 -- TODO: Wildcard not supported for type? For the moment throw error if type not specified
	 return nil, nil, nil, "No type specified for GET request"
      end

      -- Set wildcard for attributes
      table.insert(attrs, "*")

      return entity_type, entities, attrs, nil
      
   end -- TODO: Implement POST and DELETE

end

-- Generate random string with characters and digits
local function random_string(l)
   local chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
   local length = l
   local randomString = ''
   
   math.randomseed(os.time())
   
   charTable = {}
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

-- Get token from AR TODO: implement
local function get_token(token_url, iss, sub, aud)
   -- Get certificates and key
   if (not config["gatekeeper"]["jws"]["private_key"]) or (not config["gatekeeper"]["jws"]["x5c"]) then
      return nil, "Missing JWS information in config"
   end
   local private_key = config["gatekeeper"]["jws"]["private_key"]
   local x5c_certs = config["gatekeeper"]["jws"]["x5c"]

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
   --local sz = math.ceil(signed_jwt:len() / 4)
   --ngx.log(ngx.ERR, "[DEBUG] Signed JWT (1): ", signed_jwt:sub(1,sz))
   --ngx.log(ngx.ERR, "[DEBUG] Signed JWT (2): ", signed_jwt:sub(sz+1,2*sz))
   --ngx.log(ngx.ERR, "[DEBUG] Signed JWT (3): ", signed_jwt:sub(2*sz+1,3*sz))
   --ngx.log(ngx.ERR, "[DEBUG] Signed JWT (4): ", signed_jwt:sub(3*sz+1,4*sz))

   -- Send request to token_url TODO restore code
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
   
   -- Send request to /delegation endpoint of AR at delegation_url TODO restore code
   ngx.log(ngx.ERR, "[DEBUG] /delegation request payload: ", cjson.encode(payload))
   -- ngx.log(ngx.ERR, "[DEBUG] /delegation req headers: ", cjson.encode(headers))
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
   -- ngx.log(ngx.ERR, "[DEBUG] /delegation res JWT: ", cjson.encode(decoded_token))

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
   if not config["gatekeeper"]["jws"]["identifier"] then
      return nil, "Missing identifier information in jws config"
   end
   local local_eori = config["gatekeeper"]["jws"]["identifier"]
   local token, err = get_token(token_url, local_eori, local_eori, ar_eori)
   if err then
      return nil, err
   end
   -- ngx.log(ngx.ERR, "[DEBUG] Received access_token: ", token)

   -- Get delegation evidence from external AR
   del_evi, err = get_delegation_evidence(issuer, target, policy, delegation_url, token, prev_steps)
   if err then
      return nil, err
   end

   return del_evi, nil
end

-- Compare user policy with required policy
local function compare_policy(user_policy, req_policy, user_policy_target, req_policy_target)

   -- Check if user IDs are equal
   if user_policy_target ~= req_policy_target then
      return "User IDs do not match: "..user_policy_target.." != "..req_policy_target
   end

   -- Compare policy parameter: action
   user_actions = user_policy.target.actions
   req_actions = req_policy.target.actions
   for index, value in ipairs(req_actions) do
      if not has_value(user_actions, value) then
	 return "User policy does not contain action "..value
      end
   end

   -- Compare policy parameter: attributes
   user_attrs = user_policy.target.resource.attributes
   req_attrs = req_policy.target.resource.attributes
   for index, value in ipairs(req_attrs) do
      if not has_value(user_attrs, value) then
	 return "User policy does not contain required attribute: "..value
      end
   end

   -- Compare policy parameter: type
   user_type = user_policy.target.resource.type
   req_type = req_policy.target.resource.type
   if user_type ~= req_type then
      return "User policy resource is not of required type: "..req_type.." != "..user_type
   end

   -- Compare policy parameter: identifier
   user_ids = user_policy.target.resource.identifiers
   req_ids = req_policy.target.resource.identifiers
   -- Check for exact entity IDs
   for index, value in ipairs(req_ids) do
      if not has_value(user_ids, value) then
	 return "User policy does not contain required identifier: "..value
      end
   end

   return nil
end

-- Check for Permit rule in policy
local function check_permit(local_user_policy)

   local rules = local_user_policy.rules
   local found = false
   for index, value in ipairs(rules) do
      if value["effect"] and value["effect"] == "Permit" then
	 found = true
	 break
      end
   end

   if not found then
      return "No Permit rule found"
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
   if settings["auth_mode"] ~= "cb_attr_ishare_auto" then
      ngx.log(ngx.ERR, "CB attribute based authorisation type not supported: ", settings["auth_mode"])
      return "api_key_unauthorized"
   end

   -- TODO: remove debugs in this file
   ngx.log(ngx.ERR, "[DEBUG] Starting cb-attr-based validation with user info: ", cjson.encode(user))
   
   -- Build required policy from incoming request
   local req_policy, err = build_policy()
   if err then
      ngx.log(ngx.ERR, "Failed CB attribute based authorization: ", err)
      return "api_key_unauthorized"
   end
   local req_policies = {}
   table.insert(req_policies, req_policy)
   ngx.log(ngx.ERR, "[DEBUG] Required policy for this request: ", cjson.encode(req_policy))

   -- Check for user policy
   local user_policy = {}
   local user_policy_issuer = nil
   local user_policy_targetsub = nil
   if user["delegation_evidence"] and user["delegation_evidence"]["policySets"] then
      -- Policy already provided in JWT
      if user["delegation_evidence"]["policySets"][1] and user["delegation_evidence"]["policySets"][1]["policies"] and user["delegation_evidence"]["policySets"][1]["policies"][1] then
	 user_policy = user["delegation_evidence"]["policySets"][1]["policies"][1]
	 user_policy_issuer = user["delegation_evidence"]["policyIssuer"]
	 user_policy_targetsub = user["delegation_evidence"]["target"]["accessSubject"]
      else
	 ngx.log(ngx.ERR, "Failed CB attribute based authorization: User policy could not be found in JWT")
	 return "api_key_unauthorized"
      end
   elseif user["authorisation_registry"] then
      -- AR info provided in JWT, get user policy from AR
      local token_url = user["authorisation_registry"]["token_endpoint"]
      local delegation_url = user["authorisation_registry"]["delegation_endpoint"]
      local ar_eori = user["authorisation_registry"]["identifier"]
      local issuer = user["iss"]  -- TODO: Check correct?
      local target = user["sub"]  -- TODO: Check correct? Or "id"?
      local api_key = user["api_key"]
      local user_del_evi = {}
      user_del_evi, err = get_delegation_evidence_ext(issuer, target, req_policy, token_url, ar_eori, delegation_url, api_key)
      if err then
	 ngx.log(ngx.ERR, "Failed CB attribute based authorization when retrieving delegation evidence from external AR: ", err)
	 return "api_key_unauthorized"
      end
      -- ngx.log(ngx.ERR, "[DEBUG] User delegation evidence: ", cjson.encode(user_del_evi))
      if user_del_evi["policySets"] and user_del_evi["policySets"][1] and user_del_evi["policySets"][1]["policies"] and user_del_evi["policySets"][1]["policies"][1] then
	 user_policy = user_del_evi["policySets"][1]["policies"][1]
	 user_policy_issuer = user_del_evi["policyIssuer"]
	 user_policy_targetsub = user_del_evi["target"]["accessSubject"]
      else
	 ngx.log(ngx.ERR, "Failed CB attribute based authorization: User policy could not be found in AR response")
	 return "api_key_unauthorized"
      end
   else
      -- Info in JWT missing
      ngx.log(ngx.ERR, "Failed CB attribute based authorization: No policies or authorisation registry info in JWT")
      return "api_key_unauthorized"
   end

   -- Compare user policy with required policy
   ngx.log(ngx.ERR, "[DEBUG] Received user policy: ", cjson.encode(user_policy))
   err = compare_policy(user_policy, req_policy, user_policy_targetsub, user["sub"])  -- TODO: Check user.id correct? Or "sub"?
   if err then
      ngx.log(ngx.ERR, "Failed CB attribute based authorization when comparing user policy with required policy: ", err)
      return "api_key_unauthorized"
   end

   -- Check for permit rule
   err = check_permit(user_policy)
   if err then
      ngx.log(ngx.ERR, "Failed CB attribute based authorization when checking user policy rules: ", err)
      return "api_key_unauthorized"
   end
   
   -- Check issuer of user policy:
   --   * If own EORI, then check against own AR. --> Get delEv from ownAR(iss=ownEORI,target=user) and check rule for Permit
   --   * If different EORI, then ask own AR for policy with own EORI --> Get delEv from ownAR(iss=ownEORI,target=extIss) and check rule for Permit
   -- If above ok ==> access granted!!!
   if not config["gatekeeper"]["jws"]["identifier"] then
      ngx.log(ngx.ERR, "Missing identifier information in jws config")
      return "api_key_unauthorized"
   end
   local local_eori = config["gatekeeper"]["jws"]["identifier"]
   if not config["gatekeeper"]["authorisation_registry"]["identifier"] then
      ngx.log(ngx.ERR, "Missing identifier information in AR config")
      return "api_key_unauthorized"
   end
   local local_ar_eori = config["gatekeeper"]["authorisation_registry"]["identifier"]
   if not config["gatekeeper"]["authorisation_registry"]["host"] then
      ngx.log(ngx.ERR, "Missing local authorisation registry host information in config")
      return "api_key_unauthorized"
   end
   local local_ar_host = config["gatekeeper"]["authorisation_registry"]["host"]
   local local_token_url = local_ar_host.."/connect/token"
   local local_delegation_url = local_ar_host.."/delegation"
   if local_eori ~= user_policy_issuer then
      -- Policy was not issued by local authority
      -- Check at local AR for policy delegation
      ngx.log(ngx.ERR, "[DEBUG] Policy not issued by local authority, check policy delegation")
      local local_user_del_evi, err = get_delegation_evidence_ext(local_eori, user_policy_issuer, req_policy, local_token_url, local_ar_eori, local_delegation_url, nil)
      if err then
	 ngx.log(ngx.ERR, "Failed CB attribute based authorization when retrieving delegation evidence from local AR: ", err)
	 return "api_key_unauthorized"
      end
      ngx.log(ngx.ERR, "[DEBUG] Received local AR delegation evidence: ", cjson.encode(local_user_del_evi))
      if local_user_del_evi["policySets"] and local_user_del_evi["policySets"][1] and local_user_del_evi["policySets"][1]["policies"] and local_user_del_evi["policySets"][1]["policies"][1] then
	 local_user_policy = local_user_del_evi["policySets"][1]["policies"][1]
	 err = check_permit(local_user_policy)
	 if err then
	    ngx.log(ngx.ERR, "Failed CB attribute based authorization when checking delegated policy at local AR: ", err)
	    return "api_key_unauthorized"
	 end
      else
	 ngx.log(ngx.ERR, "Failed CB attribute based authorization: User policy could not be found in AR response")
	 return "api_key_unauthorized"
      end
   else
      -- User policy claims to be issued by local authority
      -- Check at local AR for this policy
      ngx.log(ngx.ERR, "[DEBUG] Policy issued by local authority, confirm at local AR")
      -- TODO implement
   end

   -- Policy validated, access granted
   ngx.log(ngx.ERR, "[DEBUG] Policy validated, access granted")
end
