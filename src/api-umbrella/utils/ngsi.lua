-- Imports
local cjson = require "cjson"

-- Returned object
local _M = {}

-- Exported constants
_M.OP_TARGET_ENTITY = "ENTITY"
_M.OP_TARGET_SUBSCRIPTION = "SUBSCRIPTION"
_M.OP_TARGET_NOTIFICATION = "NOTIFICATION"



-- Get entity type from entity ID
-- Requires Entity ID in this format: urn:XXX:<TYPE>:XXX
local function get_type_from_entity_id(entity_id)
   if not entity_id then
      return nil
   end

   -- Obtain type from URN
   local entity_type = string.match(entity_id, "urn:.+:(.+):.+")
   return entity_type
end


-- **************************************************
--  Functions for evaluating NGSI request API 
-- **************************************************

-- Checks for NGSI-v2 request
-- Request URI must contain "/v2/"
function _M.is_ngsi_v2()
   -- Get request URI and strip query args
   local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")

   -- Check for NGSI-v2 compliant URI
   local check_v2 = string.match(in_uri, ".*v2.*")
   if not check_v2 then
      return false
   else
      return true
   end
end

-- Checks for NGSI-LD request
-- Request URI must contain "/ngsi-ld/v1/"
function _M.is_ngsi_ld()
   -- Get request URI and strip query args
   local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")

   -- Check for NGSI-LD compliant URI
   local check_ld = string.match(in_uri, ".*ngsi%-ld/v1.*")
   if not check_ld then
      return false
   else
      return true
   end
end


-- **************************************************
--  Function for evaluating NGSI request action type
-- **************************************************

-- Validates and returns requests action type from HTTP method
function _M.get_request_action()
   -- Get action from HTTP method
   local method = string.upper(ngx.req.get_method())

   -- Get NGSI API
   local is_v2 = _M.is_ngsi_v2()
   local is_ld = _M.is_ngsi_ld()
   
   -- Check method
   if is_v2 and not (method == "PATCH" or method == "GET" or method == "DELETE" or method == "POST" or method == "PUT") then
      -- For NGSI-v2 only PATCH, GET, DELETE, POST, PUT allowed
      return nil, "HTTP method "..method.." not supported for NGSI-v2 attribute based authorisation"
   elseif is_ld and not (method == "PATCH" or method == "GET" or method == "DELETE" or method == "POST") then
      -- For NGSI-LD only PATCH, GET, DELETE, POST allowed
      return nil, "HTTP method "..method.." not supported for NGSI-LD attribute based authorisation"
   elseif (not is_v2) and (not is_ld) then
      -- Neither NGSI-v2 nor NGSI-LD request
      return nil, "No NGSI-v2 or NGSI-LD request could be evaluated from URI"
   else
      -- Return request action type
      return method, nil
   end
end


-- **************************************************
--  Function for evaluating NGSI request operation
--  target (e.g., entity or subscription)
-- **************************************************

-- Retrieves the type of the NGSI operation target
-- Entity, subscription, notification
function _M.check_operation_target(method, in_uri_var)
   local in_uri = nil
   if in_uri_var then
      in_uri = in_uri_var
   else 
      in_uri = string.gsub(ngx.var.request_uri, "?.*", "")
   end
   
   if _M.is_ngsi_v2() then
      return nil, "NGSI-v2 is not supported yet"
   elseif _M.is_ngsi_ld() then
      if method == "PATCH" then
	 -- PATCH request allows for updating entity attributes and subscriptions
	 -- Batch update via ngsi-ld/v1/entityOperations/upsert and ngsi-ld/v1/entityOperations/update not supported yet
	 local check_ent = string.match(in_uri, ".*/entities/.+/attrs/*.*")
	 if check_ent then
	    return _M.OP_TARGET_ENTITY, nil
	 end
	 local check_sub = string.match(in_uri, ".*/subscriptions/.+")
	 if check_sub then
	    return _M.OP_TARGET_SUBSCRIPTION, nil
	 end
	 return nil, "No NGSI-LD compliant PATCH request"

      elseif method == "DELETE" then
	 -- DELETE request allows for deleting entities (or attributes) and subscriptions
	 -- (lua does not support non-capturing groups)
	 -- Batch delete via ngsi-ld/v1/entityOperations/delete not supported yet
	 local check_ent = string.match(in_uri, ".*/entities/.+/?a?t?t?r?s?/?.*")
	 if check_ent then
	    return _M.OP_TARGET_ENTITY, nil
	 end
	 local check_sub = string.match(in_uri, ".*/subscriptions/.+")
	 if check_sub then
	    return _M.OP_TARGET_SUBSCRIPTION, nil
	 end
	 return nil, "No NGSI-LD compliant DELETE request"

      elseif method == "GET" then
	 -- GET request for allows reading entities attributes and subscriptions
	 local check_ent = string.match(in_uri, ".*/entities/*.*")
	 if check_ent then
	    return _M.OP_TARGET_ENTITY, nil
	 end
	 local check_sub = string.match(in_uri, ".*/subscriptions/*.*")
	 if check_sub then
	    return _M.OP_TARGET_SUBSCRIPTION, nil
	 end
	 return nil, "No NGSI-LD compliant GET request"

      elseif method == "POST" then
	 -- POST request allows for creating entities or subscriptions, or sending notifications
	 -- Batch create via ngsi-ld/v1/entityOperations/upsert and ngsi-ld/v1/entityOperations/create not supported yet
	 local check_ent = string.match(in_uri, ".*/entities/*.*")
	 if check_ent then
	    return _M.OP_TARGET_ENTITY, nil
	 end
	 local check_sub = string.match(in_uri, ".*/subscriptions/*")
	 if check_sub then
	    return _M.OP_TARGET_SUBSCRIPTION, nil
	 end

	 -- Notifications cannot be identified by URI, checking type of payload
	 ngx.req.read_body()
	 local body_data = ngx.req.get_body_data()
	 local body_json = cjson.decode(body_data)
	 if body_json and body_json["type"] and body_json["type"] == "Notification" then
	    return _M.OP_TARGET_NOTIFICATION, nil
	 end
	 
	 return nil, "No NGSI-LD compliant POST request"

      else
	 return false, "HTTP method "..method.." not supported for NGSI-LD attribute based authorisation"
      end
   else
      return false, "No NGSI-v2 or NGSI-LD request could be evaluated from URI"
   end
end


-- **************************************************
--  Functions for checking NGSI request compliance
-- **************************************************

-- Check NGSI-v2 compliance of request
local function check_ngsi_v2_compliance()
   -- NGSI-v2 not implemented yet
   return false, "NGSI-v2 is not supported yet"
end

-- Check NGSI-LD compliance of request
local function check_ngsi_ld_compliance()
   -- Get HTTP method and validate for NGSI-LD
   local method, method_err = _M.get_request_action()
   if method_err then
      return false, method_err
   end

   -- Get request URI and strip query args
   local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")

   -- Get NGSI operation target (e.g., entity or subscription), will also validate request
   local op_target, op_target_err = _M.check_operation_target(method, in_uri)
   if op_target_err then
      return false, op_target_err
   end

   return true, nil
end

-- Check NGSI compliance of request
function _M.check_ngsi_compliance()
   if _M.is_ngsi_v2() then
      return check_ngsi_v2_compliance()
   elseif _M.is_ngsi_ld() then
      return check_ngsi_ld_compliance()
   else
      return false, "No NGSI-v2 or NGSI-LD request could be evaluated from URI"
   end
end


-- **************************************************
--  Functions for evaluating NGSI request ID
-- **************************************************

-- Get entity IDs of NGSI-v2 request
local function get_ngsi_v2_entity_id(method_var, op_target_var)
   -- NGSI-v2 not implemented yet
   return false, "NGSI-v2 is not supported yet"
end

-- Get entity IDs of NGSI-LD request
local function get_ngsi_ld_entity_id(method_var, op_target_var)
   -- Get HTTP method and validate for NGSI-LD (if not supplied)
   local method, method_err = nil, nil
   if method_var then
      method = method_var
   else 
      method, method_err = _M.get_request_action()
      if method_err then
	 return nil, method_err
      end
   end

   -- Get request URI and strip query args
   local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")

   -- Get operation target (e.g., entity or subscription) if not supplied in this method
   local op_target, op_target_err = nil, nil
   if op_target_var then
      op_target = op_target_var
   else
      op_target, op_target_err = _M.check_operation_target(method, in_uri)
      if op_target_err then
	 return nil, op_target_err
      end
   end
   
   -- Retrieve entity ID for different action types
   local entity_id = nil
   if method == "PATCH" then
      -- Get single ID from URI
      entity_id = string.match(in_uri, ".*/entities/(.+)/attrs.*")
      if op_target == _M.OP_TARGET_SUBSCRIPTION then -- PATCH subscription
	 local sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
	 if sub_id and (string.len(sub_id) > 0) then
	    entity_id = sub_id
	 else
	    return nil, "No subscription ID specified for PATCH request"
	 end
      elseif op_target == _M.OP_TARGET_ENTITY then -- PATCH entity
	 if (not entity_id) or (not (string.len(entity_id) > 0)) then
	    return nil, "No entity ID specified for PATCH request"
	 end
      end
      
   elseif method == "DELETE" then
      -- Get single ID from URI
      entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      if op_target == _M.OP_TARGET_SUBSCRIPTION then -- DELETE subscription
	 local sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
	 if sub_id and (string.len(sub_id) > 0) then
	    entity_id = sub_id
	 else
	    return nil, "No subscription ID specified for DELETE request"
	 end
      elseif op_target == _M.OP_TARGET_ENTITY then -- DELETE entity
	 if (not entity_id) or (not (string.len(entity_id) > 0)) then
	    return nil, "No entity ID specified for DELETE request"
	 end
      end

   elseif method == "GET" then
      -- Get single ID from URI
      entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      if op_target == _M.OP_TARGET_SUBSCRIPTION then -- GET subscription
	 local sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
	 if sub_id and (string.len(sub_id) > 0) then
	    -- GET subscriptions: retrieve specific subscription
	    entity_id = sub_id
	 else
	    -- No subscription ID specified, requesting all subscriptions
	    entity_id = "*"
	 end 
      elseif op_target == _M.OP_TARGET_ENTITY then -- GET entity
	 if (not entity_id) or (not (string.len(entity_id) > 0)) then
	    -- No entity ID specified, requesting all entities
	    entity_id = "*"
	 end
      end

   elseif method == "POST" then
      -- Get single ID from URI or payload
      ngx.req.read_body()
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      if op_target == _M.OP_TARGET_SUBSCRIPTION then -- POST subscription
	 if body_json["id"] then
	    -- ID specified for subscription
	    entity_id = body_json["id"]
	 else 
	    -- POST subscription has no ID, applying wildcard
	    entity_id = "*"
	 end
      elseif op_target == _M.OP_TARGET_NOTIFICATION then -- POST notification
	 if body_json["subscriptionId"] then
	    -- POST subscription: policy identifier should restrict by subscription ID
	    entity_id = body_json["subscriptionId"]
	 else
	    return nil, "No subscription ID specified for notification in POST operation"
	 end
      elseif op_target == _M.OP_TARGET_ENTITY then -- POST entity
	 if (not entity_id) or (not (string.len(entity_id) > 0)) then
	    -- POST entity: No entity ID specified in URI, obtaining from payload
	    if not body_json["id"] then
	       return nil, "Missing entity ID in payload of POST request"
	    end
	    entity_id = body_json["id"]
	 end
      end
      
   end

   -- Return table with entity ID(s)
   return entity_id, nil
end

-- Get entity ID of NGSI request
--   When HTTP method (method) and/or operation target (op_target) are set to nil these
--   parameters are evaluated from the request
function _M.get_ngsi_entity_id(method, op_target)
   if _M.is_ngsi_v2() then
      return get_ngsi_v2_entity_id(method, op_target)
   elseif _M.is_ngsi_ld() then
      return get_ngsi_ld_entity_id(method, op_target)
   else
      return false, "No NGSI-v2 or NGSI-LD request could be evaluated from URI"
   end
end


-- **************************************************
--  Functions for evaluating NGSI request type
-- **************************************************

-- Get entity type of NGSI-v2 request
local function get_ngsi_v2_entity_type(method_var, entity_id, op_target_var)
   -- NGSI-v2 not implemented yet
   return false, "NGSI-v2 is not supported yet"
end

-- Get entity type of NGSI-LD request
local function get_ngsi_ld_entity_type(method_var, entity_id, op_target_var)
   -- Get HTTP method and validate for NGSI-LD (if not supplied)
   local method, method_err = nil, nil
   if method_var then
      method = method_var
   else 
      method, method_err = _M.get_request_action()
      if method_err then
	 return nil, method_err
      end
   end

   -- Get args
   ngx.req.read_body()
   local post_args = ngx.req.get_post_args()
   local uri_args = ngx.req.get_uri_args()

   -- Get operation target (e.g., entity or subscription) if not supplied in this method
   local op_target, op_target_err = nil, nil
   if op_target_var then
      op_target = op_target_var
   else
      local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")
      op_target, op_target_err = _M.check_operation_target(method, in_uri)
      if op_target_err then
	 return nil, op_target_err
      end
   end
   
   -- Get entity type
   local entity_type = ""
   if method == "PATCH" then
      entity_type = get_type_from_entity_id(entity_id)
      if op_target == _M.OP_TARGET_SUBSCRIPTION then -- PATCH subscription
	 entity_type = "Subscription"
      elseif (not entity_type) or (not (string.len(entity_type) > 0)) then
	 -- PATCH entity: no type determined from ID, throw error
	 return nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
      end

   elseif method == "DELETE" then
      entity_type = get_type_from_entity_id(entity_id)
      if op_target == _M.OP_TARGET_SUBSCRIPTION then -- DELETE subscription
	 entity_type = "Subscription"
      elseif (not entity_type) or (not (string.len(entity_type) > 0)) then
	 -- DELETE entity: no type determined from ID, throw error
	 return nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
      end

   elseif method == "GET" then
      -- Get entity type if specified
      -- Otherwise use wildcard 
      entity_type = "*"
      if op_target == _M.OP_TARGET_SUBSCRIPTION then -- GET subscription
	 -- GET subscription: fixed type
	 entity_type = "Subscription"
      elseif uri_args and uri_args["type"] then
	 entity_type = uri_args["type"]
      elseif post_args and post_args["type"] then
	 entity_type = post_args["type"]
      elseif (not (op_target == _M.OP_TARGET_SUBSCRIPTION)) and entity_id ~= "*" then
	 entity_type = get_type_from_entity_id(entity_id)
	 if (not entity_type) or (not (string.len(entity_type) > 0)) then
	    return nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
	 end
      else
	 -- TODO: Wildcard not supported at AR for type? For the moment throw error if type not specified
	 return nil, "No type specified for GET request"
      end
      
   elseif method == "POST" then
      -- Get entity type from payload or entity ID
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      if body_json and body_json["type"] then
	 -- Will also apply for Notification
	 entity_type = body_json["type"]
      elseif op_target == _M.OP_TARGET_SUBSCRIPTION then
	 -- POST subscription has fixed type
	 entity_type = "Subscription"
      else
	 entity_type = get_type_from_entity_id(entity_id)
	 if (not entity_type) or (not (string.len(entity_type) > 0)) then
	    return nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
	 end
      end
      
   end

   return entity_type, nil
end
   
-- Get entity type of NGSI request
--   When HTTP method (method) and/or operation target (op_target) are set to nil these
--   parameters are evaluated from the request.
--   Entity ID (entity_id) can be set to nil if not applicable
function _M.get_ngsi_entity_type(method, entity_id, op_target)
   if _M.is_ngsi_v2() then
      return get_ngsi_v2_entity_type(method, entity_id, op_target)
   elseif _M.is_ngsi_ld() then
      return get_ngsi_ld_entity_type(method, entity_id, op_target)
   else
      return false, "No NGSI-v2 or NGSI-LD request could be evaluated from URI"
   end
end


-- **************************************************
--  Functions for evaluating NGSI request attributes
-- **************************************************

-- Get entity attributes of NGSI-v2 request
local function get_ngsi_v2_entity_attributes(method_var, entity_id, op_target_var)
   -- NGSI-v2 not implemented yet
   return false, "NGSI-v2 is not supported yet"
end

-- Get entity attributes of NGSI-LD request
local function get_ngsi_ld_entity_attributes(method_var, entity_id, op_target_var)
   -- Get HTTP method and validate for NGSI-LD (if not supplied)
   local method, method_err = nil, nil
   if method_var then
      method = method_var
   else 
      method, method_err = _M.get_request_action()
      if method_err then
	 return nil, method_err
      end
   end

   -- Get request URI and strip query args
   local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")

   -- Get operation target (e.g., entity or subscription) if not supplied in this method
   local op_target, op_target_err = nil, nil
   if op_target_var then
      op_target = op_target_var
   else
      local in_uri = string.gsub(ngx.var.request_uri, "?.*", "")
      op_target, op_target_err = _M.check_operation_target(method, in_uri)
      if op_target_err then
	 return nil, op_target_err
      end
   end

   -- Get request headers
   local req_headers = ngx.req.get_headers()

   -- Get attributes based on HTTP method
   local attrs = {}
   if method == "PATCH" then
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	 -- PATCH entity: Get attribute from URL
	 table.insert(attrs, attr)
      elseif op_target == _M.OP_TARGET_SUBSCRIPTION then -- PATCH subscription: allow for all attributes
	 table.insert(attrs, "*")
      elseif req_headers and req_headers["Content-Type"] and req_headers["Content-Type"] == "application/json" then
	 -- PATCH entity: Get attributes from body, if specified and not in URI
	 ngx.req.read_body()
	 local body_data = ngx.req.get_body_data()
	 local body_json = cjson.decode(body_data)
	 for index, value in pairs(body_json) do
	    table.insert(attrs, index)
	 end
      end

   elseif method == "DELETE" then
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	 table.insert(attrs, attr)
      else
	 -- Deleting whole entity, set wildcard for attributes
	 -- Also for delete subscription or notification
	 table.insert(attrs, "*")
      end

   elseif method == "GET" then
      -- Set wildcard for attributes
      table.insert(attrs, "*")

   elseif method == "POST" then
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	 -- Attribute part of URI, creating single attribute for entity
	 table.insert(attrs, attr)
      else
	 -- Whole entity to be created, wildcard for attributes
	 -- Also for POST subscription and notification
	 table.insert(attrs, "*")
      end
      
   end
   
   -- NGSI-LD not implemented yet
   return attrs, nil
end

-- Get entity attributes of NGSI request
function _M.get_ngsi_entity_attributes(method, entity_id, op_target)
   if _M.is_ngsi_v2() then
      return get_ngsi_v2_entity_attributes(method, entity_id, op_target)
   elseif _M.is_ngsi_ld() then
      return get_ngsi_ld_entity_attributes(method, entity_id, op_target)
   else
      return false, "No NGSI-v2 or NGSI-LD request could be evaluated from URI"
   end
end

return _M
