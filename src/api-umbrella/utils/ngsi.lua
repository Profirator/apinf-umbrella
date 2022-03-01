-- Imports
local cjson = require "cjson"

-- Returned object
local _M = {}

-- Exported constants
_M.OP_TYPE_ENTITY = "ENTITY"
_M.OP_TYPE_BATCH = "BATCH"
_M.OP_TYPE_SUBSCRIPTION = "SUBSCRIPTION"
_M.OP_TYPE_NOTIFICATION = "NOTIFICATION"



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

-- Function trying to JSON decode request body
-- Can be used with pcall method, to evaluate JSON compatibility before decoding
local function decode_json_body()
   ngx.req.read_body()
   local body_data = ngx.req.get_body_data()
   if (not body_data) or (string.len(body_data) < 1) then
      error()
   end
   local body_json = cjson.decode(body_data)
   return body_json
end

-- **************************************************
--  Functions for evaluating NGSI notifications
-- **************************************************

-- Checks for NGSI notification
function _M.is_ngsi_notification()
   -- Get action from HTTP method
   local method = string.upper(ngx.req.get_method())
   if method ~= "POST" then
      return false
   end

   -- Check if payload body can be decoded as JSON
   if pcall(decode_json_body) then
      -- Notifications cannot be identified by URI, checking type of payload
      ngx.req.read_body()
      local body_data = ngx.req.get_body_data()
      if (not body_data) or (string.len(body_data) < 1) then
	       return false
      end
      local body_json = cjson.decode(body_data)
      if body_json and ( (body_json["subscriptionId"]) or (body_json["type"] and body_json["type"] == "Notification") ) then
	       return true
      end
   end

   return false
end

-- Get subscription ID which NGSI-LD notification is belonging to
local function get_ngsi_ld_notification_subscription_id(method_var)
   -- Get HTTP method and validate for NGSI-LD (if not supplied)
   local method, method_err = nil, nil
   if method_var then
      method = method_var
   else
      method = string.upper(ngx.req.get_method())
   end

   -- Notification only as POST
   local sub_id = nil
   if method == "POST" then
      -- Get subscription ID from payload
      ngx.req.read_body()
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      if body_json and body_json["subscriptionId"] then
	       sub_id = body_json["subscriptionId"]
      else
	       -- No subsciption ID specified, using wildcard
	       sub_id = "*"
      end

   else
      return nil, "Only POST request supported for notification"
   end

   -- Return entity ID
   return sub_id, nil
end

-- Get entity attributes of notification entity data
local function get_ngsi_ld_notification_entity_attributes(entity)
   local attrs = {}
   
   -- Loop over attributes
   for index, value in pairs(entity) do
      if index ~= "id" and index ~= "type" then
	       -- Skip ID and type
	       table.insert(attrs, index)
      end
   end

   return attrs, nil
end

-- Get parameters of NGSI notification
-- Result: Table (array) where each entry represents one entity and has the content:
-- {
--   method = "POST",
--   operation_type = "NOTIFICATION",
--   entity_type = "", (data type of entity in notification)
--   identifier = {subscriptionId},
--   attributes = {array of attributes of entity in notification}
-- }
function _M.get_notification_parameters()
   -- Return object
   local parameters = {}

   -- Get HTTP method
   local method = string.upper(ngx.req.get_method())
   if method ~= "POST" then
      return nil, "Notifications can be only sent as POST request"
   end

   -- Operation type fixed to notification
   local op_type = _M.OP_TYPE_NOTIFICATION
   
   -- Get subscription ID this notification is belonging to
   local sub_id, err = get_ngsi_ld_notification_subscription_id(method)
   if err then
      return nil, err
   end
   local identifier = {}
   table.insert(identifier, sub_id)
   
   -- Get entities data of this notification
   ngx.req.read_body()
   local body_data = ngx.req.get_body_data()
   local body_json = cjson.decode(body_data)
   if (not body_json) or (not body_json["data"]) then
      return nil, "No entity data in notification"
   end
   local entity_data = body_json["data"]
   
   -- Loop over entity types and create parameter object for each type
   for index, entity in pairs(entity_data) do
      -- Parameter object for this entity
      local ngsi_parameter = {
	       method = method,
	       operation_type = op_type,
	       identifier = identifier
      }
      
      -- Get entity type for this entity
      if not entity["type"] then
	       return nil, "Missing entity type in notification"
      end
      ngsi_parameter.entity_type = entity["type"]

      -- Get attributes for this entity type
      local attributes, err = get_ngsi_ld_notification_entity_attributes(entity)
      if err then
	       return nil, err
      end
      ngsi_parameter.attributes = attributes
      
      -- Add to table/array
      table.insert(parameters, ngsi_parameter)
   end
   
   return parameters 
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
	          return _M.OP_TYPE_ENTITY, nil
	       end
	       local check_sub = string.match(in_uri, ".*/subscriptions/.+")
	       if check_sub then
	          return _M.OP_TYPE_SUBSCRIPTION, nil
	       end
	       return nil, "No NGSI-LD compliant PATCH request"

      elseif method == "DELETE" then
	       -- DELETE request allows for deleting entities (or attributes) and subscriptions
	       -- (lua does not support non-capturing groups)
	       -- Batch delete via ngsi-ld/v1/entityOperations/delete not supported yet
	       local check_ent = string.match(in_uri, ".*/entities/.+/?a?t?t?r?s?/?.*")
	       if check_ent then
	          return _M.OP_TYPE_ENTITY, nil
	       end
	       local check_sub = string.match(in_uri, ".*/subscriptions/.+")
	       if check_sub then
	          return _M.OP_TYPE_SUBSCRIPTION, nil
	       end
	       return nil, "No NGSI-LD compliant DELETE request"

      elseif method == "GET" then
	       -- GET request for allows reading entities attributes and subscriptions
	       local check_ent = string.match(in_uri, ".*/entities/*.*")
	       if check_ent then
	          return _M.OP_TYPE_ENTITY, nil
	       end
	       local check_sub = string.match(in_uri, ".*/subscriptions/*.*")
	       if check_sub then
	          return _M.OP_TYPE_SUBSCRIPTION, nil
	       end
	       return nil, "No NGSI-LD compliant GET request"

      elseif method == "POST" then
	       -- POST request allows for creating entities or subscriptions, or sending notifications
	       -- Batch create via ngsi-ld/v1/entityOperations/upsert and ngsi-ld/v1/entityOperations/create not supported yet
	       local check_ent = string.match(in_uri, ".*/entities/*.*")
	       if check_ent then
	          return _M.OP_TYPE_ENTITY, nil
	       end
	       local check_sub = string.match(in_uri, ".*/subscriptions/*")
	       if check_sub then
	          return _M.OP_TYPE_SUBSCRIPTION, nil
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

-- Get subscription ID of NGSI-LD subscription request
local function get_ngsi_ld_subscription_id(method_var)
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

   -- Retrieve entity ID for different action types
   local sub_id = nil
   if method == "PATCH" or method == "DELETE" then
      -- Get single subscription ID from URI
      sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
      if (not sub_id) or (not (string.len(sub_id) > 0)) then
	       return nil, "No subscription ID specified for "..method.." request"
      end
      
   elseif method == "GET" then
      -- Get single subscription ID from URI
      sub_id = string.match(in_uri, ".*/subscriptions/([^/.]+)")
      if (not sub_id) or (not (string.len(sub_id) > 0)) then
	       -- No ID specified, request all subscriptions via wildcard
	       sub_id = "*"
      end

   elseif method == "POST" then
      -- Get single subscription ID from payload
      ngx.req.read_body()
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      if body_json["id"] then
	       -- ID specified for subscription
	       sub_id = body_json["id"]
      else 
	       -- POST subscription has no ID, applying wildcard
	       sub_id = "*"
      end
      
   end

   -- Return subscription ID
   return sub_id, nil
end

-- Get entity ID of NGSI-LD request for single entity operation
local function get_ngsi_ld_single_entity_id(method_var)
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

   -- Retrieve entity ID for different HTTP methods
   local entity_id = nil
   if method == "PATCH" or method == "DELETE" then
      -- Get single ID from URI only
      entity_id = string.match(in_uri, ".*/entities/(.+)/attrs.*")
      if (not entity_id) or (not (string.len(entity_id) > 0)) then
	       return nil, "No entity ID specified for "..method.." request"
      end
      
   elseif method == "GET" then
      -- Get single ID from URI or set wildcard
      entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      if (not entity_id) or (not (string.len(entity_id) > 0)) then
	      -- No entity ID specified, requesting all entities
	      entity_id = "*"
      end

   elseif method == "POST" then
      -- Get single ID from URI or payload
      entity_id = string.match(in_uri, ".*/entities/([^/.]+)")
      if (not entity_id) or (not (string.len(entity_id) > 0)) then
	       -- POST entity: No entity ID specified in URI, obtaining from payload
	       ngx.req.read_body()
	       local body_data = ngx.req.get_body_data()
	       local body_json = cjson.decode(body_data)
	       if not body_json["id"] then
	          return nil, "Missing entity ID in payload of POST request"
	       end
	       entity_id = body_json["id"]
      end
      
   end

   -- Return entity ID
   return entity_id, nil
end


-- **************************************************
--  Functions for evaluating NGSI request type
-- **************************************************

-- Get entity type of NGSI-LD request for subscriptions
-- Returns the entity type that is being watched for changes
local function get_ngsi_ld_subscription_entity_type(method_var)
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

   -- Get entity type of subscription
   local entity_type = ""
   if method == "PATCH" then
      -- Get entity type from payload
      ngx.req.read_body()
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      if body_json and body_json["entities"] and body_json["entities"][1] and body_json["entities"][1]["type"] then
	       -- NGSI-LD specification states that entities array has cardinality 0..1
	       entity_type = body_json["entities"][1]["type"]
      else
	       -- No change to watched entity type, therefore set to wildcard
	       -- TODO: Fails, because wildcard for type not supported by AR
	       entity_type = "*"
      end

   elseif method == "DELETE" or method == "GET" then
      -- For DELETE and GET requests, there is no restriction to the entity type
      -- TODO: Fails, because wildcard for type not supported by AR
      entity_type = "*"

   elseif method == "POST" then
      -- Get entity type from payload
      ngx.req.read_body()
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      if body_json and body_json["entities"] and body_json["entities"][1] and body_json["entities"][1]["type"] then
	       -- NGSI-LD specification states that entities array has cardinality 0..1
	       entity_type = body_json["entities"][1]["type"]
      else
	       return nil, "No entity type specified for POST subscription request"
      end
      
   end

   return entity_type, nil
end

-- Get entity type of NGSI-LD request for single entity operation
local function get_ngsi_ld_single_entity_type(method_var, entity_id)
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

   -- Get entity type depending on HTTP method
   local entity_type = ""
   if method == "PATCH" or method == "DELETE" then
      entity_type = get_type_from_entity_id(entity_id)
      if (not entity_type) or (not (string.len(entity_type) > 0)) then
	       -- PATCH/DELETE entity: no type determined from ID, throw error
	       return nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
      end

   elseif method == "GET" then
      -- Get entity type if specified
      -- Otherwise use wildcard 
      entity_type = "*"
      if uri_args and uri_args["type"] then
	       entity_type = uri_args["type"]
      elseif post_args and post_args["type"] then
	       entity_type = post_args["type"]
      elseif entity_id ~= "*" then
	       entity_type = get_type_from_entity_id(entity_id)
	       if (not entity_type) or (not (string.len(entity_type) > 0)) then
	          return nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
	       end
      else
	       -- TODO: Wildcard not supported at iSHARE AR for type? For the moment throw error if type not specified
	       return nil, "No type specified for GET request"
      end
      
   elseif method == "POST" then
      -- Get entity type from payload or entity ID
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      if body_json and body_json["type"] then
	       entity_type = body_json["type"]
      else
	       entity_type = get_type_from_entity_id(entity_id)
	       if (not entity_type) or (not (string.len(entity_type) > 0)) then
	          return nil, "Entity ID must be urn:XXX:<TYPE>:XXX in order to determine the entity type"
	       end
      end
      
   end

   return entity_type, nil
end
   

-- **************************************************
--  Functions for evaluating NGSI request attributes
-- **************************************************

-- Get entity attributes of NGSI-LD request for subscription
-- Returns entity attributes specified for the subscribed notification
local function get_ngsi_ld_subscription_entity_attributes(method_var)
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

   -- Get attributes based on HTTP method
   local attrs = {}
   if method == "GET" or method == "DELETE" then
      -- Set wildcard for attributes
      table.insert(attrs, "*")

   elseif method == "POST" or method == "PATCH" then
      -- Get attributes from body
      ngx.req.read_body()
      local body_data = ngx.req.get_body_data()
      local body_json = cjson.decode(body_data)
      if body_json and body_json["notification"] and body_json["notification"]["attributes"] and type(body_json["notification"]["attributes"]) == "table" then
	       -- Attributes specified in array
	       attrs = body_json["notification"]["attributes"]
      elseif body_json and body_json["notification"] and body_json["notification"]["attributes"] and type(body_json["notification"]["attributes"]) == "string" then
	       -- Single attribute as string (should be rejected by NGSI-LD API)
	       table.insert(attrs, body_json["notification"]["attributes"])
      else
	       -- No attributes specified, notifications for all attributes requested
	       table.insert(attrs, "*")
      end
      
   end
   
   -- NGSI-LD not implemented yet
   return attrs, nil
end

-- Get entity attributes of NGSI-LD request for single entity operation
local function get_ngsi_ld_single_entity_attributes(method_var)
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

   -- Get request headers
   local req_headers = ngx.req.get_headers()

   -- Get attributes based on HTTP method
   local attrs = {}
   if method == "PATCH" then
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	       -- PATCH entity: Get attribute from URL
	       table.insert(attrs, attr)
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
	       table.insert(attrs, "*")
      end

   elseif method == "GET" then
      -- Get args
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      local uri_args = ngx.req.get_uri_args()
      if uri_args and uri_args["attrs"] then
	       -- Transform comma-separated list of attributes
	       for att in string.gmatch(uri_args["attrs"], '([^,]+)') do
	          table.insert(attrs, att)
	       end
      elseif post_args and post_args["attrs"] then
	       -- Transform comma-separated list of attributes
	       for att in string.gmatch(post_args["attrs"], '([^,]+)') do
	          table.insert(attrs, att)
	       end
      else 
	       -- No attributes specified, set wildcard for attributes
	       table.insert(attrs, "*")
      end

   elseif method == "POST" then
      local attr = string.match(in_uri, ".*/attrs/(.*)")
      if attr and string.len(attr) > 0 then
	       -- Attribute part of URI, creating single attribute for entity
	       table.insert(attrs, attr)
      else
	       -- Whole entity to be created, wildcard for attributes
	       table.insert(attrs, "*")
      end
      
   end
   
   -- NGSI-LD not implemented yet
   return attrs, nil
end

-- Get NGSI-v2 request parameters as table (array)
local function get_ngsi_v2_parameters()
   -- NGSI-v2 not implemented yet
   return false, "NGSI-v2 is not supported yet"
end

-- Get NGSI-LD request parameters as table (array)
local function get_ngsi_ld_parameters()

   -- Return object
   local parameters = {}

   -- Get HTTP method
   local method, err = _M.get_request_action()
   if err then
      return nil, err
   end
   
   -- Get operation type
   local op_type, err = _M.check_operation_target(method, nil)
   if err then
      return nil, err
   end

   -- Depending on operation type, evaluate parameters
   if op_type == _M.OP_TYPE_ENTITY then
      -- Operation on single entity
      local ngsi_parameter = {
	       method = method,
	       operation_type = op_type
      }
      
      -- Get entity ID and create array
      local entity_id, err = get_ngsi_ld_single_entity_id(method)
      if err then
	       return nil, err
      end
      local identifier = {}
      table.insert(identifier, entity_id)
      ngsi_parameter.identifier = identifier
      
      -- Get entity type
      local entity_type, err = get_ngsi_ld_single_entity_type(method, entity_id)
      if err then
	       return nil, err
      end
      ngsi_parameter.entity_type = entity_type
      
      -- Get entity attributes
      local attributes, err = get_ngsi_ld_single_entity_attributes(method)
      if err then
	       return nil, err
      end
      ngsi_parameter.attributes = attributes

      -- Add to table/array
      table.insert(parameters, ngsi_parameter)
      
   elseif op_type == _M.OP_TYPE_SUBSCRIPTION then
      -- Operation on single subscription
      local ngsi_parameter = {
	       method = method,
	       operation_type = op_type
      }

      -- Get subscription ID and create array
      local sub_id, err = get_ngsi_ld_subscription_id(method)
      if err then
	       return nil, err
      end
      local identifier = {}
      table.insert(identifier, sub_id)
      ngsi_parameter.identifier = identifier
      
      -- Get entity type (spec states that cardinality is 0..1 for type array)
      -- Type refers to the entity type that is being watched for changes
      local entity_type, err = get_ngsi_ld_subscription_entity_type(method)
      if err then
	       return nil, err
      end
      ngsi_parameter.entity_type = entity_type
      
      -- Get notification attributes
      local attributes, err = get_ngsi_ld_subscription_entity_attributes(method)
      if err then
	       return nil, err
      end
      ngsi_parameter.attributes = attributes

      -- Add to table/array
      table.insert(parameters, ngsi_parameter)
        
   elseif op_type == _M.OP_TYPE_BATCH then
      -- Batch, can be for different entities (and types)
      return nil, "Operation type "..op_type.." not supported"
   else
      return nil, "Operation type "..op_type.." not supported"
   end

   return parameters, nil
   
end


-- Get parameters of NGSI request: HTTP method, operation type (e.g., entity, subscription, ...),
--   entity types, entity IDs, attributes
-- Result: Table (array) where each entry has the content:
-- {
--   method = "", (PATCH, POST, GET, DELETE)
--   operation_type = "", (ENTITY, SUBSCRIPTION, ...)
--   entity_type = "", (data type of entity, in case of subscription it is the entity type being watched for changes)
--   identifier = {array of IDs},
--   attributes = {array of attributes}
-- }
function _M.get_ngsi_parameters()
   -- Check for notification first
   if _M.is_ngsi_notification() then
      return _M.get_notification_parameters()
   end

   -- Now check for NGSI-v2/-LD request
   if _M.is_ngsi_v2() then
      return get_ngsi_v2_parameters()
   elseif _M.is_ngsi_ld() then
      return get_ngsi_ld_parameters()
   else
      return nil, "No NGSI-v2 or NGSI-LD request could be evaluated from URI"
   end
end

return _M
