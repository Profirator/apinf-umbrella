local cjson = require "cjson"
local config = require "api-umbrella.proxy.models.file_config"
local jwt = require "resty.jwt"
local mongo = require "api-umbrella.utils.mongo"
local http = require "resty.http"
local utils = require "api-umbrella.proxy.utils"
local _M = {}


local function get_idm_user_info(token, dict)
    local idp_host, result, res, err, rpath, resource, method
    local app_id = dict["app_id"]
    local mode = dict["mode"]
    local idp_back_name = dict["idp"]["backend_name"]
    local headers = {}
    local ssl = false
    local httpc = http.new()
    httpc:set_timeout(45000)

    if config["nginx"]["lua_ssl_trusted_certificate"] then
        ssl=true
    end

    local rquery =  "access_token="..token
    if idp_back_name == "google-oauth2" then
        rpath = "/oauth2/v3/userinfo"
        idp_host="https://www.googleapis.com"
    elseif idp_back_name == "fiware-oauth2" and mode == "authorization" then
        rpath = "/user"
        idp_host = dict["idp"]["host"]
        -- resource = ngx.ctx.uri
	-- correcting the uir parameter. Findings from Smartmaas project
	resource = ngx.escape_uri(ngx.var.request_uri)
        method = ngx.ctx.request_method
        rquery = "access_token="..token.."&app_id="..app_id.."&resource="..resource.."&action="..method
    elseif idp_back_name == "fiware-oauth2" and mode == "authentication" then
        rpath = "/user"
        idp_host = dict["idp"]["host"]
        rquery = "access_token="..token.."&app_id="..app_id
    elseif idp_back_name == "keycloak-oauth2" then
        rpath = "/auth/realms/"..dict["idp"]["realm"].."/protocol/openid-connect/userinfo"
        idp_host = dict["idp"]["host"]
        rquery = ""
        headers["Authorization"] = "Bearer "..token
    elseif idp_back_name == "facebook-oauth2" then
        rpath = "/me"
        idp_host="https://graph.facebook.com"
        rquery = "fields=id,name,email&access_token="..token
    elseif idp_back_name == "github-oauth2" then
        rpath = "/user"
        idp_host="https://api.github.com"
    end

    res, err =  httpc:request_uri(idp_host..rpath, {
        method = "GET",
        query = rquery,
        headers = headers,
        ssl_verify = ssl,
    })

    if res and (res.status == 200 or res.status == 201) then
        local body = res.body
        if not body then
            return nil
        end
        result = cjson.decode(body)

        if idp_back_name == "fiware-oauth2" then
	         -- In authorization mode, first evaluate authorization_decision flag
	          if mode == "authorization" and result["authorization_decision"] ~= "Permit" then
	              return nil, " Authorization denied"
	          -- elseif added by smartmaas team
	          elseif mode == "authorization" and result["authorization_decision"] == "Permit" then	
                return result
	          end

            -- Process organization info to generate organization scope roles
            if result["organizations"] ~= nil then
                for _, org in ipairs(result["organizations"]) do
                    for _, org_role in ipairs(org["roles"]) do
                        -- Generate organization role
                        local role_name = org["id"] .. "."
                        role_name = role_name .. org_role["name"]

                        ngx.log(ngx.INFO, "Generated org role: ", role_name)
                        result["roles"][#result["roles"] + 1] = role_name
                    end
                end
            end
        end
    end

    return result, err
end

local function decode_jwt(token, key)
    -- Parse the JWT token
    local decoded_token = jwt:verify(key, token)

    if not decoded_token["valid"] then
        return nil, "The provided JWT is not valid"
    end

    return decoded_token["payload"], nil
end

local function build_keycloak_role_mapping(parsed_token, dict)
    local result = {}

    result["email"] = parsed_token["email"]
    result["roles"] = {}

    -- Load roles info
    if parsed_token["realm_access"] ~= nil then
        for _, role in ipairs(parsed_token["realm_access"]["roles"]) do
            ngx.log(ngx.INFO, "Generated realm role: ", role_name)

            result["roles"][#result["roles"] + 1] = "realm."..role
        end
    end

    if parsed_token["resource_access"][dict["app_id"]] ~= nil then
        for _, role in ipairs(parsed_token["resource_access"][dict["app_id"]]["roles"]) do
            result["roles"][#result["roles"] + 1] = role
        end
    end
    return result
end

local function build_fiware_role_mapping(parsed_token, dict)
    local result = {}
    -- Check how a Keyrock JWT looks like
    -- TODO: Validation of app id only for non external
    result["email"] = parsed_token["email"]
    result["roles"] = {}

    -- Process user roles
    for _, role in ipairs(parsed_token["roles"]) do
        result["roles"][#result["roles"] + 1] = role["name"]
    end

    -- Process organization info to generate organization scope roles
    if parsed_token["organizations"] ~= nil then
        for _, org in ipairs(parsed_token["organizations"]) do
            for _, org_role in ipairs(org["roles"]) do
                -- Generate organization role
                local role_name = org["id"] .. "."
                role_name = role_name .. org_role["name"]

                ngx.log(ngx.INFO, "Generated org role: ", role_name)
                result["roles"][#result["roles"] + 1] = role_name
            end
        end
    end

    return result
end

local function get_fiware_organization_roles(dict, organization_id)
    -- Get Keyrock admin token
    local idp_host = dict["idp"]["host"]
    local admin_user = dict["idp"]["admin_user"]
    local admin_cred = dict["idp"]["admin_credentials"]

    local ssl = false
    if config["nginx"]["lua_ssl_trusted_certificate"] then
        ssl=true
    end

    local headers = {}
    headers["content-type"] = "application/json"

    local token_body = {}
    token_body["name"] = admin_user
    token_body["password"] = admin_cred

    local httpc = http.new()
    httpc:set_timeout(45000)

    res, err =  httpc:request_uri(idp_host.."/v1/auth/tokens", {
        method = "POST",
        headers = headers,
        body = cjson.encode(token_body),
        ssl_verify = ssl
    })

    if not res or (res.status ~= 200 and res.status ~= 201) then
        return nil, 'Error accessing fiware IDM'
    end

    -- Get token from res
    local api_token
    for k,v in pairs(res.headers) do
        if string.lower(k) == "x-subject-token" then
            api_token = v
        end
    end

    -- Get organization role mapping
    local org_mapping_url = "/v1/applications/"..dict["app_id"].."/organizations/"..organization_id.."/roles"
    headers = {}
    headers['x-auth-token'] = api_token

    res, err =  httpc:request_uri(idp_host..org_mapping_url, {
        method = "GET",
        headers = headers,
        ssl_verify = ssl,
    })

    if not res or (res.status ~= 200 and res.status ~= 201) then
        return nil, 'Error accessing fiware IDM'
    end

    -- Build role name array
    local role_mapping = cjson.decode(res.body)
    local org_roles = {}

    for i, role in ipairs(role_mapping["role_organization_assignments"]) do
        -- Get role info
        local role_path = "/v1/applications/"..dict["app_id"].."/roles/"..role["role_id"]
        res, err =  httpc:request_uri(idp_host..role_path, {
            method = "GET",
            headers = headers,
            ssl_verify = ssl,
        })
    
        if not res or (res.status ~= 200 and res.status ~= 201) then
            return nil, 'Error accessing fiware IDM'
        end

        local role_info = cjson.decode(res.body)
        org_roles[i] = role_info["role"]["name"]
    end

    return org_roles, nil
end

local function get_ext_provider_user_info(token, dict)
    local result, err, raw_idp, idp, parsed_token
    local idp_back_name = dict["idp"]["backend_name"]

    -- Check that the ext provider feature is supported
    if idp_back_name ~= "fiware-oauth2" or not dict["idp"]["jwt_enabled"] then
        -- TODO: Support Keycloak as external IDP
        return nil, "The external IDP feature is only enabled for FIWARE IDP with JWT enabled"
    end

    -- Search for IDP config in the database
    raw_idp, db_err = mongo.first("idps", {
        query = {
	   endpoint = dict["key_auth_provider"],
	   deleted_at = nil
        },
    })

    if not raw_idp then
        return nil, "IDP provider not found"
    end

    idp = utils.pick_where_present(raw_idp, {
        "endpoint",
        "secret",
        "organization_id"
    })

    -- Validate JWT using external secret
    parsed_token, err = decode_jwt(token, idp['secret'])

    -- Get fiware organization roles
    local org_roles
    org_roles, err = get_fiware_organization_roles(dict, idp['organization_id'])

    if err ~= nil then
        return nil, err
    end

    -- Validate that user roles could be assigned
    local invalid_role = nil
    for _, role in ipairs(parsed_token['roles']) do
        local found = false
        for _, org_role in ipairs(org_roles) do
            found = org_role == role["name"]
        end
        if not found then
            invalid_role = role["name"]
        end
    end

    if invalid_role ~= nil then
        ngx.log(ngx.ERR, "INVALID ROLE", invalid_role)
        return nil, 'You are not authorized to map ' .. invalid_role
    end

    -- Return efective role mapping
    result = build_fiware_role_mapping(parsed_token, dict)

    return result, err
end

local function get_jwt_policies_user_info(token, dict)
   -- CB-attr based auth user info from JWT
   local result = {}
   local err, parsed_token
   
   -- Decode JWT without validation
   local decoded_token = jwt:load_jwt(token)
   
   if not decoded_token["valid"] then
      return nil, "The provided JWT is not valid"
   end
   
   parsed_token = decoded_token["payload"]
      
   result["email"] = parsed_token["email"]
   result["iss"] = parsed_token["iss"]
   result["sub"] = parsed_token["sub"]
   result["aud"] = parsed_token["aud"]
   if parsed_token["authorisationRegistry"] then
      result["authorisation_registry"] = parsed_token["authorisationRegistry"]
   end
   if parsed_token["delegationEvidence"] then
      result["delegation_evidence"] = parsed_token["delegationEvidence"]
   end
   -- result["roles"] = {}
   
   return result, err 
end

local function get_jwt_user_info(token, dict)
    local result, err, parsed_token

    local idp_back_name = dict["idp"]["backend_name"]

    -- Secrets are generated by app in Keyrock
    parsed_token, err = decode_jwt(token, dict["idp"]["key"])

    if err ~= nil then
        ngx.log(ngx.ERR, "Token parse error", err)
        return nil, err
    end

    if idp_back_name == "keycloak-oauth2" then
        result = build_keycloak_role_mapping(parsed_token, dict)
    elseif idp_back_name == "fiware-oauth2" then
        -- Check if the request is in the correct scope
        if dict["app_id"] ~= parsed_token["app_id"] then
            return nil, "Invalid scope for access token"
        end
        result = build_fiware_role_mapping(parsed_token, dict)
    end

    return result, err
end

-- Function to connect with an IdP service (Google, Facebook, Fiware, Github) for checking
-- if a token is valid and retrieve the user properties. The function takes
-- the token provided by the user and the IdP provider registered in the api-backend
-- for checking if the token is valid making a validation request to the corresponding IdP.
-- If the token is valid, the user information stored in the IdP is retrieved.

function _M.first(dict)
    local token = dict["key_value"]
    local result, err

    -- Check if the request is made by an external IDM
    if dict["key_auth_provider"] ~= nil then
        result, err = get_ext_provider_user_info(token, dict)
    elseif string.find(dict["mode"], "cb_attr") then
       -- CB-attribute based authorization without external IDP, but external registry and policies
       result, err = get_jwt_policies_user_info(token, dict)
    else
        -- Using local IDP, so using local configuration
        if not dict["idp"]["jwt_enabled"] then
            result, err = get_idm_user_info(token, dict)
        else
            result, err = get_jwt_user_info(token, dict)
        end
    end

    return result, err
end

return _M
