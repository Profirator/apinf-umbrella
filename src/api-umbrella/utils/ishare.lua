-- Imports
local config = require "api-umbrella.proxy.models.file_config"
local cjson = require "cjson"
local jwt = require "resty.jwt"
local x509 = require("resty.openssl.x509")
local http = require "resty.http"

-- Returned object
local _M = {}



-- Set rootCA if provided in config
local isTrustCASet = false
if config["jws"] and config["jws"]["root_ca_file"] then
   jwt:set_trusted_certs_file(config["jws"]["root_ca_file"])
   isTrustCASet = true
end

-- Transforms a raw binary string to HEX
local function tohex(str)
   return (str:gsub('.', function (c)
      return string.format('%02X', string.byte(c))
   end))
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

-- Send HTTP request
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

-- Check required API Umbrella config parameters
function _M.check_config_ar()

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
   
end

-- Check required API Umbrella config parameters
function _M.check_config_satellite()

   -- Check for required config parameters
   if ( (not config["jws"]) or (not config["jws"]["private_key"]) or (not config["jws"]["x5c"]) ) then
      ngx.log(ngx.ERR, "Missing JWS information (PrivateKey+Certificates) in config")
      return "Internal error"
   end
   if (not config["jws"]) or (not config["jws"]["identifier"]) then
      ngx.log(ngx.ERR, "Missing local identifier information in jws config")
      return "Internal error"
   end
   if (not config["satellite"]) or (not config["satellite"]["identifier"]) then
      ngx.log(ngx.ERR, "Missing identifier information in Satellite config")
      return "Internal error"
   end
   if not config["satellite"]["host"] then
      ngx.log(ngx.ERR, "Missing Satellite host information in config")
      return "Internal error"
   end
   local satellite_token_url = config["satellite"]["token_endpoint"]
   local satellite_trusted_list_url = config["satellite"]["trusted_list_endpoint"]
   if not satellite_token_url then
      ngx.log(ngx.ERR, "Missing Satellite /token endpoint information in config")
      return "Internal error"
   end
   if not satellite_trusted_list_url then
      ngx.log(ngx.ERR, "Missing Satellite /trusted_list endpoint information in config")
      return "Internal error"
   end
   
end

-- Get access token from AR (or other iSHARE participant)
function _M.get_token(token_url, iss, sub, aud)
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

-- Get delegation evidence from iSHARE AR using valid access_token
-- prev_steps is optional
function _M.get_delegation_evidence(issuer, target, policies, delegation_url, access_token, prev_steps)

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
      payload["previous_steps"] = {}
      table.insert(payload["previous_steps"], prev_steps)
   end
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

local function get_trusted_list()

   -- Check for required config parameters for AR
   local err = _M.check_config_satellite()
   if err then
      return nil, err
   end
   local local_eori = config["jws"]["identifier"]
   local satellite_eori = config["satellite"]["identifier"]
   local satellite_token_url = config["satellite"]["token_endpoint"]
   local satellite_trusted_list_url = config["satellite"]["trusted_list_endpoint"]

   -- Get token at Satellite
   local token, err = _M.get_token(satellite_token_url, local_eori, local_eori, satellite_eori)
   if err then
      return nil, err
   end

   -- Build header of request
   local headers = {}
   headers["Authorization"] = "Bearer "..token
   
   -- Send request to /delegation endpoint of AR at delegation_url
   local ssl = false
   local options = {
      method = "GET",
      headers = headers,
      ssl_verify = ssl,
   }
   local res, err = request(satellite_trusted_list_url, options)
   if err then
      return nil, "Error when retrieving trusted list from Satellite: "..err
   end

   -- Get trusted_list_token from response
   local res_body = cjson.decode(res.body)
   local trusted_list_token = res_body["trusted_list_token"]
   
   if not trusted_list_token then
      return nil, "trusted_list_token not found in response: "..res_body
   end

   -- Decode trusted_list_token
   local decoded_token = jwt:load_jwt(trusted_list_token)
   if not decoded_token["valid"] then
      return nil, "The received trusted_list JWT is not valid"
   end

   -- Get trusted_list
   if not decoded_token["payload"] and not decoded_token["payload"]["trusted_list"] then
      return nil, "The received trusted list JWT contains no element trusted_list"
   end

   return decoded_token["payload"]["trusted_list"]
   
end

local function check_ca_fingerprint(ca_fingerprint)
   -- Get trusted list from satellite
   local trusted_list, err = get_trusted_list()
   if err then
      return err
   end

   -- Iterate over trusted list and compare to CA fingerprint
   for index, value in pairs(trusted_list) do
      if trusted_list[index] then
	 if trusted_list[index]["certificate_fingerprint"] then
	    if string.upper(trusted_list[index]["certificate_fingerprint"]) == string.upper(ca_fingerprint) then
	       return nil
	    end
	 end
      end
   end

   return "No matching certificate fingerprint in trusted list found"
end

-- Validate and verify iSHARE JWT
function _M.validate_ishare_jwt(token)

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

   -- Check for exp and iat in payload
   local now = os.time()
   local payload = decoded_token["payload"]
   local exp = payload['exp']
   local iat = payload['iat']
   if exp < now or iat > now then
      return "JWT has expired or was issued in the future"
   end
   
   -- Verify signature
   local jwt_obj = nil
   if not isTrustCASet then
      -- Verify fingerprint of x5c root CA against trusted_list of satellite
      local root_cert = header["x5c"][#header["x5c"]]
      root_cert = "-----BEGIN CERTIFICATE-----\n"..root_cert.."\n-----END CERTIFICATE-----\n"
      local root_x509, root_err = x509.new(root_cert)
      if root_err then
	 return "Error when loading x5c root CA: "..root_err
      end
      
      local dig = root_x509:digest("sha256")
      local ca_fingerprint = tohex(dig)
      err = check_ca_fingerprint(ca_fingerprint)
      if err then
	 return "Verification of x5c root CA failed: "..err
      end
      
      -- Verify JWT against x5c certificate chain / root CA and intermediate certs
      local cert_chain = ""
      for index, value in ipairs(header["x5c"]) do
	 --if index ~= 1 then
	 cert_chain = cert_chain.."-----BEGIN CERTIFICATE-----\n"..value.."\n-----END CERTIFICATE-----\n"
	 --end
      end
      --jwt_obj = jwt:verify(pub_key, token)
      jwt_obj = jwt:verify(cert_chain, token)
   else
      -- Root CA file is set
      -- Verify JWT against provided root CA
      jwt_obj = jwt:verify(nil, token)
   end
   if not jwt_obj["valid"] then
      return "Authorization JWT from sender is not valid"
   end
   if not jwt_obj["verified"] then
      return "Verification failed: "..jwt_obj["reason"]
   end

   return nil
end


return _M
