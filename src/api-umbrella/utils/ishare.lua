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
      payload["prev_steps"] = {}
      table.insert(payload["prev_steps"], prev_steps)
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
   -- If Root CA file is set, the verification will include validation of the cert chain
   local jwt_obj = nil
   if not isTrustCASet then
      jwt_obj = jwt:verify(pub_key, token)
   else
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
