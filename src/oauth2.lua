-- OAuth 2.0 module for Lua 5.2+
local url = require 'net.url'
local json = require 'json'
local curl = require 'cURL'


local type = type
local pcall = pcall
local io = io
local os = os
local tostring = tostring
local tonumber = tonumber
local table = table
local setmetatable = setmetatable
local getmetatable = getmetatable
local pairs = pairs

-- Create the module table here
local M = {}
package.loaded[...] = M
_ENV = M		-- Lua 5.2+

_VERSION = "1.15.12.07"

local identifier = {}

local function copyTable(source, target)
	for k, v in pairs(source) do
		target[k] = v
	end
end

local function file_exists(file)
	local f,err = io.open(file,"r")
	if not f then
		return nil,"Error opening file: "..file.." : "..err
	end
	f:close()
	return true
end 

local function load_file(name)
	local f, msg = io.open(name, 'rb')
	if not f then 
		return nil,"Error opening file: "..msg
	end
	local stat = f:read('*all')
	f:close()
	if not stat then 
		return nil,'Failed to read file: '..name 
	end
	return stat
end

local function load_JSON_file(name)
	local stat,msg = load_file(name)
	if not stat then
		return nil, "Error loading file: "..name.." "..msg
	end
	if #stat == 0 then 
		return nil,'This file is empty: '..name 
	end
	return json.decode(stat)
end

local function save_file(name, content)
	content = content or ""
	local f, err = io.open(name, 'wb')
	if not f then 
		return nil,"Cannot open file "..name.." for writing: "..err
	end
	local ret = f:write(content)
	f:close()
	if not ret then 
		return nil,"Cannot write to file "..name
	end
	return true
end

local function save_JSON_file(name, content)
	local ret = json.encode(content)
	return save_file(name, ret)
end

-- Only function using CURL (Should replace it with LuaSocket)
local function httpRequest(url, payload, headers, verb, options)
	local c = curl.easy_init()
	c:setopt_url(tostring(url))
	if options and options['ssl_verifypeer'] ~= nil then	-- Normally set ssl_verifypeer = 0
		c:setopt_ssl_verifypeer(options['ssl_verifypeer'])
	end
	if verb then
		c:setopt_customrequest(verb)
	end
	if headers then
		c:setopt_httpheader(headers)
	end
	if payload and type(payload) == 'table' then
		c:post(payload)
	elseif payload then
		c:setopt_post(1)
		c:setopt_postfields(payload)
--		c:setopt_postfieldsize(#payload)
	end
	local output = {}
	local code = 0
	c:perform{
		writefunction = function(data)
			table.insert(output, data)
		end,
		headerfunction = function(data)
			-- skip empty lines and other header lines once code is set to a non-100-Continue value
			if #data <= 2 or not (code == 0 or code == 100) then return end
			code = tonumber(data:match('^[^ ]+ ([0-9]+) '))
		end}
	return table.concat(output), code
end

local function validateOauth(o)
	if not o.creds or type(o.creds) ~= "table" then
		return nil,"OAuth object does not have a credentials table."
	end
	if not o.creds.client_id or type(o.creds.client_id) ~= "string" then
		return nil,"OAuth credentials table does not have a client_id."
	end
	if not o.creds.client_secret or type(o.creds.client_secret) ~= "string" then
		return nil,"OAuth credentials table does not have a client secret."
	end
	if o.creds.redirect_uris then
		-- Check if the redirect_uri is valid
		if o.config.redirect_uri or o.config.redirect_url then
			local ru = o.config.redirect_uri or o.config.redirect_url
			local found
			for i = 1,#o.creds.redirect_uris do
				if ru == o.creds.redirect_uris[i] then
					found = true
					break
				end
			end
			if not found then
				return nil,"OAuth configuration redirect_uri does not match the ones allowed in the credentials."
			end
		else
			o.config.redirect_uri = o.creds.redirect_uris[1]
		end
	end
	return true
end

local function validateConfig(config)
	if type(config) ~= "table" then
		return nil,"Need the configuration table as an argument for the oAuth object"
	end
	if not config.creds_file and not config.creds or 
	  (config.creds_file and (type(config.creds_file) ~= "string" or not file_exists(config.creds_file))) or
	  (config.creds and type(config.creds) ~= "table") then 
		return nil,"The Configuration does not have a valid creds_file link or a creds table"
	end
	if (config.tokens_file and type(config.tokens_file) ~= "string") then
		return nil,"The Configuration does not have a valid tokens_file string name."
	end
	if (config.tokens and type(config.tokens) ~= "table") then 
		return nil,"The configuration tokens should be a table"
	end
	if not config.auth_uri and not config.auth_url or (config.auth_uri and type(config.auth_uri) ~= "string") or
	  (config.auth_url and type(config.auth_url) ~= "string") then
		return nil,"The configuration needs to have a authorization URI string"
	end
	if (config.redirect_uri or config.redirect_url) and ((config.redirect_uri and type(config.redirect_uri) ~= "string") or
	  (config.redirect_url and type(config.redirect_url) ~= "string")) then
		return nil,"The redirect_uri if given should be a string."
	end
	if not config.token_uri and not config.token_url or (config.token_uri and type(config.token_uri) ~= "string") or
	  (config.token_url and type(config.token_url) ~= "string") then
		return nil,"The configuration needs to have a token URI string"
	end
	if config.scope and type(config.scope) ~= "string" then
		return nil,"The scope if given should be a string."
	end
	if config.access_type and type(config.access_type) ~= "string" then
		return nil,"The access_type if given should be a string"
	end
	if config.approval_prompt and type(config.approval_prompt) ~= "string" then
		return nil,"The approval_prompt parameter if given should be string."
	end
	return true
end

local function updateToken(self,params)
	params.client_id = self.creds.client_id
	params.client_secret = self.creds.client_secret

	local content, code = httpRequest(self.config.token_uri or self.config.token_url, params, nil, nil, self.config.curl_options)
	if code ~= 200 then 
		return nil,'Bad http response code: '..tostring(code)
	end

	local resp = json.decode(content)
	self.tokens = self.tokens or {}
	self.tokens.access_token = resp.access_token
	self.tokens.token_type = resp.token_type
	if resp.refresh_token then
		self.tokens.refresh_token = resp.refresh_token
	end
	self.tokens.expires = os.time() + resp.expires_in
	if self.config.tokens_file then
		local stat,msg = pcall(save_JSON_file,self.config.tokens_file,self.tokens)
	end
	return true
end

local function refreshToken(self)
	local params = {
		grant_type = 'refresh_token',
		refresh_token = self.tokens.refresh_token,
	}
	return updateToken(self,params)
end

local function request(self, url, payload, headers, verb, options)
	if getmetatable(self) ~= identifier then
		return nil,"Invalid OAuth object"
	end
	if not self.tokens then 
		return nil,"Access token not acquired yet. Run obj:aquireToken()"
	end
	if os.time() >= self.tokens.expires	then 
		-- Token has expired
		refreshToken(self) 
	end
	local tmp = string.format('Authorization: %s %s', self.tokens.token_type, self.tokens.access_token)
	headers = headers or {}
	table.insert(headers, tmp)
	options = options or {}
	copyTable(self.config.curl_options, options)
	return httpRequest(url, payload, headers, verb, options)
end

-- Returns the parsed URL as a table
local function buildAuthUrl(self,state)
	local result = url.parse(self.config.auth_uri or self.config.auth_url)
	local tmp = {
		response_type = 'code',
		client_id = self.creds.client_id,
		redirect_uri = self.config.redirect_uri or self.config.redirect_url,
		scope = self.config.scope,
		state = state,
		access_type = self.config.access_type,
		approval_prompt = self.config.approval_prompt
	}
	copyTable(tmp, result.query)
	return result
end


local function acquireToken(self)
	if getmetatable(self) ~= identifier then
		return nil,"Invalid OAuth object"
	end
	local url = buildAuthUrl(self,os.time())		-- Returns the parsed URL as a table
	return {tostring(url),function(code)			-- Function to authorize the token called by passing the code
		local params = {
			grant_type = 'authorization_code',
			redirect_uri = self.config.redirect_uri or self.config.redirect_url,
			scope = self.config.scope,
			code = code,
		}
		return updateToken(self,params)
	end}
end


-- Function to create and initialize a new oAuth2.0 object
-- config is the configuration table that defines the connection. Valid members are:
-- * creds_file (OPT this or creds) - Local path to the credentials json file. This file is loaded with all its elemets entered in the configuration
-- * tokens_file (OPT) - Local path to the tokens file previously obtained for the same connection. If not given the the acquired tokens will not be saved locally
-- * creds (OPT this or creds_file) - The credentials table for the OAuth object. Either this or the creds_file should be given
-- * tokens (OPT) - The tokens table for the OAuth object. 
-- * scope (OPT) - Scope of the access
-- * redirect_uri or redirect_url (OPT)
-- * access_type (OPT)
-- * approval_prompt (OPT)
-- * token_uri or token_url (REQUIRED)
-- * auth_uri or auth_url (REQUIRED)

-- Sample creds.json:
--[[
{
	"client_id":"CLIENT ID STRING",
	"auth_uri":"https://accounts.google.com/o/oauth2/auth",
	"token_uri":"https://accounts.google.com/o/oauth2/token",
	"auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
	"client_secret":"CLIENT SECRET STRING",
	"redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]
}
]]
function new(config)
	local stat,msg,msg2
	stat,msg = validateConfig(config)
	if not stat then
		return nil,"Invalid Configuration: "..msg
	end
	local obj = {
		config = {},
		creds = {},
		acquireToken = acquireToken,
		request = request
	}
	setmetatable(obj,identifier)
	copyTable(config,obj.config)
	if config.creds and type(config.creds) == "table" then
		copyTable(config.creds,obj.creds)
	end
	if config.tokens and type(config.tokens) == "table" then
		obj.tokens = {}
		copyTable(config.tokens,obj.tokens)
	end
	-- Now check if a creds_file and tokens_file is specified then load it
	if config.creds_file and file_exists(config.creds_file) then
		stat,msg,msg2 = pcall(load_JSON_file,config.creds_file)
		if not stat then
			return nil,"Error loading credientials file: "..config.creds_file.." "..msg
		end
		if msg then
			obj.creds = msg
		else
			return nil,"Could not load any credentials from the file "..config.creds_file.." "..msg2
		end
	end
	if config.tokens_file and file_exists(config.tokens_file) then
		stat,msg,msg2 = pcall(load_JSON_file,config.tokens_file)
		if not stat then
			return nil,"Error loading tokens file: "..config.tokens_file.." "..msg
		end
		if msg then
			obj.tokens = msg
		end
	end
	stat,msg = validateOauth(obj)
	if not stat then
		return nil,"Invalid configuration given: "..msg
	end
	return obj
end

