-- Oauth2 test file for google drive
--require("debugUtil") --To add paths to search modules
local oauth2 = require 'oauth2'

-- For Google drive

-- config = {
	-- auth_url = 'https://accounts.google.com/o/oauth2/auth',
	-- token_url = 'https://accounts.google.com/o/oauth2/token',

	-- approval_prompt = 'force',
	-- access_type = 'offline',
	-- --redirect_uri = 'urn:ietf:wg:oauth:2.0:oob',	-- Not needed if the creds table or creds_file has a table of redirect_uris
	-- scope = 'https://www.googleapis.com/auth/drive', 
	-- creds_file = [[D:\Milind\Documents\creds.json]], 	-- Place the creds file if the file is used 
	-- -- Sample creds.json:
	-- --[[
	-- {
		-- "client_id":"CLIENT ID STRING",
		-- "auth_uri":"https://accounts.google.com/o/oauth2/auth",
		-- "token_uri":"https://accounts.google.com/o/oauth2/token",
		-- "auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
		-- "client_secret":"CLIENT SECRET STRING",
		-- "redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]
	-- }
	-- ]]
	-- --[[ Use this block if creds.json file is not used,add the client id and secret  ]
	-- creds = {
		-- client_id = "CLIENT ID STRING",
		-- auth_uri = "https://accounts.google.com/o/oauth2/auth",
		-- token_uri = "https://accounts.google.com/o/oauth2/token",
		-- ["auth_provider_x509_cert_url"] = "https://www.googleapis.com/oauth2/v1/certs",
		-- client_secret = "CLIENT SECRET STRING",
		-- redirect_uris = {
			-- "urn:ietf:wg:oauth:2.0:oob",
			-- "http://localhost"
		-- }
	-- }
	-- --[ Creds Block ends ]]
	-- tokens_file = 'tokens.json',
-- }

--For Amazon cloud drive
config = {
	auth_uri = "https://www.amazon.com/ap/oa",
	token_url = "https://api.amazon.com/auth/o2/token",

	approval_prompt = 'force',
	access_type = 'offline',
	--redirect_uri = 'urn:ietf:wg:oauth:2.0:oob',	-- Not needed if the creds table or creds_file has a table of redirect_uris
	scope = 'clouddrive:read_all clouddrive:write', 
	creds_file = [[D:\Milind\Documents\credsamzn.json]], 	-- Place the creds file if the file is used 
	tokens_file = 'tokens.json',
}
oagdrive,msg = oauth2.new(config)
if oagdrive then
	local status
	status, msg = oagdrive:acquireToken()
	if status then
		print("Go to the following URL and grant permissions and get the authorization code:")
		print(status[1])
		print("Enter the authorization code:")
		code = io.read()
		status,msg,content = status[2](code)
		if not status then
			print("Code authorization failed: "..msg,content)
		else
			print('Token acquired successfully.')
			print('Now trying the refresh token code.')
			-- Get the refresh token function
			local t = debug.getinfo(oagdrive.request)
			local name,func,refreshToken
			for i = 1,t.nups do
				name,func = debug.getupvalue(oagdrive.request,i)
				if name == "refreshToken" then
					refreshToken = func
					break
				end
			end
			assert(refreshToken,"refreshToken function not found in the upvalues of the request function")
			stat,msg = refreshToken(oagdrive)
			if not stat then
				print("Token refresh failed: "..msg)
			else
				print("Token refreshed successfully.")
			end
			os.remove(oagdrive.config.tokens_file)
		end
	else
		print('Acquisition failed: ' .. msg)
	end
else
	print("Could not create OAuth2 object "..msg)
end
