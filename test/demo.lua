require("debugUtil") -- Module to modify lua paths to find my module dependencies
local oauth2 = require 'oauth2'
config = {
	auth_uri = 'https://accounts.google.com/o/oauth2/auth',
	token_url = 'https://accounts.google.com/o/oauth2/token',

	approval_prompt = 'force',
	access_type = 'offline',
	scope = 'https://www.googleapis.com/auth/drive', 
	creds_file = 'creds.json', 	-- Place the creds file if the file is used 
	tokens_file = 'tokens.json',  -- Where to save the tokens file
}

oa,msg = oauth2.new(config)
if oa then
	-- Acquire the token
	status, msg = oa:acquireToken()
	if status then
		-- Get the token from the user and give it to the object
		print("Go to the following URL and grant permissions and get the authorization code:")
		print(status[1])
		print("Enter the authorization code:")
		code = io.read()
		status,msg,content = status[2](code)
		if not status then
			print("Code authorization failed: "..msg,content)
		else
			print('Token acquired successfully.')
			-- Now try a request to get the root directory listing
			local url = 'https://www.googleapis.com/drive/v2/files/root?alt=json'
			resp, code = oa:request(url)
			if code < 200 or code > 206 then
				  print("Error "..code)
			else
				  print("Result:\n"..resp)
			end
		end
	else
		print("Error acquiring token "..msg)
	end
else
   print("Error creating oAuth 2.0 object "..msg)
end