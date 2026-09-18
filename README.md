# LuaGuard v2

Roblox-focused static security scanner. It follows literal `game:HttpGet("https://...")` chains up to 3 levels and inspects the downloaded text without executing Lua.

Normal `loadstring`/`HttpGet` usage is not considered malicious by itself. Stronger warnings focus on account/session-cookie targeting, credential references, outbound requests/webhooks, sensitive file access, and combinations suggesting exfiltration.

## Update your deployed site
Replace your existing repo files with this v2 version and commit to `main`. Render should automatically redeploy.
