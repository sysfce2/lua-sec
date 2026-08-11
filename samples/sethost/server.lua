--
-- Public domain
--
local socket = require("socket")
local ssl    = require("ssl")

local params = {
   mode = "server",
   protocol = "any",
   key = "../certs/serverAkey.pem",
   certificate = "../certs/serverA.pem",
   cafile = "../certs/rootA.pem",
   verify = "none",
   options = "all",
}

local ctx = assert(ssl.newcontext(params))

local server = socket.tcp()
server:setoption('reuseaddr', true)
assert( server:bind("127.0.0.1", 8889) )
server:listen()

-- Two connections: one where the client's expected hostname matches the
-- certificate, one where it doesn't. The server itself is oblivious to the
-- hostname check -- that happens entirely on the client side.
for _ = 1, 2 do
   local peer = server:accept()
   peer = ssl.wrap(peer, ctx)
   if peer:dohandshake() then
      pcall(peer.send, peer, "sethost test\n")
   end
   peer:close()
end
