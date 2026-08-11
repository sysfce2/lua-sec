--
-- Public domain
--
-- Demonstrates (and doubles as a test for) automatic, connection-level
-- hostname verification via cfg.host / conn:sethost() / conn:sethostflags(),
-- as opposed to the manual, post-handshake x509:checkhost() (see
-- ../checkhost/client.lua). Because the check runs as part of the
-- connection's own certificate verification, a mismatch fails the handshake
-- itself -- no separate application-side call is needed.
--
-- ../certs/serverA.cnf sets: subjectAltName=DNS:foo.bar.example
--
local socket = require("socket")
local ssl    = require("ssl")

local failures = 0

local function connect(cfg)
   local sock = socket.tcp()
   assert(sock:connect("127.0.0.1", 8889))
   return ssl.wrap(sock, cfg)
end

local base = {
   mode = "client",
   protocol = "tlsv1_2",
   cafile = "../certs/rootA.pem",
   verify = "peer",
   options = "all",
}

-- Matching hostname: handshake must succeed.
do
   local cfg = {}
   for k, v in pairs(base) do cfg[k] = v end
   cfg.host = "foo.bar.example"

   local peer = assert(connect(cfg))
   local ok = peer:dohandshake()
   if not ok then failures = failures + 1 end
   print(string.format("sethost(matching host)   dohandshake = %-5s (expected true ) %s",
      tostring(ok), ok and "OK" or "FAIL"))
   if ok then print(peer:receive("*l")) end
   peer:close()
end

-- Mismatched hostname: handshake must fail, with no manual checkhost() call.
do
   local cfg = {}
   for k, v in pairs(base) do cfg[k] = v end
   cfg.host = "evil.example"

   local peer = assert(connect(cfg))
   local ok, err = peer:dohandshake()
   local pass = (ok == nil or ok == false)
   if not pass then failures = failures + 1 end
   print(string.format("sethost(mismatched host) dohandshake = %-5s err=%-30s (expected false) %s",
      tostring(ok), tostring(err), pass and "OK" or "FAIL"))
   peer:close()
end

-- Invalid hostflags option must be rejected by wrap() itself -- no network
-- round-trip required, so no socket connection is made for this case.
do
   local cfg = {}
   for k, v in pairs(base) do cfg[k] = v end
   cfg.host = "foo.bar.example"
   cfg.hostflags = "bogus_flag"

   local ok, err = ssl.wrap(socket.tcp(), cfg)
   local pass = (ok == nil and err ~= nil)
   if not pass then failures = failures + 1 end
   print(string.format("sethostflags(\"bogus_flag\") = %-5s err=%-30s (expected nil  ) %s",
      tostring(ok), tostring(err), pass and "OK" or "FAIL"))
end

-- cfg.host combined with cfg.dane must be rejected: DANE clients are meant
-- to set the hostname via conn:setdane(host) instead (see SSL_set1_host(3)).
do
   local cfg = {}
   for k, v in pairs(base) do cfg[k] = v end
   cfg.host = "foo.bar.example"
   cfg.dane = true

   local ok, err = ssl.wrap(socket.tcp(), cfg)
   local pass = (ok == nil and err ~= nil)
   if not pass then failures = failures + 1 end
   print(string.format("host+dane conflict         = %-5s err=%-30s (expected nil  ) %s",
      tostring(ok), tostring(err), pass and "OK" or "FAIL"))
end

os.exit(failures == 0 and 0 or 1)
