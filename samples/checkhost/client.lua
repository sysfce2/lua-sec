--
-- Public domain
--
-- Demonstrates (and doubles as a test for) X509 certificate:checkhost(),
-- which wraps OpenSSL's X509_check_host() to verify that a certificate is
-- valid for a given hostname (checking subjectAltName dNSName entries,
-- falling back to the subject CommonName).
--
-- ../certs/serverA.cnf sets: subjectAltName=DNS:foo.bar.example
--
local socket = require("socket")
local ssl    = require("ssl")

local params = {
   mode = "client",
   protocol = "tlsv1_2",
   cafile = "../certs/rootA.pem",
   verify = "peer",
   options = "all",
}

local peer = socket.tcp()
peer:connect("127.0.0.1", 8888)

-- [[ SSL wrapper
peer = assert( ssl.wrap(peer, params) )
assert( peer:dohandshake() )
--]]

local cert = assert(peer:getpeercertificate())

local cases = {
   { host = "foo.bar.example", expect = true  }, -- matches subjectAltName
   { host = "evil.example",    expect = false }, -- no match
}

local failures = 0

for _, case in ipairs(cases) do
   local ok = cert:checkhost(case.host)
   local pass = (ok == case.expect)
   if not pass then failures = failures + 1 end
   print(string.format("checkhost(%-20s) = %-5s (expected %-5s) %s",
      case.host, tostring(ok), tostring(case.expect), pass and "OK" or "FAIL"))
end

-- Named X509_CHECK_FLAG_* options can be passed after the hostname.
do
   local ok = cert:checkhost("foo.bar.example", "no_wildcards", "single_label_subdomains")
   local pass = (ok == true)
   if not pass then failures = failures + 1 end
   print(string.format("checkhost(host, flags...)        = %-5s (expected true ) %s",
      tostring(ok), pass and "OK" or "FAIL"))
end

-- An unknown flag name must be rejected, not silently ignored.
do
   local ok, err = cert:checkhost("foo.bar.example", "bogus_flag")
   local pass = (ok == nil and err ~= nil)
   if not pass then failures = failures + 1 end
   print(string.format("checkhost(host, \"bogus_flag\")     = %-5s err=%-30s %s",
      tostring(ok), tostring(err), pass and "OK" or "FAIL"))
end

-- An embedded NUL makes the name malformed: checkhost() must report an
-- error instead of silently matching or not matching.
do
   local ok, err = cert:checkhost("foo.bar.example\0evil.example")
   local pass = (ok == nil and err ~= nil)
   if not pass then failures = failures + 1 end
   print(string.format("checkhost(embedded NUL)          = %-5s err=%-24s %s",
      tostring(ok), tostring(err), pass and "OK" or "FAIL"))
end

print(peer:receive("*l"))
peer:close()

os.exit(failures == 0 and 0 or 1)
