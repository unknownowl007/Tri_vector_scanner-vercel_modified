from url_analysis import check_lookalike_domain

# Domains that MUST be flagged (True) or MUST NOT be flagged (False)
tests = {
    # Digit swaps
    "faceb00k.com": True,
    "https://www.faceb00k.com": True,
    "g00gle.com": True,
    "paypa1.com": True,
    "netf1ix.com": True,
    "micr0soft-login.net": True,
    "dr0pbox.com": True,
    "1inkedin.com": True,
    "coinbas3.com": True,
    "paypa1-login.com": True,
    # Letter combinations
    "arnazon.com": True,         # rn -> m
    "vvalmart.com": True,        # vv -> w
    # Brand hidden inside another domain
    "facebook.com.evil.com": True,
    "evilfacebook.com": True,
    # Unicode lookalikes
    "g\u043e\u043egle.com": True,     # Cyrillic o
    "payp\u0430l.com": True,          # Cyrillic a
    "\u0430pple.com": True,           # Cyrillic a
    "amaz\u03bfn.com": True,          # Greek omicron
    "micr\u043esoft.com": True,       # Cyrillic o
    "\u0261oogle.com": True,          # Latin script g
    # Real brand domains (must NOT be flagged)
    "facebook.com": False,
    "www.facebook.com": False,
    "m.facebook.com": False,
    "amazon.de": False,
    "google.co.uk": False,
    "gmail.com": False,
    "github.io": False,
    "bankofamerica.com": False,
    # Normal unrelated domains (must NOT be flagged)
    "example.com": False,
    "wikipedia.org": False,
    "b\u00fccher.de": False,
}

passed = failed = 0
print("=== Required tests ===")
for domain, expected in tests.items():
    try:
        got = check_lookalike_domain(domain)["suspicious"]
    except Exception as error:
        print("ERROR", repr(domain), "->", error)
        failed += 1
        continue
    ok = got == expected
    passed += ok
    failed += not ok
    print("OK  " if ok else "FAIL", domain.encode("unicode_escape").decode(), "->", got)

print(f"\n{passed} passed, {failed} failed")

#