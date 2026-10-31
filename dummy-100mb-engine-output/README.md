# Synthetic investigation fixture

This entire folder is dummy data. No 100 MB file was processed and no provider was called.

The fixture contains 71 invented source records, 62 rule findings, 2 simulated AI hypotheses and 61 candidate incidents. The authentication candidate combines 11 distinct raw records into 2 rule findings; the other 60 candidates are isolated signature alerts. All source byte locators/checksums reference the included small sample-source.log. Source patterns resemble the supplied firewall logs; documentation-only IPs, accounts, hosts and permissions are invented.

investigation-context.json adds clearly synthetic inventory/ACL/permission facts for the website's conditional FR6 demo. These facts were not extracted from the real firewall log. One target has both network policy and account permission evidence, another lacks permission evidence, and an expired permission is excluded. All candidates depend on the unproven condition that the account is attacker-controlled.

The website reads the standard JSON/JSONL exports and creates graph responses dynamically. summary.json separates actual fixture counts from rough 100 MB projections. ai_reviews.jsonl contains simulated reviews, not provider results. No analysis.sqlite database is included. This fixture cannot establish detection accuracy or real attack reachability.
