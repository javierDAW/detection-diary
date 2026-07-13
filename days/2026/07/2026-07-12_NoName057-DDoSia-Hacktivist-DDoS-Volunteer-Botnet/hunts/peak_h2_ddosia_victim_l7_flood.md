# PEAK Hunt H2 — Victim-side Layer-7 flood characterization

**Hypothesis.** A public web property of ours (or one we defend) appears on a NoName057(16) target list and is receiving a DDoSia HTTP flood: a sharp requests-per-minute spike to a specific URI from a wide, distributed set of source IPs, with cache-busting randomized query/body values designed to defeat caching.

**Prepare.** Data sources: edge/CDN logs, WAF logs, IIS `W3CIISLog` or `CommonSecurityLog`. Fields: timestamp, client IP, URI stem, query string, method, User-Agent, response code, bytes. Establish the normal peak requests-per-minute per URI so a spike is meaningful.

**Execute.**
1. Bin requests per URI per minute; flag URIs whose rate exceeds the normal peak by a large factor with a high distinct-source-IP count.
2. Inspect the query/body: DDoSia inserts random strings (from its `randoms` config) into fields such as `login=$_1%40gmail.com&password=$-1`, so look for high-entropy, single-use values on a login or search endpoint.
3. Profile User-Agents and methods; a mix that includes `Go-http-client/1.1` alongside configured browser-like agents, and an unusual POST ratio, is consistent with the toolkit.
4. Cross-reference the targeted host/URL against the group's Telegram-published target list for the day.

**Act.** Engage DDoS mitigation (rate-limit, challenge, geo/ASN shaping, upstream scrubbing). Capture the source-IP set and User-Agent/URI signature for sharing. Remember availability impact does not imply compromise — verify no second-stage activity rode the noise.

**Notes.** DDoSia is volumetric and cache-buster-driven; the durable victim-side tells are the rate spike + distinct-source fan-in + single-use randomized parameters, not any one User-Agent.
