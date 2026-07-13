# PEAK Hunt H1 — Internal host participating in DDoSia (C2 handshake)

**Hypothesis.** A corporate endpoint has been enrolled (by an insider or via commodity malware) into the NoName057(16) DDoSia volunteer botnet and is beaconing to a DDoSia C2: authenticating with `POST /client/login` and polling `GET /client/get_targets`, using the Go client's default `Go-http-client/1.1` User-Agent and the custom `Client-Hash` / `User-Hash` request headers.

**Prepare.** Data sources: proxy / TLS-terminating egress logs, Suricata/Zeek HTTP, and Defender XDR `DeviceNetworkEvents` (RemoteUrl) + `DeviceFileEvents`. Fields: URI path, HTTP method, User-Agent, request headers, remote IP/port, initiating process. Note that DDoSia C2 has historically been plain HTTP on TCP/80 to a raw IPv4 with no prior DNS resolution.

**Execute.**
1. Search egress HTTP for URIs ending `/client/login` (POST) or `/client/get_targets` (GET). These two paths are the durable protocol anchor.
2. Filter for the `Go-http-client/1.1` User-Agent and/or the presence of a `Client-Hash` or `User-Hash` (`$2a$16$...`) request header.
3. For each hit, pivot on the source host: does it also show `client_id.txt` / `d.zip` / a `d_*.exe` on disk (`DeviceFileEvents`)? Is the remote IP a raw address reached with no DNS lookup?
4. Record `{host, user, process, remote_ip:port, uri, user_agent, first_seen, last_seen}`.

**Act.** Confirmed participation → isolate the host, preserve the client binary + `uid` folder + `client_id.txt` for the volunteer identity, and treat as insider-risk or malware per your policy. Feed the fresh C2 IP to blocking and to the CTI team (H3).

**Notes.** C2 IPs rotate ~every 9 days, so do not rely on an address list — the URI + header + Go agent combination is what persists across builds.
