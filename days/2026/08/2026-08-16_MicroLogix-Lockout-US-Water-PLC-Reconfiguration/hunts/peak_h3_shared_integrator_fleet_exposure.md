# PEAK hunt H3 - Shared integrator design as a fleet-wide exposure

## Prepare

**Hypothesis.** If our controllers were installed by a system integrator who reuses one network design across customers, then our
exposure is a property of that design, not of our site - and the same design is reachable at every other customer who bought it.
The FBI observed exactly this: similar third-party network configurations across several victims, which let one working access
method be reproduced against multiple utilities. Forescout found the physical signature of it in Eagan, MN: fifteen controllers
with adjacent addresses, similar serial numbers, largely uniform firmware and one identical GPS coordinate pair.

**Scope.** Contracts, as-built documentation and live configuration for every integrator, telecom provider and equipment vendor with
a path into the plant. Include cellular gateways, SIM and APN provisioning, VPN concentrators, remote-maintenance accounts, and any
shared credential the utility does not itself control.

## Execute

1. **Map the fleet from outside.** Enumerate the utility's own public ranges and carrier-assigned addresses for open 44818, 502,
   102, 2222, 9191 and 22, then compare that list with the internal asset register. Every device the outside view knows and the
   register does not is an asset-visibility failure.
2. **Fingerprint the design.** For each reachable device record product family and firmware revision, addressing scheme,
   management-plane exposure, carrier and APN. Cluster the results.

```bash
# Cluster controller banners captured from an authorised, read-only external assessment
awk -F, '{print $2","$3","$4}' ot_external_inventory.csv \
  | sort | uniq -c | sort -rn | head -40   # product, firmware, carrier - tight clusters mean one integrator template
```

3. **Certificate and DNS archaeology.** Query certificate transparency for utility- and water-named remote-access hostnames.
   Forescout found valid certificates serving a default IIS page since 2019, expired certificates, unrenewed hostnames and wildcard
   coverage hiding live services - all reliable markers of an unowned remote-access path.
4. **Ask the integrator three questions in writing.** Which public addresses and accounts do you hold for us; is any credential or
   configuration shared with another customer; which of your other customers uses this same template.

## Act

- **Signal.** A tight firmware and addressing cluster across sites, a shared account, or a single APN serving multiple utilities.
- **Noise.** Standardisation is a legitimate engineering practice; the risk is not uniformity but uniform exposure with shared
  credentials and no per-customer boundary.
- **Escalate when.** The integrator confirms shared credentials or a shared management plane. That escalation goes to the sector
  ISAC and the state primacy agency, because peers who bought the same design are exposed and do not know it.
- **Product.** An exposure map per site, a contractual requirement that vendors document every remote path and prohibit shared
  credentials, and a retirement plan with dates for end-of-life controllers such as the MicroLogix 1100 discontinued in April 2022.
