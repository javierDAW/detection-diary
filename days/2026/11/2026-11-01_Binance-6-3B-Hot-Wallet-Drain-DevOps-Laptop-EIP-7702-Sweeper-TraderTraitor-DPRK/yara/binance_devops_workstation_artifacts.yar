/*
  Title: Developer workstation scripts that combine cloud / Kubernetes credential harvesting with exfiltration, and Solidity source
         text with an EIP-7702-style sweeper pattern (execute or sweep plus transfer of full balances to an immutable owner)
  Author: Jarmi
  Date: 2026-11-01
  Reference: https://www.forbes.com/sites/digital-assets/2026/10/30/binances-63-billion-hack-started-with-one-engineers-laptop/ ;
             https://gizmodo.com/how-hackers-stole-6-3-billion-from-binance-in-minutes-2000833158 ;
             https://hackread.com/binance-devops-engineer-hacked-laptop-billion-theft/
  Scope: no malware name, tool name, file name or hash was published for the Binance hot-wallet drain (2026-10-29/30), and the sweeper
  contract's source or bytecode was not published either. Neither rule was run against a real sample and neither detects that attack.
  Both are generic hunting heuristics (confidence low) for text files: scripts on DevOps / SRE laptops, and Solidity source or ABI text
  in repositories, CI artifacts or download folders.
*/

rule Generic_DevWorkstation_Script_Cloud_Credential_Harvest_And_Exfil
{
    meta:
        author = "Jarmi"
        description = "Script or text file that references at least one cloud or Kubernetes credential store or secret-export command and at least one exfiltration primitive. Hunting heuristic for DevOps laptops; generic, not tied to a published sample"
        date = "2026-11-01"
        reference = "https://www.forbes.com/sites/digital-assets/2026/10/30/binances-63-billion-hack-started-with-one-engineers-laptop/"
        confidence = "low"
        family = "generic-hunting"
    strings:
        // local credential stores
        $c1 = ".aws/credentials" ascii wide
        $c2 = ".kube/config" ascii wide
        $c3 = "gcloud/credentials.db" ascii wide
        $c4 = "AWS_SECRET_ACCESS_KEY" ascii wide
        // secret-export commands
        $e1 = "sts get-session-token" ascii wide
        $e2 = "secretsmanager get-secret-value" ascii wide
        $e3 = "config view --raw" ascii wide
        // exfiltration primitives
        $x1 = "multipart/form-data" ascii wide
        $x2 = "api.telegram.org" ascii wide
        $x3 = "discord.com/api/webhooks" ascii wide
        $x4 = "curl -F" ascii wide
    condition:
        filesize < 512KB and uint32(0) != 0x464c457f and uint16(0) != 0x5a4d
        and ($c1 or $c2 or $c3 or $c4 or $e1 or $e2 or $e3)
        and ($x1 or $x2 or $x3 or $x4)
}

rule Generic_Solidity_Sweeper_Delegate_Source_Pattern
{
    meta:
        author = "Jarmi"
        description = "Solidity source or ABI text with an execute or sweep entry point, ERC-20 balanceOf plus transfer of the full balance, and an immutable owner or onlyOwner guard: the shape of a delegate sweeper that an EIP-7702 authorization could point an EOA at. Hunting heuristic for source and ABI text; legitimate smart-account and batch-executor code shares this shape"
        date = "2026-11-01"
        reference = "https://gizmodo.com/how-hackers-stole-6-3-billion-from-binance-in-minutes-2000833158"
        confidence = "low"
        family = "generic-hunting"
    strings:
        $sol1 = "pragma solidity" ascii
        $abi1 = "\"stateMutability\"" ascii
        $fn1 = "function sweep" ascii nocase
        $fn2 = "function execute" ascii
        $fn3 = "\"name\":\"sweep" ascii nocase
        $bal = "balanceOf(address(this))" ascii
        $tr1 = ".transfer(" ascii
        $tr2 = ".safeTransfer(" ascii
        $own1 = "immutable owner" ascii
        $own2 = "onlyOwner" ascii
        $own3 = "msg.sender == owner" ascii
    condition:
        filesize < 1MB and uint32(0) != 0x464c457f
        and ($sol1 or $abi1)
        and ($fn1 or $fn2 or $fn3)
        and $bal
        and ($tr1 or $tr2)
        and ($own1 or $own2 or $own3)
}
