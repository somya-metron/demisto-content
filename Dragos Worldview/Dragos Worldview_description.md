 
 This integration exposes the `!file`, `!ip`, and `!domain` commands.
 Once configured, this integration will search Dragos WorldView API for
 information about the indicator referenced by the command (file hash,
 IP address, domain name). 
 
 DBot score is calculated from the confidence level Dragos has in an
 indicator, and is outlined in the table below. 
 
| Dragos Confidence  | DBot Score Name |  DBot Score  |
|---|---|---|
| Unknown  | Unknown    | 0 |
| Low      | Suspicious | 2 |
| Moderate | Suspicious | 2 |
| High     | Bad        | 3 |