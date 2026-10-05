# Registry signing keys

This file records the public keys AT1C's registry has used to sign agent certificates, and their status.

## Current

`MCowBQYDK2VwAyEArtdv1EI8Lwa/R81S8IaeBUG5HX6xs7RFGu7FakndxC4=`

Ed25519 public key (SPKI, base64). In use from 4 October 2026 by the command-line registration script. The private key is held offline and is not stored on the server or in this repository.

## Retired (4 October 2026)

`MCowBQYDK2VwAyEAu237TnDouxCDfx3Rrqkoc+nY40n+1ca6YZfWE1GDZ/M=`

Do not trust anything signed with this key. Its private half was committed to this repository's history on 25 June 2026 (commit d5664f0), inside an example script. It was also held in the live server's environment settings, and was removed from there on 4 October 2026.

## What happened

Scratch notes, including a printout of the registry key, were pasted into an example script and swept into a bulk commit of 23 files. No check looked for secrets before the commit.

## Impact

We found no sign of third-party agents or user data involved: only test agents existed. The registry kept no log of what the retired key signed, so we cannot rule out its misuse. Certificates issued under it, including those for the three test agents, are untrusted.

## Prevention

- Private keys are never printed to a terminal.
- Commits name specific files instead of adding everything at once.
- A pre-commit check blocks private-key blocks and npm tokens.
