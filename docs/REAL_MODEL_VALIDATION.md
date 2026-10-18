# Real model and OS validation checklist

- [ ] Download model from a trusted source and record immutable revision and license.
- [ ] Record model and tokenizer configuration hashes and each weight-file SHA-256.
- [ ] Run smoke test without sandbox; preserve raw JSON and logs.
- [ ] Run under a separately reviewed namespace launcher with no network route.
- [ ] Compare `/proc/<pid>/ns/*` against a host-side observer.
- [ ] Verify filesystem denial using a temporary canary outside allowed paths.
- [ ] Verify outbound TCP/UDP attempts fail and capture exact errno.
- [ ] Verify seccomp/Landlock status through independent observation, not config intent.
- [ ] Run negative controls and reset environment between independent trials.
- [ ] Reproduce on a second host/kernel before generalizing results.

Do not describe a smoke test as a weight-confidentiality result. Do not test against a hosted provider's private weights; the project cannot inspect them.
