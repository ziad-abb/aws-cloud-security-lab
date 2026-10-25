# Management summary: cloud security exercise, October 2026

> 🇫🇷 [Version française](management-summary.fr.md) · One page for non-technical readers.

**What was done.** A small company environment was built on AWS (a web server, a customer-data storage bucket, logging) and attacked on purpose with three realistic cloud incidents. For each one we measured how fast it was **detected** and how fast it was **stopped**, then wrote incident reports, a risk register and a compliance mapping. All customer data was fictional.

## Results
| Incident | What happened | Detected in | Stopped in | Outcome |
|---|---|---|---|---|
| Storage made public by mistake | Anyone on the internet could download the customer file | 1–3.5 min | **10 s** automated · 8 min by hand | Fictional customer file read 26 times in ~14 min of exposure; the encrypted copy stayed safe |
| Developer key leaked in code | An attacker found the key, downloaded a file and created a backdoor key | 3.7 min | **6.4 min** (2.7 min after the alert) | 1 file read; backdoor removed; no other system affected |
| Server login port opened to the internet | Password-guessing attack | seconds | **5 s** automated · 8 min by hand | No access: the server does not accept passwords |
| Unsafe server setting re-enabled | No attack | 1.4 min | **6 s** automated | Fixed before it could be used |

## What it means
1. **Automation pays off.** Automatic fixes stopped problems in 5–10 seconds, 50–90 times faster than a person, and usually before the alert even arrived.
2. **Monitoring catches what automation misses.** Once, the automatic fix was not active yet. The monitoring system still raised the alarm within a minute.
3. **Layers worked.** Encryption and minimal permissions kept the most sensitive copy of the data safe even when other controls failed.
4. **Detection alone is too slow to stop data theft.** Data was taken within seconds; alerts take minutes. Prevention matters most.

## Top risks and recommendations
| Priority | Risk | Recommendation |
|---|---|---|
| 1 | Customer data made public by a configuration mistake | Block public storage at account level (one setting, no cost) |
| 2 | Developer keys leaking from code | Replace permanent keys with short-lived logins for build systems; scan code for secrets before publishing |
| 3 | Automatic fixes silently not working | Keep them always on and test them after every change |
| 4 | Limited monitoring on this account type | Add the provider's managed threat detection when the account plan allows it |

**Risk position:** 17 risks recorded; **7 rated high before the controls, 0 high after them** (average score 12.3 → 5.8 on 25). Residual risks are owned and tracked in `reports/risk-register.xlsx`.

**Compliance:** controls are mapped to CIS AWS 7.0, ISO/IEC 27001:2022, ISO/IEC 27017 and NIST CSF 2.0. A note covers Moroccan law 09-08 (personal data). Configuration score (CIS AWS 7.0): **53 % at the start → 57 % during the tests → 68 % after hardening** (failures 39 → 31).
