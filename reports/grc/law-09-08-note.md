# Note: Moroccan law 09-08 and this lab

> Not legal advice. The note shows how a Moroccan company running this setup would have to think about its personal-data obligations. Check every point against the current text of the law and CNDP guidance before relying on it.

## 1. Context
- **Law n° 09-08** (2009) governs the processing of personal data of individuals in Morocco. It is enforced by the **CNDP** (Commission Nationale de contrôle de la protection des Données à caractère Personnel).
- The lab simulates a Moroccan company that keeps a **customer file** (names, contact details) in an S3 bucket hosted in **eu-north-1 (Stockholm, Sweden)**.
- **No real personal data was used:** every record was generated with Faker (`scripts/gen_fake_data.py`). The analysis below is "what if this were real".

## 2. Obligations that apply to the scenario
| Topic | What it means for this company | How the lab addresses it |
|---|---|---|
| **Prior declaration / authorization** | Processing customer data generally has to be declared to the CNDP (and some processing needs prior authorization) before it starts | Out of scope (fictional company); would be the first GRC step |
| **Security of processing** | The controller must apply appropriate technical and organizational measures against accidental or unlawful destruction, loss, alteration, disclosure or access | Encryption (SSE-S3 and SSE-KMS), least privilege, Block Public Access, logging, monitoring, automated containment, runbooks. See the control mapping |
| **Processor (subcontractor)** | The cloud provider processes data on the company's behalf; security obligations must be covered by contract | AWS shared-responsibility model (ISO 27017 CLD.6.3.1); the company remains responsible for its configuration, which is exactly what S1 and S3 test |
| **Transfer outside Morocco** | Storing the data in Sweden is a transfer abroad. Transfers are allowed to countries that ensure an adequate level of protection; otherwise a CNDP authorization or another legal basis is needed | EU member states are generally treated as adequate by the CNDP (verify the current list). The region was imposed by the account type and is documented as a design constraint |
| **Data subjects' rights** | Information, access, rectification, objection | Out of scope |

## 3. Applied to the incidents
| Incident | Personal data disclosed? | Real-world consequence |
|---|---|---|
| S1 public bucket | Yes: 26 anonymous downloads of the SSE-S3 customer file over ~14 min (the KMS copy was not readable) | Security obligation breached. Assess the breach, document it, inform the CNDP and the affected customers where required or appropriate, and fix the root cause (account-level BPA) |
| S2 leaked key | Yes: 1 download by an identified attacker | Same, plus a criminal complaint is possible (unauthorized access to an information system is a criminal offence under the Moroccan Penal Code) |
| S3 SSH | No | Event logged; no notification needed |
| M-IMDS | No | — |

**Breach notification.** Law 09-08 has no GDPR-style 72-hour breach notification rule; the duty comes from the general security obligation and from CNDP guidance. Law **05-20** on cybersecurity (and its implementing decree) adds **incident reporting to the DGSSI** for State bodies and critical-infrastructure operators. A company in those categories would have to report S1 and S2. Verify both points against the current texts.

**GDPR.** Storing data in the EU does not by itself make the GDPR apply to a Moroccan company. It applies if the company offers goods or services to people in the EU or monitors their behaviour. Keep it in mind if the customers include EU residents.

## 4. What the lab demonstrates for compliance
- **Measures exist and work:** encryption, least privilege and automated containment limited the damage (KMS copy never disclosed; exposure stopped in 5–10 s when the automation was armed).
- **Accountability:** every incident has a timeline, evidence with integrity proof (SHA-256 + CloudTrail digest validation) and lessons learned. That's what a regulator or auditor asks for after a breach.
- **Residual risk is documented:** see `reports/risk-register.xlsx` (R01, R02, R16).
