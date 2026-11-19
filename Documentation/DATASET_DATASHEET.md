# Dataset datasheet

## What is in `Dataset/`
| File | Content |
|---|---|
| `synthetic_findings_seed42_n6000.csv` | The exact synthetic dataset used for all reported results (generator seed 42, 6000 findings). Re-created by `Main --headless`. |
| `sample_real_format/*.csv` | Three **tiny hand-written** files showing the column layout the loader expects for NVD-derived, CISA KEV and FIRST EPSS data. They contain made-up CVE ids and are only for testing the loader. |

## Synthetic generator (`SyntheticDataGenerator`)
Each row = one vulnerability on one asset at snapshot date **2025-09-30**. CVE ids and every value are synthetic.
A hidden "true exploitability" factor drives CVSS, public exploit code, KEV listing, EPSS and the future label; the label also
depends on exposure, attack vector, patch availability, noise and a mild upward drift over publication years (injected temporal /
class-distribution shift). **Asset criticality is independent of exploitation** - it only drives impact.
Exploited rate: about 4.7% (train), 6.9% (validation), 7.5% (test).

Columns: `cve_id, published, snapshot, cvss, attack_vector, epss, in_kev, exploit_code, patch, confidence, asset_id, asset_name,
asset_type, criticality, internet_facing, exploited`.

## Using REAL data (NVD / KEV / EPSS)
Sources (all open; **verify current access terms/licences before use**): NIST NVD, CISA KEV catalogue, FIRST EPSS.
`CsvDatasetLoader` expects:
* NVD-derived CSV: `cve_id,published,cvss_base,attack_vector[,exploit_code_public,patch_available]` (export from the NVD API/JSON yourself).
* KEV CSV: the official `known_exploited_vulnerabilities.csv` (uses `cveID`, `dateAdded`).
* EPSS CSV: `epss_scores-YYYY-MM-DD.csv` (`cve,epss,percentile`, comment line allowed). **Use the file archived for the snapshot date**, otherwise EPSS leaks future knowledge.

Labelling without leakage: KEV listing **on/before** the snapshot is a *feature*; being added to KEV within 90 days **after** the snapshot is the *label*.
Intel confidence is a documented proxy (0.5 + 0.25 if in KEV + 0.25 if EPSS present). Asset context is still synthetic (seeded).
GUI: *Data* tab -> "Import NVD + KEV + EPSS files...". The loader was tested only on the tiny sample files, **not on full downloads** (no internet in the build environment).

## Known limitations
* Results on synthetic data show the method works; they say little about real organisations.
* In the synthetic data `vuln_age_years` partly acts as a proxy for the injected drift.
* The synthetic label is close to logistic in the features, which favours Logistic Regression relative to tree models.
