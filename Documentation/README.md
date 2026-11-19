# Explainable AI for Cyber Threat Prioritisation (Research Project 12, CTI)

A pure-Java application that ranks vulnerabilities on organisational assets by **risk = P(exploitation) x asset impact**,
compares four prioritisation methods, and explains every prediction with feature-level attributions.

| Method | Class | Notes |
|---|---|---|
| CVSS-based prioritisation | `CvssScorer` | asset-blind baseline |
| Rule-based weighted risk score | `RuleBasedScorer` | analyst-set weights |
| Logistic Regression | `LogisticRegressionScorer` | L2, standardised, exact linear attributions |
| XGBoost-style GBDT + SHAP | `GradientBoostingScorer`, `RegressionTree` | second-order boosting, early stopping, **exact TreeSHAP** |

> Why not the real XGBoost/SHAP libraries? The assignment is a Java project; the XGBoost-style booster and TreeSHAP were
> implemented from scratch (and verified: base value + sum of SHAP values equals the model margin to ~1e-15).

## Requirements
* JDK 17 or newer (tested with 21). No Maven/Gradle needed.
* Optional: `lib/sqlite-jdbc-3.41.2.2.jar` for JDBC mode (see `Implementation/lib/README.txt`).

## Build / run (from the `Implementation` folder)
| Action | Linux / macOS | Windows |
|---|---|---|
| Compile | `./scripts/build.sh` | `scripts\build.bat` |
| Run GUI | `./scripts/run.sh` | `scripts\run.bat` |
| Self-tests (25 checks) | `./scripts/test.sh` | `scripts\test.bat` |
| Whole study without GUI | `./scripts/headless.sh` | `scripts\headless.bat` |

Manual: `javac -d out $(find src -name "*.java")` then `java -cp "out:lib/*" com.threatprio.Main` (use `;` instead of `:` on Windows).

## Folder map
```
Implementation/src/com/threatprio/
  model/    Identifiable, Vulnerability, Asset, Finding, enums          (domain)
  scoring/  Scorer, Explainable, Explanation, 4 methods, ImpactModel    (models + XAI)
  data/     SyntheticDataGenerator, CsvDatasetLoader, DatasetSplit      (data + leakage-safe split)
  eval/     Metrics, ExperimentRunner, StabilityEvaluator, results      (evaluation)
  db/       ThreatRepository, JdbcThreatRepository, FileThreatRepository, RepositoryFactory
  gui/      MainWindow, MainPanel, charts, AppController, exporter      (Swing)
  SelfTest, Main
```

## VS Code
Install the "Extension Pack for Java", then **open the `Implementation` folder** (File > Open Folder). The included `.vscode/` files
provide four run configurations (GUI, headless study, self-tests, GUI screenshots) with the correct working directory.
Put `sqlite-jdbc-3.41.2.2.jar` in `lib/` for JDBC mode (picked up automatically).
