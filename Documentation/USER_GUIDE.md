# User guide (GUI)

1. **1. Data** - click *Generate synthetic dataset* (6000 findings, seed 42) or *Load from database*. *Import NVD + KEV + EPSS files...* loads real files (formats in `DATASET_DATASHEET.md`).
2. **3. Evaluation** - click *Run full experiment*. Training runs on background threads (a few seconds). The table shows ROC-AUC, PR-AUC, Brier, ECE, P@K, NDCG@K; the text area below holds shift, ablation, importance, stability and bootstrap results.
3. **4. Charts** - ROC, Precision-Recall, calibration diagram, global SHAP importance.
4. **2. Prioritisation & Explanations** - choose a model and split; the table is ranked by risk. Select a row: the bar chart shows why (log-odds contributions), the text box gives the plain-language summary.
   Rate how useful the explanation was (1-5), add a comment, *Save / update rating* or *Delete rating* (stored through JDBC/CSV).
5. **5. Analyst Feedback** - all stored ratings and the mean usefulness.

Headless mode: `headless.sh` / `headless.bat` writes `results/experiment_results.md`, `metrics.csv`, `top20_priorities_test_set.csv`, `example_explanations.txt` and chart PNGs.
