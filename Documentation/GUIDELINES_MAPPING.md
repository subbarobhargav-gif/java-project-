# Mapping to Project_Guidelines.pdf (report sections 1-12)

| # | Report section required | Where the evidence is in this project |
|---|---|---|
| 1 | Project title / real-world problem | "Explainable AI for Cyber Threat Prioritisation" - SOC teams cannot patch everything; rank by risk and justify it |
| 2 | Background | `Documentation/README.md`, Research Project 12 abstract (CVSS-only ranking is a weak proxy for exploitation) |
| 3 | Problem statement | Predict exploitation within 90 days and rank findings by risk = probability x impact, with explanations |
| 4 | Objectives | (a) reproducible dataset, (b) 4 methods compared, (c) ranking/calibration/stability evaluation, (d) GUI with explanations + analyst feedback |
| 5 | System design + UML | `Documentation/DESIGN_AND_UML.md` (architecture, class diagram, patterns) |
| 6 | OOP concepts | table below |
| 7 | Advanced Java concepts | table below |
| 8 | GUI | `gui/MainPanel.java`, `MainWindow.java`, charts; reference renders in `Report/screenshots_reference` (take real screenshots too) |
| 9 | JDBC | `db/JdbcThreatRepository.java` (insert, retrieve, update, delete with PreparedStatement + transaction) |
| 10 | Source code + screenshots | `Implementation/src`; screenshots from the running app |
| 11 | Testing and results | `SelfTest.java` (25 checks), `Implementation/results/experiment_results.md` |
| 12 | Conclusion / future work | `Report/REPORT_MATERIAL.md` |

## OOP concepts (section 6)
| Concept | Example |
|---|---|
| Classes / objects | `Finding`, `Vulnerability`, `Asset`, `ExperimentRunner` |
| Encapsulation | private final fields + getters + validation in constructors (`Vulnerability`, `Asset`) |
| Inheritance | `Identifiable` -> `Vulnerability`, `Asset`; `TrainableScorer` -> `LogisticRegressionScorer`, `GradientBoostingScorer` |
| Polymorphism | `List<Scorer>` evaluated uniformly; `CvssScorer` overrides `priority()`; `ThreatRepository` implemented twice |
| Abstraction | abstract `Identifiable.describe()`, abstract `TrainableScorer.doFit()` |
| Interfaces | `Scorer`, `Explainable`, `ThreatRepository` (with default methods) |

## Advanced Java concepts (section 7)
| Concept | Example |
|---|---|
| Exception handling | custom checked `ThreatPrioException`; try-with-resources in JDBC; validation via `IllegalArgumentException`; SwingWorker error dialogs |
| Multithreading | `ExecutorService` trains LR, GBDT and 6 ablation models in parallel (`ExperimentRunner`); `SwingWorker` keeps the GUI responsive; `synchronized` file repository |
| Collections | `LinkedHashMap`, `TreeMap`, `HashSet`, `ArrayList`, `EnumMap`-style enums, `Optional` |
| Generics | `Map<String, List<Metrics.CalibrationBin>>`, `Optional<AnalystFeedback>`, generic `find(Container, Class<T>)` in `GuiScreenshots` |
| Streams / lambdas | `groupingBy`, `mapToDouble`, `sorted`, `filter`, `collect` in `ExperimentRunner`, `AppController.rank`, `DatasetSplit` |
| Records / enums / switch expressions | `Explanation`, `ScoredFinding`, `ModelMetrics`; `AttackVector`; table model `getValueAt` |
