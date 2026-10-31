# Provisional jury assessment

Assessment date: 1 November 2026. This is a reasoned review of current evidence, not an official competition score. Do not treat unverified metrics as failures or as passes.

**Overall demonstrated readiness: 5/10.** I would keep this project in consideration for a technical demonstration, but would not select it as a winner on the evidence currently available.

| Area | Provisional assessment | Reason |
|---|---|---|
| Problem fit | 7/10 | Addresses the required log-to-detection-to-incident-to-investigation workflow. |
| Evidence and uncertainty handling | 7/10 | Source locators, distinct AI hypotheses, unknown permissions and observed/inferred/predicted links are useful investigation features. |
| Detection and labelling evidence | 3/10 | No supplied ground-truth precision/recall results. In the reviewed firex-part1 output, 311,835 of 360,377 rule findings have no technique mapping. Those are alerts, not established attacks. |
| Attack reconstruction / FR4 | 4/10 | Global correlation exists, but the requested planted attack-path reconstruction accuracy has not been demonstrated. Large counts of single candidates do not prove reconstruction. |
| Performance | 4/10 | Bounded-memory samples are encouraging; full supplied-file timing is being measured. A sample cannot establish the Core tier. |
| Investigation UI | 6/10 | Graph, timeline, evidence and reports work on fixtures and partial exports. Large-result import responsiveness and real-data end-to-end use still need acceptance. |
| Delivery readiness | 4/10 | Latest GitHub adds raw-log execution, but retains restrictive output limits and inconsistent startup documentation. Local improvements are not yet reconciled into a release. |

The numerical rows are my qualitative judgments; they are not a mathematical scoring formula or a replacement for the PRD's gates.

## What would change the decision

1. Complete the supplied 6.543 GB source within two hours, ideally one, with under 8 GB combined application-process memory; disclose AI scope and rejected bytes.
2. Repeat on a valid full 15 GB Core dataset before claiming Core qualification.
3. Evaluate supplied planted-attack ground truth: detection over 70%, correct technique labels over 60%, at least half the planted paths reconstructed, false incidents under 30%. Stretch targets are over 90%, over 85%, all paths and under 10%, respectively.
4. Demonstrate one real reconstructed incident with evidence-backed host/account links, a readable timeline, explained risk, distinct raw-record count and cited report. FR6 must use actual access context or explicitly remain unknown.
5. Start from a clean checkout with one correct documented command, run the selected file through the UI, and open an incident within two seconds (stretch: 500 ms).

Passing these gates could justify a much stronger rating, but no future score or selection outcome is guaranteed. Automation should follow correctness and measured performance rather than substitute for them.
