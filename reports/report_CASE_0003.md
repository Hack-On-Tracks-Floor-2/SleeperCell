# InsiderLens Incident Report

**Case ID:** CASE-0003
**Generated:** 2026-10-15 17:59:20
**Classification:** CONFIDENTIAL

---

## 1. Executive Summary

This report documents a **MEDIUM** severity insider threat case for user **USER-009**
(pseudonymized identifier). The detection system generated **24** alerts across
**1** kill-chain stage(s): Exfiltration.

The current risk score is **53.8/100**.

> **Important:** This assessment is based on behavioral analysis of encrypted traffic metadata.
> No content was decrypted or inspected. Findings indicate suspicious *behavior patterns*
> and require human investigation to confirm intent.

---

## 2. User Profile

| Field | Value |
|-------|-------|
| Pseudonymous ID | USER-009 |
| Risk Score | 53.8 / 100 |
| Severity | MEDIUM |
| Case Status | open |
| First Alert | 2026-10-03 |
| Latest Alert | 2026-10-14 23:54:18 |

---

## 3. Timeline of Events

| Timestamp | Detector | Score | Evidence | Kill-Chain Stage |
|-----------|----------|-------|----------|-----------------|
| 2026-10-03 | volume_anomaly | 0.70 | extreme_volume_deviation, unusual_after_hours | Exfiltration |
| 2026-10-12 | low_and_slow | 0.50 | cusum_shift_detected | Exfiltration |
| 2026-10-12 | volume_anomaly | 0.70 | extreme_volume_deviation, unusual_after_hours | Exfiltration |
| 2026-10-12 00:49:49 | flow_classifier | 1.00 | after_hours, large_upload | Exfiltration |
| 2026-10-12 01:24:08 | flow_classifier | 0.99 | after_hours, large_upload | Exfiltration |
| 2026-10-12 02:24:44 | flow_classifier | 0.98 | after_hours, new_destination | Exfiltration |
| 2026-10-12 22:29:05 | flow_classifier | 0.99 | after_hours, new_destination, large_upload | Exfiltration |
| 2026-10-12 22:42:05 | flow_classifier | 0.99 | high_upload_ratio, after_hours, new_destination, large_upload | Exfiltration |
| 2026-10-12 23:50:15 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 | low_and_slow | 0.50 | cusum_shift_detected | Exfiltration |
| 2026-10-13 00:59:50 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 01:56:21 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 22:03:00 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 22:12:45 | flow_classifier | 1.00 | high_upload_ratio, after_hours | Exfiltration |
| 2026-10-13 22:26:27 | flow_classifier | 0.99 | high_upload_ratio, after_hours | Exfiltration |
| 2026-10-13 23:32:35 | flow_classifier | 1.00 | after_hours, large_upload | Exfiltration |
| 2026-10-14 | user_anomaly | 0.44 | high_volume_day, high_after_hours | Exfiltration |
| 2026-10-14 | low_and_slow | 0.50 | cusum_shift_detected | Exfiltration |
| 2026-10-14 00:46:47 | flow_classifier | 1.00 | high_upload_ratio, after_hours, new_destination, large_upload | Exfiltration |
| 2026-10-14 01:05:59 | flow_classifier | 1.00 | high_upload_ratio, after_hours | Exfiltration |
| 2026-10-14 01:13:21 | flow_classifier | 0.99 | high_upload_ratio, after_hours, new_destination, large_upload | Exfiltration |
| 2026-10-14 02:52:56 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 22:01:59 | flow_classifier | 0.90 | after_hours | Exfiltration |
| 2026-10-14 23:54:18 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |


---

## 4. Evidence Summary

- **Total Alerts:** 24
- **Detectors Triggered:** user_anomaly, flow_classifier, volume_anomaly, low_and_slow
- **Evidence Tags:** new_destination, extreme_volume_deviation, high_upload_ratio, high_after_hours, after_hours, unusual_after_hours, cusum_shift_detected, large_upload, high_volume_day

---

## 5. Kill-Chain Assessment

Observed stages: **Exfiltration**

ℹ️ Single kill-chain stage observed. Additional monitoring recommended to determine if further stages emerge.

---

## 6. Risk Assessment

| Factor | Assessment |
|--------|-----------|
| Risk Score | 53.8 / 100 (medium) |
| Alert Volume | 24 alerts |
| Pattern Type | Isolated anomaly |
| Confidence | Medium |

---

## 7. Recommended Actions

1. **Immediate:** Review the user's activity timeline in the InsiderLens dashboard
2. **Investigation:** Continue monitoring
3. **Containment:** No immediate action required
4. **Follow-up:** Schedule review with the user's manager (after identity reveal approval)
5. **Documentation:** Record investigation findings and analyst assessment

---

## 8. Caveats and Limitations

- This analysis is based on **network traffic metadata only**. No content was decrypted or inspected.
- Behavioral anomalies do not necessarily indicate malicious intent. Legitimate reasons
  (projects, deadlines, role changes) may explain the patterns.
- The risk score is probabilistic and should be treated as an indicator, not proof.
- All identifiers are pseudonymized. De-anonymization requires authorized approval.
- This report is auto-generated and should be reviewed by a qualified analyst.

---

*Report generated by InsiderLens Detection Platform*
*Privacy Notice: This report contains no decrypted content or raw payload data.*
