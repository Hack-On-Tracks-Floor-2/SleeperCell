# InsiderLens Incident Report

**Case ID:** CASE-0002
**Generated:** 2026-10-15 16:44:19
**Classification:** CONFIDENTIAL

---

## 1. Executive Summary

This report documents a **HIGH** severity insider threat case for user **USER-003**
(pseudonymized identifier). The detection system generated **145** alerts across
**1** kill-chain stage(s): Exfiltration.

The current risk score is **65.0/100**.

> **Important:** This assessment is based on behavioral analysis of encrypted traffic metadata.
> No content was decrypted or inspected. Findings indicate suspicious *behavior patterns*
> and require human investigation to confirm intent.

---

## 2. User Profile

| Field | Value |
|-------|-------|
| Pseudonymous ID | USER-003 |
| Risk Score | 65.0 / 100 |
| Severity | HIGH |
| Case Status | open |
| First Alert | 2026-10-03 |
| Latest Alert | 2026-10-14 23:56:18 |

---

## 3. Timeline of Events

| Timestamp | Detector | Score | Evidence | Kill-Chain Stage |
|-----------|----------|-------|----------|-----------------|
| 2026-10-03 | volume_anomaly | 0.50 | extreme_volume_deviation | Exfiltration |
| 2026-10-09 | user_anomaly | 0.49 | high_volume_day, high_after_hours | Exfiltration |
| 2026-10-09 | low_and_slow | 0.70 | cusum_shift_detected, high_7d_cumulative | Exfiltration |
| 2026-10-09 | volume_anomaly | 0.70 | extreme_volume_deviation, unusual_after_hours | Exfiltration |
| 2026-10-09 09:40:27 | flow_classifier | 1.00 | high_upload_ratio, new_destination, large_upload | Exfiltration |
| 2026-10-09 11:29:40 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 11:46:04 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 11:49:18 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 12:11:47 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 13:13:51 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 13:35:14 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 15:12:59 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 15:13:16 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 17:25:22 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 17:49:53 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 18:45:41 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-09 20:18:56 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 20:42:04 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 20:53:53 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 21:34:22 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 21:36:07 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 21:38:51 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 21:41:20 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 21:57:44 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 22:31:43 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 22:39:07 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 23:07:45 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 23:18:48 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 23:21:22 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 23:42:28 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 23:47:36 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-09 23:59:19 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 | low_and_slow | 0.70 | cusum_shift_detected, high_7d_cumulative | Exfiltration |
| 2026-10-10 06:47:23 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 10:15:37 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 11:21:37 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 11:56:59 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 12:36:38 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 12:49:21 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 13:52:58 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 14:59:02 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 15:53:11 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 16:36:05 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 16:55:02 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 17:09:29 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 19:21:46 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-10 20:03:03 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 20:08:20 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 20:23:00 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 20:45:02 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 20:53:29 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 21:15:11 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 21:28:00 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 22:35:32 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 22:52:10 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-10 23:14:44 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-11 | user_anomaly | 0.42 | high_volume_day | Exfiltration |
| 2026-10-11 | low_and_slow | 0.70 | cusum_shift_detected, high_7d_cumulative | Exfiltration |
| 2026-10-11 07:15:17 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 09:59:04 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 10:50:21 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 10:52:45 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 11:26:10 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 11:47:52 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 12:06:08 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 12:20:11 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 12:46:46 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 13:22:09 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 13:28:50 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 13:40:04 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 13:48:46 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 14:12:19 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 16:54:35 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 17:09:57 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 18:10:21 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 18:38:28 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 18:57:07 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-11 20:30:05 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-11 21:13:35 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-11 22:10:47 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-11 22:25:25 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-11 23:18:45 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-11 23:41:52 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 | low_and_slow | 0.70 | cusum_shift_detected, high_7d_cumulative | Exfiltration |
| 2026-10-12 08:19:21 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 09:24:43 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 09:29:12 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 10:14:36 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 12:19:32 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 14:55:58 | flow_classifier | 0.99 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 16:49:07 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 17:39:06 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 17:46:16 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-12 20:02:45 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 20:02:53 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 20:11:37 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 20:26:50 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 21:04:03 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 21:56:40 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 22:32:38 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 22:36:13 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 22:40:16 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 22:53:14 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-12 23:10:18 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 | user_anomaly | 0.47 | high_volume_day, high_after_hours | Exfiltration |
| 2026-10-13 | low_and_slow | 0.70 | cusum_shift_detected, high_7d_cumulative | Exfiltration |
| 2026-10-13 10:24:22 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 10:28:27 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 11:12:48 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 11:27:31 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 12:25:53 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 15:15:03 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 16:02:47 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 16:57:28 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 17:49:52 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 19:27:44 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-13 20:01:52 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 20:11:26 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 21:53:16 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 22:05:16 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-13 23:56:57 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 | user_anomaly | 0.40 | high_volume_day, high_after_hours | Exfiltration |
| 2026-10-14 | low_and_slow | 0.70 | cusum_shift_detected, high_7d_cumulative | Exfiltration |
| 2026-10-14 06:20:14 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 08:46:58 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 09:13:03 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 10:44:16 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 11:39:24 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 11:52:50 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 13:01:40 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 13:46:24 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 14:14:18 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 16:07:56 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 16:14:33 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 16:36:58 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 16:46:37 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 18:00:43 | flow_classifier | 1.00 | high_upload_ratio, large_upload | Exfiltration |
| 2026-10-14 20:36:33 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 20:47:43 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 20:50:56 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 20:51:41 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 21:24:32 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 23:00:28 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 23:49:06 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |
| 2026-10-14 23:56:18 | flow_classifier | 1.00 | high_upload_ratio, after_hours, large_upload | Exfiltration |


---

## 4. Evidence Summary

- **Total Alerts:** 145
- **Detectors Triggered:** user_anomaly, low_and_slow, volume_anomaly, flow_classifier
- **Evidence Tags:** high_7d_cumulative, high_volume_day, new_destination, unusual_after_hours, cusum_shift_detected, high_upload_ratio, large_upload, after_hours, high_after_hours, extreme_volume_deviation

---

## 5. Kill-Chain Assessment

Observed stages: **Exfiltration**

ℹ️ Single kill-chain stage observed. Additional monitoring recommended to determine if further stages emerge.

---

## 6. Risk Assessment

| Factor | Assessment |
|--------|-----------|
| Risk Score | 65.0 / 100 (high) |
| Alert Volume | 145 alerts |
| Pattern Type | Isolated anomaly |
| Confidence | Medium |

---

## 7. Recommended Actions

1. **Immediate:** Review the user's activity timeline in the InsiderLens dashboard
2. **Investigation:** Escalate to security team lead
3. **Containment:** Consider temporary upload restriction pending review
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
