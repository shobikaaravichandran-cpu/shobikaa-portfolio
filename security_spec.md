# EvidenceOS Firestore Security Specification

## 1. Data Invariants
1. **Strict Ownership Isolation (PII & Financial Records):** Every document across `/users`, `/documents`, `/manualCorrections`, `/findingReviews`, `/simulations`, `/investigations`, and `/auditEvents` is strictly owned by `ownerId == request.auth.uid` (or `userId == request.auth.uid` for `/users`). Cross-user read, list, update, or delete is categorically denied.
2. **Verified Identity Gate:** All writes require `request.auth != null && request.auth.token.email_verified == true`.
3. **No Self-Assigned Privileges:** `/users/{userId}` only permits `role == 'analyst'` on create and forbids mutating `role`, `uid`, `email`, or `createdAt` on update.
4. **Simulation Isolation:** Every document in `/simulations/{simulationId}` MUST satisfy `simulated == true`, preventing hypothetical shock scenarios from being misclassified as live financial evidence.
5. **Audit & Correction Immutability:** `/manualCorrections/{correctionId}` and `/auditEvents/{eventId}` are append-only (`allow update, delete: if false;`), preserving provenance and original OCR extractions.
6. **Temporal Integrity:** `createdAt == request.time` on create and `updatedAt == request.time` on update.
7. **Terminal Finding Lock:** Once a `/findingReviews/{reviewId}` reaches `status == 'Resolved'`, further client mutations are blocked.
8. **Path ID & Size Bounds:** Every single-doc path variable satisfies `isValidId(id)` (`<= 128` chars, `^[a-zA-Z0-9_\-]+$`) and every string/array field enforces strict length limits.
9. **Privacy & Authorized Business Evidence Enforcement:** `/documents/{documentId}` categorically rejects `category == 'communication'` (WhatsApp decommissioned), enforces `authorizedBySubmitter == true`, requires a bounded `processingPurpose` (5–240 chars), bounds `retentionPolicyDays` (30–2555), and isolates `/privacyPolicies/{policyId}` strictly to `ownerId == request.auth.uid`.

## 2. The "Dirty Dozen" Adversarial Payloads
1. **Shadow Field Injection on Document Create:** Adding undocumented key `isVerifiedByBank: true` to `/documents/doc1` -> MUST FAIL (`hasOnly`).
2. **Identity Spoofing on Document Create:** Authenticated as `userA` writing `ownerId: "userB"` -> MUST FAIL (`ownerId == request.auth.uid`).
3. **Self-Assigned Admin Role:** Creating `/users/userA` with `role: "admin"` -> MUST FAIL (`role == 'analyst'`).
4. **Unverified Email Write:** Writing any record with `email_verified: false` -> MUST FAIL (`isVerifiedUser()`).
5. **Cross-User PII Read:** `userB` requesting `get /users/userA` -> MUST FAIL (`isOwner(userId)`).
6. **Blanket List Scraping:** `userB` querying `/documents` without matching `ownerId == userB` -> MUST FAIL (`resource.data.ownerId == request.auth.uid`).
7. **Simulation Contamination:** Writing `/simulations/sim1` with `simulated: false` -> MUST FAIL (`data.simulated == true`).
8. **Audit Trail Tampering:** Attempting `update` or `delete` on `/auditEvents/evt1` -> MUST FAIL (`if false`).
9. **Manual Correction Erasure:** Attempting `update` on `/manualCorrections/cor1` -> MUST FAIL (`if false`).
10. **Terminal Finding Unlock:** Updating `/findingReviews/rev1` when existing `status == 'Resolved'` -> MUST FAIL (`existing().status != 'Resolved'`).
11. **Client Timestamp Forgery:** Submitting a backdated `createdAt` timestamp instead of `request.time` -> MUST FAIL (`incoming().createdAt == request.time`).
12. **ID Poisoning & Array Overflow:** Creating `/investigations/a...200chars` or passing 50 items in `citedDocumentIds` -> MUST FAIL (`isValidId` and `size() <= 20`).
