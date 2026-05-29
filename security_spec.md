# Security Specification: Screen Recorder Studio

This specification describes the data invariants and access controls for Screen Recorder Studio.

## Part 1: Data Invariants
1. **User Invariant**: A user's profile can only be read or written by the authenticated owner of that user ID (`request.auth.uid == userId`). No user profiles are readable publicly.
2. **Recording Invariant**: A recording metadata document can only be read, created, updated, or deleted if the user is authenticated and is the rightful creator/owner of that recording (`userId == request.auth.uid`).
3. **Timestamp Invariant**: The `createdAt` field are immutable once created, and must be validated against `request.time` exactly.
4. **ID Invariant**: Document IDs must conform to a strict alphanumeric pattern (`[a-zA-Z0-9_\-]+`) and must be <= 128 characters in size.

---

## Part 2: The "Dirty Dozen" Threat Payloads
Here are 12 specific JSON payloads designed to violate identity, integrity, and state, all of which will be mathematically rejected by our Firestore Security Rules.

### Attack 1: User Identity Hijacking
*   **Target**: `/users/attacker_uid`
*   **Payload**: `{"uid": "victim_uid", "name": "Attacker", "email": "victim@example.com"}`
*   **Action**: Attempt to write a profile claiming to be another user.
*   **Result**: `PERMISSION_DENIED` - Rejected because the document ID doesn't match the authenticated UID.

### Attack 2: Spoofed Creator UID
*   **Target**: `/recordings/rec_123`
*   **Payload**: `{"id": "rec_123", "userId": "victim_uid", "title": "Injected Rec", "createdAt": "TIMESTAMP"}`
*   **Action**: Attempt to create a recording document asserting a different user's UID as owner.
*   **Result**: `PERMISSION_DENIED` - Rejected as the `userId` in the payload must match `request.auth.uid`.

### Attack 3: Spoofed Timestamp
*   **Target**: `/recordings/rec_123`
*   **Payload**: `{"id": "rec_123", "userId": "my_uid", "title": "Old Rec", "createdAt": 10000000}`
*   **Action**: Sending a pre-calculated historical timestamp instead of `request.time`.
*   **Result**: `PERMISSION_DENIED` - Rejected because `createdAt` must match `request.time`.

### Attack 4: Shadow Fields Update (Ghost Injection)
*   **Target**: `/recordings/rec_123`
*   **Payload**: `{"title": "Updated Title", "compromised": true, "isAdmin": true}`
*   **Action**: Attempting to inject random variables inside a recording doc update.
*   **Result**: `PERMISSION_DENIED` - Rejected because updates must check `affectedKeys().hasOnly()` for permitted fields.

### Attack 5: Poisoned Huge ID Character Injection (Wallet Exhaustion)
*   **Target**: `/recordings/long_gibberish_id_over_128_chars_with_special_characters_...`
*   **Payload**: `{"id": "long_gibberish...", "userId": "my_uid", "title": "Rec", "createdAt": "TIMESTAMP"}`
*   **Action**: Injecting massive string IDs to blow up Firestore index and query storage nodes.
*   **Result**: `PERMISSION_DENIED` - Checked via `isValidId()` ensuring maximum size <= 128 and strict regex matching.

### Attack 6: Unauthenticated Scraping (PII Leak)
*   **Target**: `/users/victim_uid`
*   **Action**: Unauthenticated read request.
*   **Result**: `PERMISSION_DENIED` - User rules require `request.auth != null`.

### Attack 7: Cross-User Metadata Reading (PII Leak)
*   **Target**: `/recordings/rec_victim`
*   **Action**: Authenticated User A tries to read recording document belonging to Authenticated User B.
*   **Result**: `PERMISSION_DENIED` - Checked via `resource.data.userId == request.auth.uid`.

### Attack 8: Bulk Collection Scraping List Bypass
*   **Target**: `/recordings`
*   **Action**: Querying all records in the collection without a restrictive `where` filter.
*   **Result**: `PERMISSION_DENIED` - Enforcement clause mandates that list query checks `resource.data.userId == request.auth.uid`.

### Attack 9: Title Field Type Poisoning
*   **Target**: `/recordings/rec_123`
*   **Payload**: `{"title": ["Malicious", "Array", "Instead", "Of", "String"], "userId": "my_uid", ...}`
*   **Action**: Writing a list of strings instead of a plain string to corrupt user interfaces.
*   **Result**: `PERMISSION_DENIED` - The schema validation helper strictly enforces `title is string`.

### Attack 10: Inactive/Terminal Resource Delete
*   **Target**: `/recordings/rec_123`
*   **Action**: Attacker tries to delete a Recording owned by another user.
*   **Result**: `PERMISSION_DENIED` - Non-owner delete blocker prevents execution.

### Attack 11: Oversized Subtitle Injection
*   **Target**: `/recordings/rec_123`
*   **Action**: Attempting to write captions containing massive strings of text.
*   **Result**: `PERMISSION_DENIED` - Blocked by subtitle item string size validation limiters.

### Attack 12: Anonymous User Write
*   **Target**: `/recordings/rec_123`
*   **Action**: Attacker attempts to write data with an unverified anonymous token.
*   **Result**: `PERMISSION_DENIED` - Denied because email authentication is marked as required.

---

## Part 3: Threat Countermeasures Map
The security layout ensures absolute protection against all listed attacks.
All rules compiles on Firestore engine natively.
