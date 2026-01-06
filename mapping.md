# FIX Protocol to VCP Field Mapping
## VCP v1.1 | FIX 4.4 Sidecar Integration

---

## Lossless / Lossy Field Classification

**CRITICAL**: This section defines which FIX fields are captured losslessly and which may involve transformation or loss.

### Lossless Fields (1:1 Mapping)

| FIX Tag | FIX Field | VCP Field | Guarantee |
|---------|-----------|-----------|-----------|
| 11 | ClOrdID | `Trade.ClOrdID` | Exact string copy |
| 37 | OrderID | `Trade.OrderID` | Exact string copy |
| 17 | ExecID | `Trade.ExecID` | Exact string copy |
| 41 | OrigClOrdID | `Trade.OrigClOrdID` | Exact string copy |
| 55 | Symbol | `Trade.Symbol` | Exact string copy (masked in PoC) |
| 35 | MsgType | `Header.EventType` | Deterministic mapping |
| 150 | ExecType | `Header.EventType` | Deterministic mapping |

### Lossy Fields (Transformation Applied)

| FIX Tag | FIX Field | VCP Field | Transformation | Loss Description |
|---------|-----------|-----------|----------------|------------------|
| 54 | Side | `Trade.Side` | `1`→`"BUY"`, `2`→`"SELL"` | Enum to string (reversible) |
| 52/60 | SendingTime/TransactTime | `Header.TimestampISO` | FIX→ISO 8601 | Format change (lossless) |
| 38/32 | OrderQty/LastQty | `Trade.Volume` | Numeric | Float precision (IEEE 754) |
| 44/31 | Price/LastPx | `Trade.Price` | Numeric | Float precision (IEEE 754) |

**Rationale for Transformations**:

| Transformation | Reason |
|----------------|--------|
| Side enum→string | Human readability; fully reversible (`BUY`→`1`, `SELL`→`2`) |
| Timestamp format | ISO 8601 is industry standard; original precision preserved |
| Float precision | IEEE 754 double (64-bit) provides 15-17 significant digits; exceeds typical FIX precision requirements |
| Symbol masking | Counterparty/instrument information may be commercially sensitive; masked at capture time |

### Dropped Fields (Not Captured)

| FIX Tag | FIX Field | Reason | Alternative |
|---------|-----------|--------|-------------|
| 6 | AvgPx | Derived value | Recomputable from executions |
| 14 | CumQty | Derived value | Recomputable from executions |
| 151 | LeavesQty | Derived value | Recomputable |
| 34 | MsgSeqNum | Session-level | Gap detection handled separately |
| 49/56 | SenderCompID/TargetCompID | Session-level | Masked to `Governance.AlgorithmName` |

### Timestamp Priority and Precision

| Priority | FIX Field | Tag | Condition |
|----------|-----------|-----|-----------|
| 1 | TransactTime | 60 | Always preferred |
| 2 | SendingTime | 52 | Fallback if 60 absent |
| 3 | Sidecar timestamp | — | Last resort |

**Precision Handling**:
```
FIX: 20250106-08:15:23.456    → VCP: 1736151323456000 (µs)
FIX: 20250106-08:15:23.456789 → VCP: 1736151323456789 (µs)
FIX: 20250106-08:15:23        → VCP: 1736151323000000 (µs, zero-padded)
```

**Note**: Silver tier uses MILLISECOND precision. Sub-millisecond digits are preserved but ClockSyncStatus remains BEST_EFFORT.

---

## Overview

This document defines the field mapping between FIX Protocol 4.4 messages and VCP v1.1 events. The VCP Sidecar captures FIX messages non-invasively and transforms them into cryptographically verifiable audit events.

**Mapping Version**: 1.0  
**FIX Version**: 4.4  
**VCP Version**: 1.1

---

## 1. Core Field Mappings

### 1.1 Timestamp Handling

| FIX Tag | FIX Field | VCP Field | Notes |
|---------|-----------|-----------|-------|
| 52 | SendingTime | `Header.TimestampISO` | Primary timestamp source |
| 60 | TransactTime | `Header.TimestampISO` | Used if SendingTime unavailable |
| — | — | `Header.TimestampInt` | Derived: microseconds since epoch |

**Precision Mapping**:

| FIX Precision | Example | VCP TimestampPrecision | ClockSyncStatus |
|---------------|---------|------------------------|-----------------|
| Seconds | `20250106-08:15:23` | MILLISECOND | BEST_EFFORT |
| Milliseconds | `20250106-08:15:23.456` | MILLISECOND | BEST_EFFORT |
| Microseconds | `20250106-08:15:23.456789` | MICROSECOND | NTP_SYNCED |

**Conversion Formula**:
```
VCP TimestampISO = FIX YYYYMMDD-HH:MM:SS.sss → ISO 8601 (YYYY-MM-DDTHH:MM:SS.sssZ)
VCP TimestampInt = Unix epoch × 1,000,000 (microseconds)
```

---

### 1.2 Order Identification

| FIX Tag | FIX Field | VCP Field | Description |
|---------|-----------|-----------|-------------|
| 11 | ClOrdID | `Trade.ClOrdID` | Client-assigned order ID |
| 37 | OrderID | `Trade.OrderID` | Broker-assigned order ID |
| 17 | ExecID | `Trade.ExecID` | Execution report ID |
| 41 | OrigClOrdID | `Trade.OrigClOrdID` | Original order ID (for cancel/replace) |

**Example**:
```
FIX: 11=ORD-001|37=BRK-001|17=EXE-002
VCP: { "Trade": { "ClOrdID": "ORD-001", "OrderID": "BRK-001", "ExecID": "EXE-002" } }
```

---

### 1.3 Instrument and Side

| FIX Tag | FIX Field | VCP Field | Value Mapping |
|---------|-----------|-----------|---------------|
| 55 | Symbol | `Trade.Symbol` | Direct copy (masked in PoC) |
| 54 | Side | `Trade.Side` | `1` → `"BUY"`, `2` → `"SELL"` |

---

### 1.4 Quantity and Price

| FIX Tag | FIX Field | VCP Field | Description |
|---------|-----------|-----------|-------------|
| 38 | OrderQty | `Trade.Volume` | Order quantity |
| 44 | Price | `Trade.Price` | Limit price |
| 32 | LastQty | `Trade.Volume` | Fill quantity (for EXE/PRT) |
| 31 | LastPx | `Trade.Price` | Fill price (for EXE/PRT) |
| 14 | CumQty | — | Not mapped (derived) |
| 151 | LeavesQty | — | Not mapped (derived) |
| 6 | AvgPx | — | Not mapped (derived) |
| 12 | Commission | `Trade.Commission` | Execution commission |

---

### 1.5 Session Identification

| FIX Tag | FIX Field | VCP Field | Notes |
|---------|-----------|-----------|-------|
| 49 | SenderCompID | `Governance.AlgorithmName` | Masked in PoC |
| 56 | TargetCompID | — | Not directly mapped |
| 34 | MsgSeqNum | — | Used for gap detection |

---

## 2. Message Type to Event Type Mapping

| FIX MsgType (35) | FIX Name | VCP EventType | Trigger |
|------------------|----------|---------------|---------|
| D | NewOrderSingle | `ORD` | Order submission |
| F | OrderCancelRequest | `CXL` | Cancel request |
| G | OrderCancelReplaceRequest | `MOD` | Modify request |
| 8 (150=0) | ExecutionReport - New | `ACK` | Order acknowledged |
| 8 (150=1) | ExecutionReport - Partial | `PRT` | Partial fill |
| 8 (150=2/F) | ExecutionReport - Fill | `EXE` | Full execution |
| 8 (150=4) | ExecutionReport - Canceled | `CXL` | Cancel confirmed |
| 8 (150=5) | ExecutionReport - Replaced | `MOD` | Modify confirmed |
| 8 (150=8) | ExecutionReport - Rejected | `REJ` | Order rejected |
| 9 | OrderCancelReject | `REJ` | Cancel rejected |

---

## 3. ExecType (150) Detailed Mapping

| ExecType | Name | VCP EventType | OrdStatus (39) |
|----------|------|---------------|----------------|
| 0 | New | `ACK` | 0 (New) |
| 1 | Partial Fill | `PRT` | 1 (Partially Filled) |
| 2 | Fill | `EXE` | 2 (Filled) |
| 3 | Done for Day | `CXL` | 3 (Done for Day) |
| 4 | Canceled | `CXL` | 4 (Canceled) |
| 5 | Replaced | `MOD` | 0/1 (New/Partial) |
| 6 | Pending Cancel | — | Not mapped |
| 7 | Stopped | — | Not mapped |
| 8 | Rejected | `REJ` | 8 (Rejected) |
| F | Trade | `EXE` | 1/2 |

---

## 4. Error and Rejection Mapping

### 4.1 OrdRejReason (103) to VCP Error

| FIX Code | FIX Reason | VCP ErrorCode | VCP Severity |
|----------|------------|---------------|--------------|
| 0 | Broker option | `BROKER_OPTION` | WARNING |
| 1 | Unknown symbol | `UNKNOWN_SYMBOL` | WARNING |
| 2 | Exchange closed | `EXCHANGE_CLOSED` | WARNING |
| 3 | Order exceeds limit | `INSUFFICIENT_MARGIN` | WARNING |
| 4 | Too late to enter | `TOO_LATE` | WARNING |
| 5 | Unknown order | `UNKNOWN_ORDER` | WARNING |
| 6 | Duplicate order | `DUPLICATE_ORDER` | WARNING |

### 4.2 Text Field Mapping

| FIX Tag | FIX Field | VCP Field |
|---------|-----------|-----------|
| 58 | Text | `Error.ErrorMessage` |

---

## 5. VCP-Specific Fields (Not from FIX)

These fields are generated by the VCP Sidecar, not extracted from FIX:

| VCP Field | Source | Description |
|-----------|--------|-------------|
| `Header.Version` | Config | Always "1.1" |
| `Header.EventID` | Generated | UUID v7 (time-ordered) |
| `Header.EventHash` | Computed | SHA-256 of canonical event |
| `Header.PrevHash` | Chain | Previous event's hash |
| `Header.HashAlgo` | Config | "SHA256" |
| `Header.SignAlgo` | Config | "ED25519" |
| `Header.ClockSyncStatus` | System | Per tier requirements |
| `Header.TimestampPrecision` | Config | Per tier requirements |
| `Governance.DecisionReason` | Sidecar | Event description |
| `Governance.Confidence` | Algorithm | Signal confidence (SIG only) |
| `PolicyIdentification.*` | Config | VCP v1.1 policy metadata |

---

## 6. Signal Events (SIG)

Signal events are **not derived from FIX messages** but generated by the trading algorithm before order submission:

| VCP Field | Source | Description |
|-----------|--------|-------------|
| `Trade.Symbol` | Algorithm | Target instrument |
| `Trade.Side` | Algorithm | Trade direction |
| `Trade.Price` | Algorithm | Signal price |
| `Governance.Confidence` | Algorithm | Signal confidence (0.0-1.0) |
| `Governance.DecisionReason` | Algorithm | Decision rationale |

---

## 7. Example Transformations

### 7.1 NewOrderSingle (D) → ORD

**FIX Input**:
```
8=FIX.4.4|35=D|49=CLIENT|56=BROKER|11=ORD-001|55=XXXYYY|54=1|38=10000|44=150.125|60=20250106-08:15:23.456|
```

**VCP Output**:
```json
{
  "Header": {
    "Version": "1.1",
    "EventID": "019b91a8-9d69-7b94-...",
    "EventType": "ORD",
    "TimestampISO": "2025-01-06T08:15:23.456Z",
    "TimestampInt": 1736151323456000,
    "EventHash": "e715472c782a6950..."
  },
  "Trade": {
    "Symbol": "XXXYYY",
    "Side": "BUY",
    "Volume": 10000.0,
    "Price": 150.125,
    "ClOrdID": "ORD-001"
  },
  "Governance": {
    "AlgorithmName": "ALGO_001",
    "DecisionReason": "Order submitted via FIX"
  }
}
```

### 7.2 ExecutionReport - Fill (8/150=2) → EXE

**FIX Input**:
```
8=FIX.4.4|35=8|37=BRK-001|17=EXE-002|11=ORD-001|55=XXXYYY|54=1|150=2|32=10000|31=150.127|12=0.50|60=20250106-08:15:23.789|
```

**VCP Output**:
```json
{
  "Header": {
    "EventType": "EXE",
    "TimestampISO": "2025-01-06T08:15:23.789Z"
  },
  "Trade": {
    "Symbol": "XXXYYY",
    "OrderID": "BRK-001",
    "Side": "BUY",
    "Volume": 10000.0,
    "Price": 150.127,
    "Commission": 0.50,
    "ClOrdID": "ORD-001",
    "ExecID": "EXE-002"
  },
  "Governance": {
    "DecisionReason": "Order fully executed"
  }
}
```

---

## 8. Validation Rules

### 8.1 Required FIX Fields per Message Type

| MsgType | Required FIX Tags |
|---------|-------------------|
| D (NewOrderSingle) | 11, 55, 54, 38, 44, 60 |
| F (CancelRequest) | 11, 41, 55, 54, 60 |
| G (CancelReplace) | 11, 41, 55, 54, 38, 44, 60 |
| 8 (ExecReport) | 11, 37, 17, 55, 54, 150, 39, 60 |

### 8.2 Timestamp Validation

- TransactTime (60) **MUST** be present
- SendingTime (52) **SHOULD** be present
- Sidecar timestamp **MUST NOT** precede FIX timestamp

---

## 9. Limitations and Considerations

| Aspect | Limitation | Mitigation |
|--------|------------|------------|
| FIX Timestamp | Max millisecond precision | Silver tier acceptable |
| Session ID | SenderCompID masked | Use Governance.AlgorithmName |
| Quote/MarketData | Not captured | Out of scope for order audit |
| Heartbeat/Logon | Not captured | Session-level, not order-level |

---

## 10. References

- FIX Protocol 4.4 Specification: https://www.fixtrading.org/standards/fix-4-4/
- VCP Specification v1.1: https://veritaschain.org/vcp/v1.1
- VCP-TRADE Module: VCP Specification Section 4

---

*Document Version: 1.0 | Last Updated: 2025-01-06*
