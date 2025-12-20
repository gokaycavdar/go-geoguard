# GeoGuard

GeoGuard is a location-based security library for Go applications. It analyzes login attempts using geographic, network, and behavioral signals to detect suspicious activity such as VPN usage, impossible travel, and device changes.

## Problem Statement

Modern authentication systems need to detect account compromise beyond just password validation. Attackers using stolen credentials often:

- Connect from different geographic locations than the legitimate user
- Use VPNs, proxies, or data center infrastructure to mask their origin
- Exhibit "impossible travel" patterns (logging in from distant locations within short timeframes)
- Use different devices or browsers than the legitimate user

GeoGuard provides a rule-based, explainable risk scoring system that can be integrated into any Go backend.

## Design Principles

### Library-First Architecture

GeoGuard is designed as a reusable library, not an application:

- **Rule-agnostic engine**: The engine does not know concrete rule implementations
- **Interface-based extensibility**: All extensibility through interfaces, not type switches
- **Separation of concerns**: Engine owns GeoIP; rules receive only derived values
- **No exposed internal services**: Rules cannot access GeoIP directly

### Privacy by Design (KVKK/GDPR Compliant)

GeoGuard is designed to minimize personal data storage:

- **No raw IP storage**: IP addresses are masked to /24 (IPv4) or /64 (IPv6) subnet prefixes before storage
- **Ephemeral coordinates**: GPS coordinates are used only during analysis and never persisted
- **Minimal data retention**: Only CountryCode and CityGeonameID are stored for location context
- **No raw UserAgent storage**: Only hashed fingerprints are stored (SHA256)
- **Fingerprint hashing**: Device fingerprints are hashed before storage

### Explainable Results

Every risk score can be traced back to specific rules with human-readable explanations:

```go
// Example violation
{
    RuleName:  "Impossible Travel (Velocity Check)",
    RiskScore: 80,
    Reason:    "Checks if travel speed between logins exceeds 900 km/h.",
}
```

### Rule-Based Architecture

- **Stateless rules**: Evaluate each login independently (Geofencing, DataCenter, OpenProxy, Timezone, IP-GPS)
- **Stateful rules**: Compare with user's login history (Velocity, Fingerprint, CountryMismatch)
- **Configurable scores**: Each rule's risk contribution can be tuned per deployment

## Installation

```bash
go get github.com/gokaycavdar/go-geoguard
```

### Dependencies

GeoGuard requires MaxMind GeoIP2 databases:

1. Download [GeoLite2-City.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and [GeoLite2-ASN.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
2. Place them in an accessible directory
3. Optionally, download [IPsum](https://github.com/stamparm/ipsum) threat intelligence list for proxy detection

## Usage

### Minimal Integration

```go
package main

import (
    "log"

    "github.com/gokaycavdar/go-geoguard/pkg/engine"
    "github.com/gokaycavdar/go-geoguard/pkg/geoip"
    "github.com/gokaycavdar/go-geoguard/pkg/rules"
    "github.com/gokaycavdar/go-geoguard/pkg/storage"
)

func main() {
    // 1. Initialize GeoIP service
    geoService, err := geoip.NewService(
        "/path/to/GeoLite2-City.mmdb",
        "/path/to/GeoLite2-ASN.mmdb",
    )
    if err != nil {
        log.Fatal(err)
    }
    defer geoService.Close()

    // 2. Create history store (use Redis/PostgreSQL in production)
    store := storage.NewMemoryStore()

    // 3. Initialize engine (engine owns GeoIP service)
    guard := engine.New(geoService, store)

    // 4. Add rules (rules never access GeoIP directly)
    guard.AddRule(rules.NewGeofencingRule(39.0, 35.0, 500.0, 50))
    guard.AddRule(rules.NewVelocityRule(900.0, 80))  // No GeoIP parameter
    guard.AddRule(rules.DefaultDataCenterRule(30))

    // 5. Validate a login attempt
    input := engine.Input{
        UserID:         "user123",
        IPAddress:      "185.193.17.1",     // Backend-derived (ephemeral)
        Latitude:       41.0082,            // Frontend GPS (optional)
        Longitude:      28.9784,            // Frontend GPS (optional)
        UserAgent:      "Mozilla/5.0 ...",  // Backend-derived (hashed, not stored raw)
        ClientTimezone: "Europe/Istanbul",  // Frontend JS
    }

    result, record, err := guard.Validate(input)
    if err != nil {
        log.Fatal(err)
    }

    // 6. Make decision based on risk score
    if result.TotalRiskScore >= 100 {
        log.Println("BLOCKED:", result.Violations)
    } else {
        // Save for stateful rules
        store.SaveRecord(record)
        log.Println("ALLOWED, risk score:", result.TotalRiskScore)
    }
}
```

### Frontend-Backend Signal Correlation

GeoGuard correlates signals from both sources:

| Signal | Source | Trust Level |
|--------|--------|-------------|
| IP Address | Backend (HTTP connection) | Authoritative |
| User-Agent | Backend (HTTP header) | Authoritative |
| Accept-Language | Backend (HTTP header) | Authoritative |
| GPS Coordinates | Frontend (Geolocation API) | User-controlled |
| Timezone | Frontend (JavaScript) | User-controlled |

Backend-derived signals cannot be spoofed. Frontend-derived signals are cross-validated against backend signals to detect manipulation.

## Available Rules

### Stateless Rules

| Rule | Description | Typical Score |
|------|-------------|---------------|
| `GeofencingRule` | Flags logins outside a defined geographic area | 50 |
| `DataCenterRule` | Detects hosting/cloud provider IPs via ASN | 30 |
| `OpenProxyRule` | Matches IPs against known proxy/VPN lists | 40 |
| `IPGPSRule` | Compares IP location with client GPS | 40 |
| `TimezoneRule` | Compares IP timezone with browser timezone | 45 |

### Stateful Rules

| Rule | Description | Typical Score |
|------|-------------|---------------|
| `VelocityRule` | Detects impossible travel between logins | 80 |
| `FingerprintRule` | Flags device/browser changes | 35 |
| `CountryMismatchRule` | Flags country changes between logins | 25 |

## Storage Interface

GeoGuard uses an abstract storage interface for history management:

```go
type HistoryStore interface {
    GetLastRecord(userID string) (*models.LoginRecord, error)
    SaveRecord(record *models.LoginRecord) error
}
```

The library includes `MemoryStore` for development. For production, implement this interface with Redis, PostgreSQL, or your preferred data store.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Application                          │
├─────────────────────────────────────────────────────────────┤
│                     GeoGuard Engine                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Validate()                        │   │
│  │  1. Mask IP → /24 or /64 prefix                     │   │
│  │  2. Lookup GeoIP (engine-owned, ephemeral)          │   │
│  │  3. Build LoginRecord (privacy-safe)                │   │
│  │  4. Build GeoContext for EphemeralGeoRule           │   │
│  │  5. Execute rules via interface detection           │   │
│  │  6. Aggregate risk scores                           │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Rule Interfaces                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Rule (base)          │  EphemeralGeoRule (optional)│   │
│  │  - Name()             │  - ValidateWithGeo(ctx)     │   │
│  │  - Description()      │                             │   │
│  │  - Validate(...)      │  Used by: Geofencing,       │   │
│  │                       │  IPGPSRule, VelocityRule    │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Concrete Rules                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │Geofencing│ │DataCenter│ │OpenProxy │ │   IP-GPS     │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ Timezone │ │ Velocity │ │Fingerprnt│ │CountryChange │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐            ┌─────────────────────┐    │
│  │   GeoIP Service │            │   History Store     │    │
│  │ (Engine-owned)  │            │ (Memory/Redis/SQL)  │    │
│  └─────────────────┘            └─────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Key Architectural Decisions

1. **Engine owns GeoIP**: Rules never receive GeoIP services directly. The engine performs all lookups and passes derived values via `GeoContext`.

2. **Interface-based detection**: The engine uses type assertion to detect if a rule implements `EphemeralGeoRule`, avoiding type switches on concrete types.

3. **GeoContext for coordinates**: Rules requiring geographic data implement `EphemeralGeoRule` and receive coordinates via `GeoContext` struct.

4. **Privacy boundary at engine**: All privacy transformations (IP masking, fingerprint hashing) happen in the engine before data reaches rules or storage.

## Rule Interface

Rules implement one of two interfaces:

```go
// Base interface - all rules must implement
type Rule interface {
    Name() string
    Description() string
    Validate(input LoginRecord, lastRecord *LoginRecord) (int, error)
}

// Optional interface for rules requiring coordinates
type EphemeralGeoRule interface {
    Rule
    ValidateWithGeo(ctx GeoContext, input LoginRecord, lastRecord *LoginRecord) (int, error)
}

// GeoContext provides ephemeral coordinates (never persisted)
type GeoContext struct {
    IPLatitude, IPLongitude           float64  // From GeoIP
    DeviceLatitude, DeviceLongitude   float64  // From client GPS
    PreviousIPLatitude, PreviousIPLongitude float64  // From last login
}
```

## Examples

The `examples/` directory contains:

- **`scenarios/`**: Programmatic demonstration of security scenarios (VPN detection, impossible travel, etc.)
- **`webserver/`**: HTTP API integration example using Gin framework

Run the scenarios example:

```bash
cd examples/scenarios
go run main.go
```

## Privacy Implementation Details

### IP Masking

```go
// IPv4: 185.193.17.42 → 185.193.17.0/24
// IPv6: 2001:db8::1234:5678 → 2001:db8::/64
maskedPrefix := rules.MaskIP(rawIP)
```

### Ephemeral Coordinate Handling

Coordinates from GeoIP lookup are used only during rule evaluation:

1. Engine calls `geoService.GetLocation(ip)` → returns `(lat, lon, country, city, timezone)`
2. Engine builds `GeoContext` with current and previous coordinates
3. Rules implementing `EphemeralGeoRule` receive `GeoContext` via `ValidateWithGeo()`
4. Only `CountryCode` and `CityGeonameID` are stored in `LoginRecord`
5. Raw coordinates go out of scope and are garbage collected

### What Gets Stored (LoginRecord)

```go
type LoginRecord struct {
    UserID          string    // User identifier
    Timestamp       time.Time // Login time
    MaskedIPPrefix  string    // /24 or /64 prefix only (NEVER raw IP)
    CountryCode     string    // "TR", "US", etc.
    CityGeonameID   uint      // Numeric city ID
    ASN             uint      // Autonomous System Number
    OrgName         string    // ISP/Organization name
    FingerprintHash string    // SHA256 of UserAgent+Language (NEVER raw UserAgent)
    IPTimezone      string    // From GeoIP
    ClientTimezone  string    // From frontend JS
}
```

### What Is NOT Stored

- Raw IP addresses
- GPS coordinates (latitude/longitude)
- Raw User-Agent strings
- Raw Accept-Language headers

## License

MIT License

## Contributing

Contributions are welcome. Please ensure:

1. All comments are in English
2. Privacy principles are maintained
3. New rules implement the `Rule` interface
4. Tests cover new functionality
