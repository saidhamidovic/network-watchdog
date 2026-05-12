# 🛰️ WatchDog Unified

En sammanslagen och kraftfull säkerhetssvit för hemmanätverket som kombinerar proaktiv skanning med realtidsövervakning av intrång.

## 🛠️ Arkitektur & Funktioner

### 1. Nätverksövervakning (Proaktiv)
*   **Periodisk Scanning:** Kör `nmap -sV --script vuln` mot lokala nätverket (standard: var 8:e timme).
*   **Intelligent Discovery:** Bevakar ARP-tabellen i realtid. Så fort en ny IP upptäcks triggas en omedelbar djup-scan.
*   **Baseline Comparison:** Jämför resultat mot `baseline.xml` för att hitta nya enheter eller nyligen öppnade portar.

### 2. Intrångsdetektering (HIDS)
*   **SSH Guard:** Övervakar `/var/log/auth.log` för misslyckade och lyckade inloggningar.
*   **Kernel Auditing (Auditd):** Integrerad med Linux Audit Daemon för att se modifieringar av kritiska systemfiler (`/etc/passwd`, `/etc/shadow`, etc.) och körning av riskfyllda kommandon i realtid.
*   **ARP Spoofing Detector:** Bevakar Gatewayens MAC-adress för att förhindra Man-in-the-Middle-attacker.

### 3. Respons & Notifiering
*   **Fail2ban Integration:** Skriver säkerhetshändelser till en dedikerad logg som Fail2ban på värdmaskinen kan agera på för att banna IP-adresser.
*   **Real-time Alerts:** Push-notiser via **ntfy.sh** för alla kritiska händelser.

---

## 📁 Projektstruktur
```text
/home/cako/gemini_projects/HomeNetwork/
├── watchdog.py           # Sammanslagen logik (Multithreaded)
├── Dockerfile            # Innehåller nmap, iproute2, audit-verktyg
├── docker-compose.yml    # Enhetlig tjänst med nödvändiga volym-mounts
├── .env                  # Central konfiguration
├── README.md             # Användarinstruktioner
├── data/                 # baseline.xml, watchdog.log och security_events.log
└── fail2ban/             # Filter och Jail-inställningar för värdmaskinen
```

## 🛡️ Status & Historik
*   **2026-05-12:** Sammanslagning av Network Watchdog och Security Guardian till **WatchDog Unified**.
*   **Förbättring:** Implementerat omedelbar scanning av nya enheter via ARP-discovery.
*   **Förbättring:** Implementerat `auditd`-integration för kernel-level filövervakning.
*   **Status:** Deployed på `192.168.0.150` (Ubuntu Proxy).

## 📋 Rekommendationer för framtiden:
1.  **DB-migrering:** Flytta från `baseline.xml` till SQLite för bättre historik.
2.  **UPnP-detektor:** Implementera övervakning av automatiska portöppningar i routern.
3.  **IPv6-stöd:** Utöka bevakningen till att även omfatta IPv6 Neighbor Discovery.
