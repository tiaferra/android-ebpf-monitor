# Android eBPF Monitor

**android-ebpf-monitor** è un progetto di monitoraggio e osservabilità per ambienti Android (Cuttlefish) basato su **eBPF** e **bpftrace**, con un layer di orchestrazione in Python.

L'obiettivo è costruire un sistema in grado di:
- osservare eventi di sistema a basso livello (syscall, processi, file, rete)
- correlare attività tra applicazioni e servizi di sistema
- generare sessioni di monitoraggio strutturate
- produrre report e statistiche di sicurezza

Questo progetto nasce come strumento sperimentale di analisi, ricerca e sicurezza.

---

## 📁 Struttura del progetto

```
android-ebpf-monitor/
├── config/          # configurazioni future (policy, filtri, regole)
├── monitor.py       # orchestratore principale
├── probes/          # script bpftrace
│   └── test_exec.bt
├── reports/         # report generati
└── sessions/        # sessioni di monitoraggio
    └── <timestamp>/
        ├── events.jsonl
        └── stderr.log
```

---

## 🧠 Architettura concettuale

Il sistema è strutturato a livelli:

1. **Livello kernel (eBPF)**
   - probe bpftrace
   - hook su syscall, tracepoint, kprobe, uprobes

2. **Livello di raccolta eventi**
   - bpftrace produce eventi in formato JSON

3. **Livello di orchestrazione (Python)**
   - `monitor.py` avvia le probe
   - gestisce le sessioni
   - salva gli eventi
   - separa output valido/errori

4. **Livello di analisi (futuro)**
   - parsing
   - correlazione
   - grafi di interazione
   - statistiche
   - reportistica

---

## ▶️ Avvio del monitor

```bash
python3 monitor.py
```

Alla partenza:
- viene creata una nuova sessione in `sessions/<timestamp>/`
- parte `bpftrace`
- gli eventi vengono salvati in `events.jsonl`
- output non valido viene salvato in `stderr.log`

Stop:
```text
Ctrl-C
```

---

## 📄 Formato eventi

Gli eventi sono salvati in formato JSON Lines (`.jsonl`):

```json
{"ts": 1737974612, "pid": 1234, "comm": "app_process", "syscall": "execve", "filename": "/system/bin/sh"}
```

Questo formato permette:
- streaming
- parsing incrementale
- compatibilità con sistemi di analisi

---

## 🎯 Obiettivi funzionali (roadmap)

### Monitoraggio
- [ ] Syscall tracing
- [ ] File access tracking
- [ ] Process execution
- [ ] Network activity
- [ ] IPC / Binder

### Analisi
- [ ] Statistiche syscall
- [ ] Rilevamento syscall ad alto rischio
- [ ] Pattern comportamentali
- [ ] Profilazione applicazioni

### Visualizzazione
- [ ] Grafi app-app
- [ ] Grafi app-servizi
- [ ] Grafi rete
- [ ] Timeline eventi

### Sicurezza
- [ ] Anomaly detection
- [ ] Behaviour fingerprinting
- [ ] Rule engine

---

## 🔮 Estensioni previste

- Integrazione con **Tetragon (Cilium eBPF)**
- Motore di regole
- Sistema di policy
- Alerting
- Export dati (JSON, CSV, GraphML)

---

## 🛠 Tecnologie

- **eBPF**
- **bpftrace**
- **Python 3**
- **Android Cuttlefish**
- **Debian (proot)**

---

## ⚠️ Disclaimer

Questo progetto è a scopo **didattico, sperimentale e di ricerca**.
Non è pensato per ambienti produttivi.

---

## 📌 Autore

Progetto sviluppato come parte di attività di studio e ricerca su:
- eBPF
- osservabilità
- sicurezza dei sistemi
- sistemi Android
