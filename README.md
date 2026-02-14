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
## Probe disponibili

Le seguenti probe eBPF sono disponibili nella directory `probes/`.  
Ogni probe genera eventi JSON strutturati che vengono automaticamente raccolti da `monitor.py` e salvati in formato JSONL all’interno della cartella di sessione.

---

### binder.bt

**Categoria:** Monitoraggio IPC  

**Descrizione:**  
Traccia le transazioni Binder, il principale meccanismo di comunicazione inter-processo (IPC) nei sistemi Android. La probe cattura metadati relativi a ogni transazione, inclusi processo sorgente, processo destinatario, identificativi dei thread e flag della transazione.

**Eventi generati:**
- `binder_transaction`

**Casi d’uso:**
- Analizzare i pattern di comunicazione tra applicazioni e servizi di sistema  
- Individuare comportamenti IPC anomali  
- Supportare l’analisi comportamentale dei processi Android  

---

### process_lifecycle.bt

**Categoria:** Monitoraggio dei processi  

**Descrizione:**  
Monitora il ciclo di vita dei processi osservando i tracepoint dello scheduler del kernel. La probe registra eventi di creazione (`fork`), esecuzione di un nuovo programma (`exec`) e terminazione (`exit`).

**Eventi generati:**
- `fork`
- `exec`
- `exit`

**Casi d’uso:**
- Ricostruire l’albero dei processi  
- Identificare creazioni di processi sospette  
- Correlare l’attività dei processi con syscall o eventi IPC  

---

### syscalls.bt

**Categoria:** Monitoraggio delle system call  

**Descrizione:**  
Intercetta specifiche system call al momento dell’ingresso utilizzando il tracepoint `raw_syscalls:sys_enter`.  
Attualmente vengono monitorate:

- `execve`
- `openat`
- `connect`

La probe registra l’identificativo della syscall insieme al contesto di esecuzione (PID, UID e nome del processo).

**Casi d’uso:**
- Rilevare tentativi di esecuzione di programmi  
- Osservare l’accesso al file system  
- Monitorare tentativi di connessione verso l’esterno  

**Nota:**  
Gli argomenti delle system call vengono raccolti in forma grezza e potrebbero richiedere post-processing per un’interpretazione semantica.

---

### syscalls_latency.bt

**Categoria:** Monitoraggio delle prestazioni delle system call  

**Descrizione:**  
Estende il tracciamento delle system call correlando eventi di ingresso e uscita per calcolare la latenza di esecuzione e registrare il valore di ritorno. Questo consente un’analisi più approfondita del comportamento del sistema e delle condizioni di errore.

**Metriche aggiuntive:**
- Valore di ritorno (`ret`)
- Latenza di esecuzione in microsecondi (`lat_us`)

**Casi d’uso:**
- Individuare system call fallite  
- Rilevare latenze anomale  
- Effettuare analisi prestazionali  
- Abilitare analisi comportamentali avanzate  

---

### sched_switch.bt

**Categoria:** Monitoraggio dello scheduler  

**Descrizione:**  
Osserva i cambi di contesto effettuati dallo scheduler Linux. La probe registra quale processo viene sospeso e quale viene attivato, fornendo visibilità sulla dinamica di utilizzo della CPU.

**Eventi generati:**
- `switch`

**Casi d’uso:**
- Analizzare il comportamento dello scheduler  
- Individuare un’elevata frequenza di context switch  
- Supportare indagini sulle prestazioni  
- Correlare l’attività runtime con il comportamento dei processi  

---

## Formato degli eventi

Tutte le probe emettono eventi JSON su singola riga con una struttura coerente:

```json
{
  "ts": "HH:MM:SS",
  "type": "categoria",
  "event": "nome_evento",
  "pid": 123,
  "tid": 123,
  "uid": 1000,
  "comm": "nome_processo",
  "data": { ... }
}

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
