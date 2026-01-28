#Questo file indica lo schema a cui devono fare riferimento tutti gli output delle probes
{
  "ts": 1737974612.123, --> timestamp in secondi decimali
  "type": "process", --> indica il macro-tipo della probe
  "event": "execve", --> il nome dell'evento specifico
  "pid": 1234, --> process id
  "tid": 1234, --> thread id
  "uid": 1000, --> user id
  "comm": "app_process", --> nome del processo
  "data": { 
    "filename": "/system/bin/sh" --> questo serve in casi particolari che richiedono payload specifici
  }
}
