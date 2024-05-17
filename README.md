# ClientAnprPdnd

clientAnpr API di esempio per recuperare l'idANPR dal servizio c030 ed usarlo nella chiamata al servizio C001
- API version: 1.1-SNAPSHOT
  - Build date: 2024-05-17T10:02:31.334Z[GMT]


## Requirements

Building the API client library requires:
1. Java 1.7+

## Installation
Inserite la vostra chiave privata (pk.priv) nella cartella store .
Riempite i campi relativi agli id pdnd nel file pdnd.properties:
  - kidPdnd
  - clientIdPdnd
  - purposeIdPdnd_c001 per il servizio notifica
  - purposeIdPdnd_c030 per il recupero dell'idANPR
  - se necessario modificate il file "testCF" presente nella cartella store e contenente la richiesta
  - se necessario settate i campi relativi al proxy


```shell
mvn clean install
```
#Run
To execute:

```shell
java -jar target/dist-clientApiAnprPdnd-1.0.0.jar
