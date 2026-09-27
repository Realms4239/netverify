# netverify

**Vérifier la sortie d'un équipement réseau, sans aucun identifiant.**

Serveur MCP en lecture seule, et bibliothèque Python sans dépendance, pour
analyser la sortie brute d'un backbone ISP (SR Linux, FRR) : état des
interfaces, adjacences OSPF, sessions BGP, routes installées, ping.

[English](README.md) · [Français](README.fr.md)

## Le problème

Quand un ingénieur réseau diagnostique un routeur, il lit la sortie brute et la
compare à ce qu'il attend. C'est un travail manuel, répétitif, et c'est
exactement le type de travail où un agent IA se trompe de façon silencieuse : il
peut déclarer un lien « sain » parce que la sortie *ressemble* correcte.

Le piège principal : **la sortie d'un équipement n'est pas toujours de la sortie
d'équipement.** Un bandeau, une description d'interface ou une ligne syslog
peuvent contenir du texte écrit par une personne ayant un accès partiel au
réseau de gestion. Ce texte atterrit tel quel dans le contexte du modèle. Un
serveur MCP qui le recopie dans un rapport transmet une instruction, pas une
donnée.

`netverify` traite ce texte comme non fiable avant de l'utiliser.

## Garanties

- **Aucun identifiant, aucun socket.** La bibliothèque est une fonction pure sur
  du texte que vous avez déjà collected. Elle ne peut pas modifier un
  équipement, car cette capacité n'existe pas dans le processus.
- **Liste d'autorisations fermée.** Les commandes sont des identifiants
  enregistrés, pas des chaînes CLI. Le caractère « lecture seule » est garanti
  par le *type* de l'entrée, pas par un filtre.
- **Texte non fiable assaini.** Les identifiants extraits sont masqués et les
  tentatives d'injection de prompt sont neutralisées avant tout usage.
- **Zéro dépendance.** `netverify` s'importe avec un Python 3.11 nu.

## Installation

```sh
pip install netverify          # bibliothèque seule, sans dépendance
pip install "netverify[mcp]"   # plus le serveur MCP
```

## Utilisation comme bibliothèque

```python
from netverify import verify, sanitize

v = verify("srl_interface_brief", sortie, interface="ethernet-1/1")
print(v.ok, v.outcome.value)  # True 'pass'

rapport = sanitize(sortie)
print(rapport.safe_text)  # utilisable devant un modèle
print(rapport.findings)  # ce qui a été neutralisé
```

## Utilisation comme serveur MCP

```json
{
  "mcpServers": {
    "netverify": {
      "command": "netverify"
    }
  }
}
```

Outils publiés :

| Outil | Rôle |
|---|---|
| `verify_network_output` | Verdict structuré pour une commande de lecture |
| `sanitize_device_output` | Masque les secrets, neutralise les injections |
| `audit_device_output` | Signale les risques sans modifier le texte |
| `verify_capture` | Vérifie toute une capture d'incident |

Ressources : `netverify://contract` (commandes et limites),
`netverify://security` (modèle de menace).

## Commandes prises en charge

`frr_bgp_summary`, `ping`, `srl_bgp_neighbor_detail`, `srl_interface_brief`,
`srl_ospf_neighbor`, `srl_route_detail`

## Limites

- Le serveur **ne collecte pas** la sortie : il vérifie le texte que vous lui
  fournissez. Collecter exigerait des identifiants, ce que ce projet refuse par
  conception.
- Le transport `stdio` est local : la frontière de confiance est celle du
  processus système. Un déploiement distant exige un authorizer en amont.
- Le journal d'audit enregistre les résultats, **jamais** les charges utiles.

## Développement

```sh
python -m unittest discover -s tests -t .   # 76 tests, aucun install
python evals/run_evals.py                   # porte de qualité, sans réseau
python scripts/smoke_test.py                # bout-en-bbout via MCP
python scripts/stdio_check.py               # vrai processus, stdout propre
```

## Licence

MIT.
