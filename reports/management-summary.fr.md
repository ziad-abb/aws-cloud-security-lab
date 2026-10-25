# Synthèse pour la direction : exercice de sécurité cloud, octobre 2026

> 🇬🇧 [English version](management-summary.md) · Une page pour un lecteur non technique.

**Ce qui a été fait.** Un environnement de petite entreprise a été construit sur AWS (un serveur web, un espace de stockage des données clients, la journalisation) puis attaqué volontairement avec trois incidents cloud réalistes. Pour chacun, nous avons mesuré la rapidité de **détection** et d'**arrêt**, puis rédigé des rapports d'incident, un registre des risques et une correspondance avec les référentiels. Toutes les données clients étaient fictives.

## Résultats
| Incident | Ce qui s'est passé | Détecté en | Arrêté en | Bilan |
|---|---|---|---|---|
| Stockage rendu public par erreur | N'importe qui sur Internet pouvait télécharger le fichier clients | 1 à 3,5 min | **10 s** automatique · 8 min à la main | Fichier clients fictif lu 26 fois en ~14 min d'exposition ; la copie chiffrée est restée protégée |
| Clé développeur divulguée dans le code | Un attaquant a trouvé la clé, téléchargé un fichier et créé une clé « porte dérobée » | 3,7 min | **6,4 min** (2,7 min après l'alerte) | 1 fichier lu ; porte dérobée supprimée ; aucun autre système touché |
| Port de connexion du serveur ouvert à Internet | Tentative de devinette de mots de passe | quelques secondes | **5 s** automatique · 8 min à la main | Aucun accès : le serveur n'accepte pas de mot de passe |
| Réglage dangereux du serveur réactivé | Pas d'attaque | 1,4 min | **6 s** automatique | Corrigé avant toute exploitation |

## Ce qu'il faut en retenir
1. **L'automatisation est rentable.** Les corrections automatiques ont arrêté les problèmes en 5 à 10 secondes, 50 à 90 fois plus vite qu'une personne, et souvent avant même l'arrivée de l'alerte.
2. **La surveillance rattrape ce que l'automatisation manque.** Une fois, la correction automatique n'était pas encore active. Le système de surveillance a quand même donné l'alerte en moins d'une minute.
3. **Les couches de protection ont fonctionné.** Le chiffrement et des droits minimaux ont protégé la copie la plus sensible même quand d'autres contrôles avaient échoué.
4. **La détection seule est trop lente pour empêcher un vol de données.** Les données ont été prises en quelques secondes ; les alertes prennent des minutes. La prévention compte le plus.

## Principaux risques et recommandations
| Priorité | Risque | Recommandation |
|---|---|---|
| 1 | Données clients rendues publiques par une erreur de configuration | Bloquer le stockage public au niveau du compte (un réglage, sans coût) |
| 2 | Clés développeur divulguées depuis le code | Remplacer les clés permanentes par des connexions de courte durée pour les systèmes de build ; analyser le code à la recherche de secrets avant publication |
| 3 | Corrections automatiques qui ne fonctionnent pas sans qu'on le sache | Les garder toujours actives et les tester après chaque changement |
| 4 | Surveillance limitée sur ce type de compte | Ajouter la détection de menaces gérée du fournisseur dès que l'offre le permet |

**Situation des risques :** 17 risques recensés ; **7 jugés élevés avant les contrôles, 0 après** (score moyen 12,3 → 5,8 sur 25). Les risques résiduels ont un responsable et sont suivis dans `reports/risk-register.xlsx`.

**Conformité :** les contrôles sont mis en correspondance avec CIS AWS 7.0, ISO/IEC 27001:2022, ISO/IEC 27017 et NIST CSF 2.0. Une note traite de la loi marocaine 09-08 (données personnelles). Score de configuration (CIS) : 53 % au départ, 57 % pendant les tests ; un score final après durcissement suivra.
