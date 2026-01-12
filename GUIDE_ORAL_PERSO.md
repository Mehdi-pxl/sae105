# 🎤 GUIDE ORAL PERSONNEL - SAÉ 1.05 (VERSION SIMPLE)
## ⚠️ CONFIDENTIEL - NE PAS RENDRE - ANTISÈCHE POUR L'ORAL

---

## 📋 PLAN GÉNÉRAL (12 MINUTES)

| Temps | Section | Durée |
|-------|---------|-------|
| 0:00-1:00 | Contexte France-Inde | 1 min |
| 1:00-4:00 | Démonstration Complète | 3 min |
| 4:00-8:00 | Explication Technique | 4 min |
| 8:00-12:00 | Questions du Jury | 4 min |

---

## 🎯 PARTIE 1: CONTEXTE (0:00 - 1:00)

**Script à dire**:

> "Bonjour, je m'appelle [TON NOM] et je présente mon projet SAÉ 1.05 : un système d'analyse de sécurité réseau.
>
> **Le contexte**: Une entreprise avec un site en France et un site de production en Inde subit une saturation réseau. Mon rôle est d'analyser les logs pour identifier les problèmes.
>
> **Ma solution**: Un script Python simple qui détecte les anomalies, et un site web Symfony qui affiche les résultats avec des graphiques."

---

## 💻 PARTIE 2: DÉMONSTRATION COMPLÈTE (1:00 - 4:00)

### A. Lancer l'Analyse Python (1:00 - 1:30)

**Action**:
```bash
python analyse_reseau.py
```

**Ce que tu dis**:
> "Je lance mon script Python. Il lit le fichier de logs, détecte les anomalies, et crée 2 fichiers :
> - Un CSV avec les données détaillées
> - Un JSON avec un résumé en texte
>
> Les fichiers sont horodatés, donc chaque analyse garde son historique."

**Montrer la sortie**:
- 507 891 lignes lues
- 1969 paquets SYN détectés (CRITIQUE)
- Fichiers créés dans `public/rapports/`

### B. Afficher la Liste des Rapports (1:30 - 2:00)

**Action**: Ouvrir `http://localhost:8000`

**Ce que tu dis**:
> "Sur le site web, je vois la liste de tous mes rapports avec la date et l'heure.
>
> Si je lance l'analyse plusieurs fois, j'ai un historique complet. Rien n'est écrasé."

### C. Voir le Détail avec Graphiques (2:00 - 3:00)

**Action**: Cliquer sur "View Report"

**Ce que tu dis**:
> "En cliquant sur un rapport, je vois :
>
> 1. **Le résumé texte** : Explications simples des problèmes détectés
> 2. **Les graphiques Chart.js** :
>    - Graphique 1 : Répartition par sévérité (CRITIQUE, ÉLEVÉE, MOYENNE)
>    - Graphique 2 : Types d'attaques (SYN Flood, Horaires anormaux)
> 3. **Le tableau détaillé** : Toutes les alertes avec IP source, sévérité, description"

### D. Exporter en PDF (3:00 - 4:00)

**Action**: Cliquer sur "Print to PDF"

**Ce que tu dis**:
> "Pour créer un rapport PDF, je clique sur 'Print to PDF'.
>
> Le navigateur ouvre la boîte de dialogue d'impression. Je peux choisir 'Enregistrer en PDF'.
>
> **Astuce technique** : J'utilise du CSS `@media print` pour cacher les boutons et menus à l'impression. C'est simple et ça marche partout."

---

## 🔧 PARTIE 3: EXPLICATION TECHNIQUE (4:00 - 8:00)

### A. Le Script Python Simple (4:00 - 6:00)

**Ouvrir `analyse_reseau.py`** et montrer :

#### 1. Récupération du Fichier (ligne ~250)

```python
if len(sys.argv) > 1:
    fichier = sys.argv[1]
else:
    fichier = FICHIER_PAR_DEFAUT
```

**Explication**:
> "`sys.argv` est une liste qui contient les arguments de la ligne de commande.
>
> - `sys.argv[0]` = nom du script ('analyse_reseau.py')
> - `sys.argv[1]` = premier argument (le fichier)
>
> **Analogie** : C'est comme quand tu donnes une adresse au GPS. Si tu ne donnes rien, il utilise 'Maison' par défaut."

#### 2. Nom Horodaté (ligne ~180)

```python
maintenant = datetime.now()
nom = maintenant.strftime("rapport_%Y%m%d_%H%M%S")
```

**Explication**:
> "`datetime.now()` donne la date et l'heure actuelles.
>
> `strftime()` formate cette date en texte. Par exemple :
> - `%Y` = année (2026)
> - `%m` = mois (01)
> - `%d` = jour (12)
> - `%H%M%S` = heure:minute:seconde
>
> Résultat : `rapport_20260112_083000`
>
> **Pourquoi ?** Chaque rapport a un nom unique. On ne perd jamais l'historique."

#### 3. Export JSON (ligne ~200)

```python
resume = {
    "date_analyse": "12/01/2026 08:30:00",
    "resume_texte": [
        "⚠️ ALERTE CRITIQUE : IP 190-0-175-100...",
        "📊 1969 paquets SYN envoyés"
    ]
}

with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(resume, f, ensure_ascii=False, indent=2)
```

**Explication**:
> "JSON est un format de données simple, comme un dictionnaire Python.
>
> Je crée un résumé en phrases simples pour l'afficher sur le site web.
>
> `json.dump()` écrit ce dictionnaire dans un fichier."

### B. Le Contrôleur Symfony (6:00 - 8:00)

**Ouvrir `RapportController.php`** et montrer :

#### 1. Lister les Rapports (méthode `index()`)

```php
$fichiers = scandir($dossier);

foreach ($fichiers as $fichier) {
    if (str_ends_with($fichier, '.csv')) {
        // Extraire date et heure du nom
        if (preg_match('/rapport_(\d{8})_(\d{6})/', $nom, $matches)) {
            $date = $matches[1];
            $heure = $matches[2];
            // ...
        }
    }
}
```

**Explication**:
> "`scandir()` lit tous les fichiers d'un dossier. C'est comme ouvrir un tiroir et regarder ce qu'il y a dedans.
>
> Ensuite, je filtre pour ne garder que les fichiers `.csv`.
>
> `preg_match()` utilise une expression régulière pour extraire la date et l'heure du nom de fichier."

#### 2. Afficher un Rapport (méthode `detail()`)

```php
$file = fopen($csv_path, 'r');
fgetcsv($file, 1000, ';'); // Ignorer l'en-tête

while (($data = fgetcsv($file, 1000, ';')) !== false) {
    $alertes[] = [
        'type' => $data[0],
        'ip_source' => $data[1],
        // ...
    ];
}
```

**Explication**:
> "`fopen()` ouvre le fichier CSV.
>
> `fgetcsv()` lit une ligne et la découpe en tableau selon le séparateur (`;`).
>
> La première ligne est l'en-tête, je l'ignore. Ensuite, je lis toutes les lignes dans une boucle `while`."

---

## ❓ PARTIE 4: QUESTIONS DU JURY (8:00 - 12:00)

### Question 1: "Pourquoi Chart.js en CDN ?"

**Ta réponse**:

> "J'ai utilisé Chart.js via CDN (Content Delivery Network) pour 3 raisons :
>
> **1. Simplicité**
> - Pas besoin d'installer de librairie
> - Juste un lien `<script src="...">` dans le HTML
> - Ça marche immédiatement
>
> **2. Performance**
> - Le CDN est rapide et fiable
> - Les fichiers sont mis en cache par le navigateur
> - Pas de gestion de versions à faire
>
> **3. Visualisation**
> - Les graphiques permettent de voir instantanément la saturation réseau
> - Plus facile à comprendre qu'un tableau de chiffres
> - Professionnel pour une présentation
>
> **Alternative** : Si je devais installer localement, j'utiliserais `npm install chart.js`, mais pour un projet étudiant, le CDN est parfait."

### Question 2: "Comment tu fais le PDF ?"

**Ta réponse**:

> "J'utilise la fonction native `window.print()` du navigateur avec du CSS `@media print`.
>
> **Fonctionnement** :
> 1. L'utilisateur clique sur 'Print to PDF'
> 2. JavaScript appelle `window.print()`
> 3. Le navigateur ouvre la boîte de dialogue d'impression
> 4. L'utilisateur choisit 'Enregistrer en PDF'
>
> **Le CSS `@media print`** :
> ```css
> @media print {
>     .no-print { display: none; }
> }
> ```
> Ça cache les boutons et menus à l'impression pour un rendu propre.
>
> **Avantages** :
> - Fonctionne sur n'importe quel PC (Windows, Mac, Linux)
> - Pas besoin d'installer de librairie PHP lourde (TCPDF, FPDF)
> - L'utilisateur contrôle les paramètres (orientation, marges)
> - Méthode recommandée pour les petits projets
>
> **Inconvénient** : Moins de contrôle qu'une librairie dédiée, mais suffisant pour ce projet."

### Question 3: "Pourquoi l'historique des rapports ?"

**Ta réponse**:

> "Chaque analyse crée un fichier horodaté (exemple: `rapport_20260112_083000.csv`).
>
> **Utilité** :
> 1. **Traçabilité** : Garder une trace de chaque incident
> 2. **Comparaison** : Voir l'évolution dans le temps
> 3. **Sécurité** : Ne jamais écraser les anciennes analyses
> 4. **Audit** : Prouver qu'on a bien analysé à telle date
>
> **Exemple concret** :
> - Lundi 8h : Analyse → 1 alerte
> - Lundi 14h : Analyse → 5 alertes (aggravation !)
> - Mardi 8h : Analyse → 0 alerte (problème résolu)
>
> Avec l'historique, je peux montrer cette évolution au responsable réseau.
>
> **Alternative sans historique** : Un seul fichier `alertes.csv` qui serait écrasé à chaque fois. On perdrait l'historique."

### Question 4: "Pourquoi pas de base de données ?"

**Ta réponse**:

> "J'ai choisi de ne pas utiliser de base de données pour ce projet.
>
> **Raisons** :
> 1. **Simplicité** : Fichiers CSV/JSON plus faciles à comprendre
> 2. **Portabilité** : Pas besoin de configurer MySQL/PostgreSQL
> 3. **Scope du projet** : Quelques rapports, pas des millions
> 4. **Transparence** : On peut ouvrir le CSV dans Excel pour vérifier
>
> **Quand utiliser une BDD ?**
> - Millions d'alertes
> - Requêtes complexes (JOIN, GROUP BY, statistiques avancées)
> - Accès concurrent de plusieurs utilisateurs
> - Historisation sur plusieurs années
>
> Pour ce projet étudiant, les fichiers sont le **bon outil pour le bon usage**."

### Question 5: "C'est quoi `sys.argv` exactement ?"

**Ta réponse**:

> "`sys.argv` est une liste Python qui contient les arguments de la ligne de commande.
>
> **Exemple** :
> ```bash
> python analyse.py data/fichier.txt
> ```
>
> Dans le script :
> - `sys.argv[0]` = `'analyse.py'` (nom du script)
> - `sys.argv[1]` = `'data/fichier.txt'` (premier argument)
> - `len(sys.argv)` = `2` (nombre total d'éléments)
>
> **Mon code** :
> ```python
> if len(sys.argv) > 1:
>     fichier = sys.argv[1]  # Utiliser l'argument
> else:
>     fichier = FICHIER_PAR_DEFAUT  # Utiliser le défaut
> ```
>
> **Analogie** : C'est comme une fonction qui reçoit des paramètres, mais depuis la ligne de commande au lieu du code."

---

## 📝 CHECKLIST AVANT L'ORAL

- [ ] `python analyse_reseau.py` fonctionne
- [ ] Serveur Symfony démarré (`symfony serve`)
- [ ] Au moins 1 rapport généré dans `public/rapports/`
- [ ] Navigateur ouvert sur `localhost:8000`
- [ ] Code source ouvert (Python + Controller)
- [ ] Relire ce guide 30 min avant
- [ ] RESPIRER ET CROIRE EN TOI !

---

## 💡 PHRASES CLÉS À RETENIR

### Sur le code simple:
> "J'ai volontairement gardé un code simple que je peux expliquer ligne par ligne. Pas de librairies complexes, juste du Python et PHP basiques."

### Sur l'historique:
> "Chaque analyse crée un fichier horodaté. C'est comme un journal de bord des incidents réseau."

### Sur Chart.js:
> "Chart.js en CDN : simple, rapide, et parfait pour visualiser les données. Juste un lien, pas d'installation."

### Sur le PDF:
> "`window.print()` avec CSS `@media print`. Fonctionne partout, pas de librairie lourde."

### Si tu bloques:
> "Bonne question, laissez-moi vous montrer dans le code..."

---

## 🎯 OBJECTIF FINAL

À la fin de l'oral, le jury doit penser :

> "Cet étudiant a créé un outil **simple mais fonctionnel**. Il comprend parfaitement ce qu'il a codé. Il a fait des choix techniques intelligents pour son niveau. C'est un excellent travail pour une 1ère année."

---

## 💪 MOTIVATION FINALE

> "Ton code est SIMPLE, mais c'est une FORCE, pas une faiblesse !
>
> Tu peux expliquer chaque ligne. Tu as fait des choix réfléchis. Tu as un projet qui FONCTIONNE.
>
> Le jury ne cherche pas du code complexe. Il cherche un étudiant qui COMPREND ce qu'il fait.
>
> Et toi, tu COMPRENDS. Alors vas-y avec confiance !
>
> TU VAS ASSURER ! 🚀🔥"

---

**Bonne chance pour ta soutenance ! 🍀**
