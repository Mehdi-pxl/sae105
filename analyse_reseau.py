#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SAÉ 1.05 - Analyse de Logs Réseau (VERSION SIMPLE)
Auteur: Étudiant BUT R&T 1ère année
Contexte: Détection d'anomalies réseau entre le site France et le site Inde

UTILISATION SIMPLE:
    python analyse_reseau.py                    # Utilise le fichier par défaut
    python analyse_reseau.py data/fichier.txt   # Analyse un fichier spécifique
"""

import re
import sys
import os
import json
from datetime import datetime
from collections import defaultdict

# ============================================================================
# CONFIGURATION
# ============================================================================

# Fichier par défaut si l'utilisateur n'en donne pas
FICHIER_PAR_DEFAUT = '2025-SAE-main/DumpFile.txt'

# Seuil pour détecter une attaque SYN flood
SEUIL_SYN_FLOOD = 100

# Heures normales de travail (8h-18h en Inde)
HEURE_DEBUT_NORMALE = 8
HEURE_FIN_NORMALE = 18

# Dossier où sauvegarder les rapports
DOSSIER_RAPPORTS = 'sae-monitoring/public/rapports'

# ============================================================================
# FONCTION 1: LIRE LE FICHIER DE LOGS
# ============================================================================

def lire_fichier(chemin):
    """
    Lit le fichier de logs ligne par ligne.
    
    Explication simple:
    On ouvre le fichier et on lit toutes les lignes dedans.
    """
    print(f"📂 Lecture du fichier: {chemin}")
    
    try:
        # Ouvrir le fichier en lecture
        with open(chemin, 'r', encoding='utf-8', errors='ignore') as fichier:
            lignes = fichier.readlines()
        
        print(f"✅ {len(lignes)} lignes lues")
        return lignes
    
    except FileNotFoundError:
        print(f"❌ Erreur: Le fichier {chemin} n'existe pas")
        return []

# ============================================================================
# FONCTION 2: EXTRAIRE LES INFOS D'UNE LIGNE
# ============================================================================

def extraire_infos(ligne):
    """
    Extrait les informations importantes d'une ligne de log.
    """
    infos = {
        'timestamp': None,
        'ip_source': None,
        'ip_dest': None,
        'port_dest': None,
        'flags': None,
        'flags_suspects': [],
        'payload_suspect': False
    }
    
    # Chercher l'heure (exemple: 15:34:04)
    match_time = re.search(r'(\d{2}:\d{2}:\d{2})', ligne)
    if match_time:
        infos['timestamp'] = match_time.group(1)
    
    # Chercher les IPs et ports
    match_ip = re.search(r'IP\s+([\w\-\.]+)\.(\w+)\s+>\s+([\w\-\.]+)\.(\w+)', ligne)
    if match_ip:
        infos['ip_source'] = match_ip.group(1)
        infos['ip_dest'] = match_ip.group(3)
        infos['port_dest'] = match_ip.group(4)
    
    # Chercher les flags TCP
    if 'Flags [S]' in ligne or 'Flags [S.]' in ligne:
        infos['flags'] = 'SYN'
    
    # Détecter flags suspects
    if 'Flags [F]' in ligne or 'Flags [F.]' in ligne:
        infos['flags_suspects'].append('FIN')
    if 'Flags [R]' in ligne or 'Flags [R.]' in ligne:
        infos['flags_suspects'].append('RST')
    if 'Flags [P]' in ligne or 'Flags [P.]' in ligne:
        infos['flags_suspects'].append('PSH')
    if 'Flags [U]' in ligne:
        infos['flags_suspects'].append('URG')
    # NULL scan (aucun flag)
    if 'Flags [none]' in ligne or 'Flags []' in ligne:
        infos['flags_suspects'].append('NULL')
    # XMAS scan (FIN+PSH+URG)
    if 'Flags [FPU]' in ligne:
        infos['flags_suspects'].append('XMAS')
    
    # Chercher payload suspect (XXXX répété)
    if 'XXXX' in ligne or '5858 5858' in ligne:
        infos['payload_suspect'] = True
    
    return infos

# ============================================================================
# FONCTION 3: ANALYSER LES LOGS
# ============================================================================

def analyser_logs(lignes):
    """
    Analyse toutes les lignes et trouve les anomalies.
    """
    print("\n🔍 Analyse en cours...")
    
    # Compteurs
    compteur_syn = defaultdict(int)
    ips_suspectes = set()
    connexions_par_heure = defaultdict(int)
    ports_par_ip = defaultdict(set)
    flags_suspects_par_ip = defaultdict(lambda: defaultdict(int))
    
    # Timestamps (première occurrence)
    premiere_occurrence_syn = {}
    premiere_occurrence_port = {}
    premiere_occurrence_flags = {}
    
    # Parcourir toutes les lignes
    for i, ligne in enumerate(lignes):
        if i % 50000 == 0 and i > 0:
            print(f"   {i}/{len(lignes)} lignes...")
        
        infos = extraire_infos(ligne)
        
        if infos['ip_source']:
            # Compter les SYN
            if infos['flags'] == 'SYN':
                compteur_syn[infos['ip_source']] += 1
                # Sauvegarder la première occurrence
                if infos['ip_source'] not in premiere_occurrence_syn and infos['timestamp']:
                    premiere_occurrence_syn[infos['ip_source']] = infos['timestamp']
            
            # Marquer les IPs suspectes
            if infos['payload_suspect']:
                ips_suspectes.add(infos['ip_source'])
            
            # Compter par heure
            if infos['timestamp']:
                heure = int(infos['timestamp'].split(':')[0])
                connexions_par_heure[heure] += 1
            
            # Détecter port scan
            if infos['port_dest']:
                if infos['ip_source'] not in premiere_occurrence_port and infos['timestamp']:
                    premiere_occurrence_port[infos['ip_source']] = infos['timestamp']
                ports_par_ip[infos['ip_source']].add(infos['port_dest'])
            
            # Compter les flags suspects
            for flag in infos['flags_suspects']:
                if infos['ip_source'] not in premiere_occurrence_flags and infos['timestamp']:
                    premiere_occurrence_flags[infos['ip_source']] = infos['timestamp']
                flags_suspects_par_ip[infos['ip_source']][flag] += 1
    
    print(f"✅ Analyse terminée")
    
    # Créer les alertes
    alertes = []
    
    # ANOMALIE 1: SYN Flood
    print("\n🚨 Recherche d'attaques SYN Flood...")
    for ip, nombre_syn in compteur_syn.items():
        if nombre_syn > SEUIL_SYN_FLOOD:
            if nombre_syn > 1000:
                severite = "CRITIQUE"
            elif nombre_syn > 500:
                severite = "ÉLEVÉE"
            else:
                severite = "MOYENNE"
            
            payload_info = " (Payload XXXX)" if ip in ips_suspectes else ""
            timestamp = premiere_occurrence_syn.get(ip, "Unknown")
            
            alertes.append({
                'type': 'SYN Flood Attack',
                'ip_source': ip,
                'ip_dest': 'Multiple targets',
                'port': 'Various',
                'timestamp': timestamp,
                'severite': severite,
                'description': f"{nombre_syn} paquets SYN{payload_info}"
            })
            print(f"   ⚠️  {ip}: {nombre_syn} SYN - {severite}")
    
    # ANOMALIE 2: Port Scan
    print("\n🔍 Recherche de port scans...")
    for ip, ports in ports_par_ip.items():
        nombre_ports = len(ports)
        if nombre_ports > 10:
            if nombre_ports > 50:
                severite = "CRITIQUE"
            elif nombre_ports > 25:
                severite = "ÉLEVÉE"
            else:
                severite = "MOYENNE"
            
            timestamp = premiere_occurrence_port.get(ip, "Unknown")
            
            alertes.append({
                'type': 'Port Scan',
                'ip_source': ip,
                'ip_dest': 'Multiple targets',
                'port': f'{nombre_ports} ports',
                'timestamp': timestamp,
                'severite': severite,
                'description': f"Scan de {nombre_ports} ports différents"
            })
            print(f"   ⚠️  {ip}: {nombre_ports} ports scannés - {severite}")
    
    # ANOMALIE 3: Flags TCP suspects
    print("\n🚩 Recherche de flags TCP suspects...")
    for ip, flags_dict in flags_suspects_par_ip.items():
        total_flags = sum(flags_dict.values())
        if total_flags > 50:
            flags_list = ', '.join([f"{flag}:{count}" for flag, count in flags_dict.items()])
            
            if total_flags > 200:
                severite = "CRITIQUE"
            elif total_flags > 100:
                severite = "ÉLEVÉE"
            else:
                severite = "MOYENNE"
            
            timestamp = premiere_occurrence_flags.get(ip, "Unknown")
            
            alertes.append({
                'type': 'Suspicious TCP Flags',
                'ip_source': ip,
                'ip_dest': 'Multiple targets',
                'port': 'Various',
                'timestamp': timestamp,
                'severite': severite,
                'description': f"{total_flags} paquets avec flags suspects ({flags_list})"
            })
            print(f"   ⚠️  {ip}: {total_flags} flags suspects - {severite}")
    
    # ANOMALIE 4: Horaires anormaux
    print("\n🕐 Recherche de connexions hors horaires...")
    connexions_anormales = sum(
        count for heure, count in connexions_par_heure.items()
        if heure < HEURE_DEBUT_NORMALE or heure >= HEURE_FIN_NORMALE
    )
    
    if connexions_anormales > 100:
        alertes.append({
            'type': 'Abnormal Timing',
            'ip_source': 'Various',
            'ip_dest': 'Various',
            'port': 'Various',
            'timestamp': f'Outside {HEURE_DEBUT_NORMALE}h-{HEURE_FIN_NORMALE}h',
            'severite': 'MOYENNE',
            'description': f"{connexions_anormales} connexions hors horaires"
        })
        print(f"   ⚠️  {connexions_anormales} connexions anormales")
    
    print(f"\n📊 Total: {len(alertes)} anomalies détectées")
    
    return alertes, len(lignes), len(compteur_syn)

# ============================================================================
# FONCTION 4: CRÉER LE NOM DE FICHIER HORODATÉ
# ============================================================================

def creer_nom_rapport():
    """
    Crée un nom unique avec la date et l'heure.
    
    Exemple: rapport_20260112_083045
    
    Explication simple:
    On prend la date et l'heure actuelle et on les met dans le nom.
    Comme ça, chaque rapport a un nom différent.
    """
    maintenant = datetime.now()
    nom = maintenant.strftime("rapport_%Y%m%d_%H%M%S")
    return nom, maintenant

def nettoyer_anciens_rapports():
    """
    Supprime tous les anciens rapports pour ne garder que le nouveau.
    """
    print("\n🗑️  Nettoyage des anciens rapports...")
    
    if not os.path.exists(DOSSIER_RAPPORTS):
        return
    
    fichiers = os.listdir(DOSSIER_RAPPORTS)
    nombre_supprimes = 0
    
    for fichier in fichiers:
        chemin_complet = os.path.join(DOSSIER_RAPPORTS, fichier)
        if os.path.isfile(chemin_complet):
            os.remove(chemin_complet)
            nombre_supprimes += 1
    
    if nombre_supprimes > 0:
        print(f"✅ {nombre_supprimes} fichiers supprimés")
    else:
        print("✅ Aucun ancien fichier à supprimer")

# ============================================================================
# FONCTION 5: SAUVEGARDER EN CSV
# ============================================================================

def sauvegarder_csv(alertes, nom_fichier):
    """
    Sauvegarde les alertes dans un fichier CSV.
    
    Explication simple:
    On écrit les alertes dans un fichier texte avec des point-virgules.
    Excel peut ouvrir ce format facilement.
    """
    print(f"\n💾 Sauvegarde CSV: {nom_fichier}")
    
    # Créer le dossier s'il n'existe pas
    dossier = os.path.dirname(nom_fichier)
    if not os.path.exists(dossier):
        os.makedirs(dossier)
        print(f"   📁 Dossier créé: {dossier}")
    
    # Écrire le fichier
    with open(nom_fichier, 'w', encoding='utf-8') as f:
        # En-tête
        f.write('Type;IP Source;IP Destination;Port;Timestamp;Sévérité;Description\n')
        
        # Données
        for alerte in alertes:
            ligne = ';'.join([
                alerte['type'],
                alerte['ip_source'],
                alerte['ip_dest'],
                alerte['port'],
                alerte['timestamp'],
                alerte['severite'],
                alerte['description']
            ]) + '\n'
            f.write(ligne)
    
    print(f"✅ CSV sauvegardé")

# ============================================================================
# FONCTION 6: SAUVEGARDER EN JSON
# ============================================================================

def sauvegarder_json(alertes, nom_fichier, fichier_source, total_lignes, ips_uniques, date_analyse):
    """
    Sauvegarde un résumé en JSON.
    """
    print(f"\n💾 Sauvegarde JSON: {nom_fichier}")
    
    # Créer le résumé texte
    resume_texte = []
    
    for alerte in alertes:
        if alerte['type'] == 'SYN Flood Attack':
            resume_texte.append(f"⚠️ ALERTE {alerte['severite']} : IP {alerte['ip_source']}")
            resume_texte.append(f"📊 {alerte['description']}")
        elif alerte['type'] == 'Port Scan':
            resume_texte.append(f"🔍 ALERTE {alerte['severite']} : IP {alerte['ip_source']}")
            resume_texte.append(f"📊 {alerte['description']}")
        elif alerte['type'] == 'Suspicious TCP Flags':
            resume_texte.append(f"🚩 ALERTE {alerte['severite']} : IP {alerte['ip_source']}")
            resume_texte.append(f"📊 {alerte['description']}")
        elif alerte['type'] == 'Abnormal Timing':
            resume_texte.append(f"🕐 {alerte['description']}")
    
    # Créer l'objet JSON
    resume = {
        "date_analyse": date_analyse.strftime("%d/%m/%Y %H:%M:%S"),
        "fichier_source": fichier_source,
        "nombre_alertes": len(alertes),
        "resume_texte": resume_texte,
        "statistiques": {
            "total_lignes": total_lignes,
            "ips_uniques": ips_uniques,
            "severite_max": max([a['severite'] for a in alertes]) if alertes else "AUCUNE"
        }
    }
    
    # Écrire le fichier
    with open(nom_fichier, 'w', encoding='utf-8') as f:
        json.dump(resume, f, ensure_ascii=False, indent=2)
    
    print(f"✅ JSON sauvegardé")

# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

def main():
    """
    Fonction principale du programme.
    
    Explication simple:
    C'est le chef d'orchestre. Il appelle toutes les autres fonctions
    dans le bon ordre.
    """
    print("=" * 70)
    print("  SAÉ 1.05 - ANALYSE DE LOGS RÉSEAU")
    print("=" * 70)
    
    # ÉTAPE 1: Récupérer le nom du fichier
    # Si l'utilisateur donne un fichier, on l'utilise
    # Sinon, on utilise le fichier par défaut
    if len(sys.argv) > 1:
        fichier = sys.argv[1]
        print(f"📋 Fichier spécifié: {fichier}")
    else:
        fichier = FICHIER_PAR_DEFAUT
        print(f"📋 Fichier par défaut: {fichier}")
    
    # ÉTAPE 2: Lire le fichier
    lignes = lire_fichier(fichier)
    if not lignes:
        print("❌ Impossible de continuer")
        return
    
    # ÉTAPE 3: Analyser les logs
    alertes, total_lignes, ips_uniques = analyser_logs(lignes)
    
    # ÉTAPE 4: Nettoyer les anciens rapports
    nettoyer_anciens_rapports()
    
    # ÉTAPE 5: Créer le nom du rapport
    nom_rapport, date_analyse = creer_nom_rapport()
    print(f"\n📝 Nom du rapport: {nom_rapport}")
    
    # ÉTAPE 5: Sauvegarder les fichiers
    csv_path = os.path.join(DOSSIER_RAPPORTS, nom_rapport + '.csv')
    json_path = os.path.join(DOSSIER_RAPPORTS, nom_rapport + '.json')
    
    if alertes:
        sauvegarder_csv(alertes, csv_path)
        sauvegarder_json(alertes, json_path, fichier, total_lignes, ips_uniques, date_analyse)
    else:
        print("\n✅ Aucune anomalie détectée")
        # Créer quand même les fichiers vides
        sauvegarder_csv([], csv_path)
        sauvegarder_json([], json_path, fichier, total_lignes, ips_uniques, date_analyse)
    
    # ÉTAPE 6: Afficher le résumé
    print("\n" + "=" * 70)
    print("  RÉSUMÉ")
    print("=" * 70)
    for alerte in alertes:
        print(f"\n🔴 {alerte['type']}")
        print(f"   Sévérité: {alerte['severite']}")
        print(f"   {alerte['description']}")
    
    print("\n" + "=" * 70)
    print("  TERMINÉ")
    print("=" * 70)
    print(f"\n📊 Rapports créés:")
    print(f"   - {csv_path}")
    print(f"   - {json_path}")
    print(f"\n🌐 Voir les résultats:")
    print(f"   cd sae-monitoring && symfony serve")
    print(f"   Ouvrir: http://localhost:8000")
    print("=" * 70)

# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if __name__ == '__main__':
    """
    Point d'entrée du programme.
    
    Explication simple:
    Quand on lance "python analyse_reseau.py", c'est ici que ça commence.
    """
    main()
