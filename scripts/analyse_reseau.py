#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SAÉ 1.05 - Traiter des Données
Script d'analyse de logs réseau (tcpdump) avec Pandas
Auteur: Étudiant BUT R&T S1
Date: Janvier 2026
"""

import pandas as pd
import re
import os
from datetime import datetime
import argparse
from pathlib import Path


# ============================================================================
# FONCTION 1 : PARSING DES LOGS
# ============================================================================
def parser_logs(chemin_fichier):
    """
    Parse le fichier de logs tcpdump et retourne un DataFrame Pandas.
    
    Cette fonction lit le fichier ligne par ligne, ignore les lignes
    hexadécimales (payload), et extrait les informations clés.
    
    Args:
        chemin_fichier (str): Chemin vers le fichier DumpFile.txt
    
    Returns:
        pd.DataFrame: DataFrame avec colonnes [Heure, Source, IP_Source, Port_Source, 
                                                Destination, IP_Dest, Port_Dest, Flags]
    """
    print(f"[INFO] Lecture du fichier: {chemin_fichier}")
    
    # Regex 1: Paquets TCP avec Flags (SYN, ACK, FIN, etc.)
    # Format: "15:34:04.766656 IP source > destination: Flags [X.]"
    pattern_tcp = re.compile(
        r'^(\d{2}:\d{2}:\d{2})\.\d+\s+'    # Heure (ex: 15:34:04)
        r'IP\s+'                            # Protocole IP
        r'(\S+)\s+'                         # Source (tout jusqu'à l'espace)
        r'>\s+'                             # Séparateur >
        r'(\S+):\s+'                        # Destination (tout jusqu'au :)
        r'.*?Flags\s+\[([^\]]+)\]'          # Flags (ex: [P.], [S], [F])
    )
    
    # Regex 2: Paquets UDP (sans flags TCP)
    # Format: "18:01:29.487415 IP 161.3.129.167.65203 > broadcasthost.gvcp: UDP, length 8"
    pattern_udp = re.compile(
        r'^(\d{2}:\d{2}:\d{2})\.\d+\s+'    # Heure
        r'IP\s+'                            # Protocole IP
        r'(\S+)\s+'                         # Source
        r'>\s+'                             # Séparateur >
        r'(\S+):\s+'                        # Destination
        r'UDP'                              # Protocole UDP
    )
    
    # Regex 3: Requêtes DNS (pour détecter les port scans)
    # Format: "15:34:05.768334 IP BP-Linux8.58466 > ns1.lan.rt.domain: 16550+ PTR?"
    pattern_dns = re.compile(
        r'^(\d{2}:\d{2}:\d{2})\.\d+\s+'    # Heure
        r'IP\s+'                            # Protocole IP
        r'(\S+)\s+'                         # Source
        r'>\s+'                             # Séparateur >
        r'(\S+):\s+'                        # Destination
        r'\d+\+?\s+'                        # ID requête DNS
    )
    
    # Liste pour stocker les données parsées
    donnees = []
    lignes_valides = 0
    lignes_ignorees = 0
    
    # Lecture du fichier ligne par ligne
    with open(chemin_fichier, 'r', encoding='utf-8', errors='ignore') as f:
        for ligne in f:
            # Ignorer les lignes hexadécimales (commencent par tab/espaces + 0x)
            ligne_strip = ligne.strip()
            if ligne_strip.startswith('0x') or ligne.startswith('\t'):
                lignes_ignorees += 1
                continue
            
            # Essayer de matcher avec le pattern TCP (avec flags)
            match = pattern_tcp.match(ligne)
            if match:
                heure = match.group(1)
                source_brute = match.group(2)
                dest_brute = match.group(3)
                flags = match.group(4)
                protocole = 'TCP'
            else:
                # Essayer le pattern UDP
                match = pattern_udp.match(ligne)
                if match:
                    heure = match.group(1)
                    source_brute = match.group(2)
                    dest_brute = match.group(3)
                    flags = 'UDP'  # Pas de flags pour UDP
                    protocole = 'UDP'
                else:
                    # Essayer le pattern DNS
                    match = pattern_dns.match(ligne)
                    if match:
                        heure = match.group(1)
                        source_brute = match.group(2)
                        dest_brute = match.group(3)
                        flags = 'DNS'  # Requête DNS
                        protocole = 'DNS'
                    else:
                        continue  # Ligne non reconnue (ARP, STP, etc.)
            
            # Nettoyer source et destination pour séparer IP/hostname du port
            ip_source, port_source = separer_ip_port(source_brute)
            ip_dest, port_dest = separer_ip_port(dest_brute)
            
            # Ajouter les données à notre liste
            donnees.append({
                'Heure': heure,
                'Source': source_brute,
                'IP_Source': ip_source,
                'Port_Source': port_source,
                'Destination': dest_brute,
                'IP_Dest': ip_dest,
                'Port_Dest': port_dest,
                'Flags': flags,
                'Protocole': protocole
            })
            lignes_valides += 1
    
    print(f"[INFO] {lignes_valides} lignes valides parsées")
    print(f"[INFO] {lignes_ignorees} lignes hexadécimales ignorées")
    
    # Créer le DataFrame Pandas
    df = pd.DataFrame(donnees)
    return df


def separer_ip_port(adresse):
    """
    Sépare une adresse en IP/hostname et port.
    
    Gère les cas suivants:
    - 192.168.190.130.50019 -> ('192.168.190.130', '50019')
    - BP-Linux8.ssh -> ('BP-Linux8', 'ssh')
    - 190-0-175-100.gba.solunet.com.ar.2465 -> ('190-0-175-100.gba.solunet.com.ar', '2465')
    
    Args:
        adresse (str): Adresse brute à parser
    
    Returns:
        tuple: (ip_ou_hostname, port)
    """
    # Pattern pour détecter une IP (4 octets numériques)
    ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(.+)$')
    match_ip = ip_pattern.match(adresse)
    
    if match_ip:
        # C'est une IP suivie d'un port (192.168.1.1.80)
        return match_ip.group(1), match_ip.group(2)
    else:
        # C'est un hostname, le port est après le dernier point
        if '.' in adresse:
            parties = adresse.rsplit('.', 1)
            return parties[0], parties[1]
        else:
            # Pas de séparateur, on retourne tel quel
            return adresse, 'N/A'


# ============================================================================
# FONCTION 2 : DÉTECTION DES ANOMALIES
# ============================================================================
def detecter_anomalies(df):
    """
    Analyse le DataFrame pour détecter 3 types d'anomalies réseau.
    
    Types d'anomalies détectées:
    1. SYN Flood: Nombreux paquets SYN depuis une même IP (seuil: 100)
    2. Port Scan: Une IP scanne plusieurs ports (seuil: 10 ports)
    3. Flags Suspects: Paquets avec flags FIN, PUSH ou URG
    
    Args:
        df (pd.DataFrame): DataFrame contenant les logs réseau
    
    Returns:
        list: Liste de dictionnaires décrivant les anomalies détectées
    """
    print("[INFO] Analyse des anomalies en cours...")
    
    alertes = []
    
    # === ANOMALIE 1 : SYN FLOOD ATTACK ===
    # Le flag 'S' seul (sans '.') indique un paquet SYN pur
    df_syn = df[df['Flags'].str.match('^S$', na=False)]
    
    # Compter le nombre de paquets SYN par IP Source
    syn_par_source = df_syn['IP_Source'].value_counts()
    
    # Seuil de détection: > 100 paquets SYN
    for ip_source, nb_paquets in syn_par_source.items():
        if nb_paquets > 100:
            severite = "CRITIQUE" if nb_paquets > 1000 else "ÉLEVÉE"
            alertes.append({
                'Type': 'SYN Flood Attack',
                'IP_Source': ip_source,
                'Nb_Paquets': nb_paquets,
                'Sévérité': severite,
                'Description': f"L'IP {ip_source} a envoyé {nb_paquets} paquets SYN (attaque par inondation)"
            })
    
    # === ANOMALIE 2 : PORT SCAN ===
    # Grouper par IP Source et compter le nombre de ports différents visés
    ports_par_source = df.groupby('IP_Source')['Port_Dest'].nunique()
    
    # Seuil de détection: > 10 ports différents
    for ip_source, nb_ports in ports_par_source.items():
        if nb_ports > 10:
            severite = "CRITIQUE" if nb_ports > 50 else "ÉLEVÉE"
            alertes.append({
                'Type': 'Port Scan',
                'IP_Source': ip_source,
                'Nb_Ports_Scannés': nb_ports,
                'Sévérité': severite,
                'Description': f"L'IP {ip_source} a scanné {nb_ports} ports différents (reconnaissance réseau)"
            })
    
    print(f"[INFO] {len(alertes)} anomalie(s) détectée(s)")
    return alertes


# ============================================================================
# FONCTION 3 : GÉNÉRATION DES RAPPORTS
# ============================================================================
def generer_rapports(df, alertes, dossier_sortie):
    """
    Génère 3 fichiers de rapport (CSV, JSON, Markdown) dans le dossier spécifié.
    
    Fichiers générés:
    - rapport_YYYYMMDD_HHMMSS.csv (compatible Excel)
    - rapport_YYYYMMDD_HHMMSS.json (pour interface web)
    - rapport_YYYYMMDD_HHMMSS.md (résumé lisible)
    
    Args:
        df (pd.DataFrame): DataFrame des logs réseau
        alertes (list): Liste des anomalies détectées
        dossier_sortie (str): Chemin du dossier où sauvegarder les rapports
    """
    # Créer le dossier de sortie s'il n'existe pas
    Path(dossier_sortie).mkdir(parents=True, exist_ok=True)
    
    # Générer un timestamp pour les noms de fichiers
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # === RAPPORT 1 : CSV (Compatible Excel) ===
    chemin_csv = os.path.join(dossier_sortie, f"rapport_{timestamp}.csv")
    df.to_csv(
        chemin_csv,
        sep=';',               # Séparateur pour Excel français
        encoding='utf-8-sig',  # Encodage avec BOM pour Excel
        index=False            # Ne pas inclure l'index
    )
    print(f"[OK] Rapport CSV généré: {chemin_csv}")
    
    # === RAPPORT 2 : JSON (Pour interface web) ===
    chemin_json = os.path.join(dossier_sortie, f"rapport_{timestamp}.json")
    df.to_json(
        chemin_json,
        orient='records',      # Format: liste de dictionnaires
        indent=2,              # Indentation pour lisibilité
        force_ascii=False      # Conserver les caractères UTF-8
    )
    print(f"[OK] Rapport JSON généré: {chemin_json}")
    
    # === RAPPORT 3 : MARKDOWN (Lisible et structuré) ===
    chemin_md = os.path.join(dossier_sortie, f"rapport_{timestamp}.md")
    
    with open(chemin_md, 'w', encoding='utf-8') as f:
        # En-tête du rapport
        f.write(f"# 📊 Rapport d'Analyse Réseau\n\n")
        f.write(f"**Date de génération:** {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}\n\n")
        f.write(f"---\n\n")
        
        # Résumé de l'analyse
        f.write(f"## 📈 Résumé de l'analyse\n\n")
        f.write(f"- **Nombre total de paquets analysés:** {len(df)}\n")
        f.write(f"- **Nombre d'anomalies détectées:** {len(alertes)}\n")
        
        if not df.empty:
            f.write(f"- **Plage horaire:** {df['Heure'].min()} → {df['Heure'].max()}\n\n")
        
        f.write(f"---\n\n")
        
        # Tableau des alertes
        if alertes:
            f.write(f"## 🚨 Alertes de Sécurité\n\n")
            f.write("| Sévérité | Type | IP Source | Détails |\n")
            f.write("|----------|------|-----------|--------|\n")
            
            for alerte in alertes:
                type_anomalie = alerte['Type']
                ip = alerte['IP_Source']
                severite = alerte['Sévérité']
                
                # Emoji de sévérité
                if severite == 'CRITIQUE':
                    emoji = "🔴"
                elif severite == 'ÉLEVÉE':
                    emoji = "🟠"
                else:
                    emoji = "🟡"
                
                # Détails selon le type d'anomalie
                if 'Nb_Paquets' in alerte:
                    details = f"{alerte['Nb_Paquets']} paquets"
                elif 'Nb_Ports_Scannés' in alerte:
                    details = f"{alerte['Nb_Ports_Scannés']} ports"
                else:
                    details = "N/A"
                
                f.write(f"| {emoji} {severite} | {type_anomalie} | `{ip}` | {details} |\n")
            
            f.write("\n---\n\n")
            
            # Détails des anomalies
            f.write(f"## 📋 Détails des Anomalies\n\n")
            for i, alerte in enumerate(alertes, 1):
                f.write(f"### {i}. {alerte['Type']}\n\n")
                f.write(f"- **Sévérité:** {alerte['Sévérité']}\n")
                f.write(f"- **Description:** {alerte['Description']}\n\n")
        else:
            f.write(f"## ✅ Aucune anomalie détectée\n\n")
            f.write("Le trafic réseau analysé ne présente pas de comportement suspect.\n\n")
        
        # Recommandations
        f.write(f"---\n\n")
        f.write(f"## 💡 Recommandations\n\n")
        
        if alertes:
            severites = [a['Sévérité'] for a in alertes]
            if 'CRITIQUE' in severites:
                f.write("⚠️ **ACTIONS IMMÉDIATES REQUISES:**\n\n")
                f.write("1. Bloquer les adresses IP malveillantes identifiées\n")
                f.write("2. Renforcer les règles de pare-feu\n")
                f.write("3. Contacter l'équipe sécurité réseau en Inde\n\n")
            else:
                f.write("1. Surveiller les IP suspectes identifiées\n")
                f.write("2. Analyser les logs détaillés pour confirmer la menace\n")
                f.write("3. Mettre à jour les règles de détection d'intrusion\n\n")
        else:
            f.write("1. Continuer la surveillance réseau standard\n")
            f.write("2. Maintenir les sauvegardes régulières des logs\n\n")
        
        # Pied de page
        f.write("---\n\n")
        f.write("*Rapport généré par le script SAÉ 1.05 - BUT R&T*\n")
    
    print(f"[OK] Rapport Markdown généré: {chemin_md}")


# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================
def main():
    """
    Fonction principale qui orchestre l'analyse réseau.
    
    Étapes:
    1. Lire les arguments en ligne de commande
    2. Parser le fichier de logs
    3. Détecter les anomalies
    4. Générer les rapports
    """
    # === GESTION DES ARGUMENTS EN LIGNE DE COMMANDE ===
    parser = argparse.ArgumentParser(
        description="Analyse de logs réseau pour SAÉ 1.05 (BUT R&T)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python analyse_reseau.py
  python analyse_reseau.py --fichier ../data/DumpFile.txt
  python analyse_reseau.py -f ../data/MonAutreLog.txt
        """
    )
    
    parser.add_argument(
        '-f', '--fichier',
        default='../data/DumpFile.txt',
        help='Chemin vers le fichier de logs tcpdump (défaut: ../data/DumpFile.txt)'
    )
    
    args = parser.parse_args()
    
    # === VÉRIFICATION DE L'EXISTENCE DU FICHIER ===
    if not os.path.exists(args.fichier):
        print(f"[ERREUR] Le fichier '{args.fichier}' n'existe pas!")
        print("Vérifiez le chemin et réessayez.")
        return
    
    # === AFFICHAGE DE L'EN-TÊTE ===
    print("=" * 60)
    print("     SAÉ 1.05 - ANALYSE DE LOGS RÉSEAU (TCPDUMP)")
    print("=" * 60)
    print()
    
    # === ÉTAPE 1 : PARSING DES LOGS ===
    try:
        df = parser_logs(args.fichier)
        
        if df.empty:
            print("[ERREUR] Aucune donnée valide trouvée dans le fichier!")
            return
        
        print(f"\n[OK] DataFrame créé avec {len(df)} lignes")
        print("\nAperçu des 5 premières lignes:")
        print(df.head().to_string())
        
    except Exception as e:
        print(f"[ERREUR] Problème lors du parsing: {e}")
        return
    
    # === ÉTAPE 2 : DÉTECTION DES ANOMALIES ===
    print("\n" + "-" * 60)
    try:
        alertes = detecter_anomalies(df)
    except Exception as e:
        print(f"[ERREUR] Problème lors de la détection: {e}")
        return
    
    # === ÉTAPE 3 : GÉNÉRATION DES RAPPORTS ===
    print("\n" + "-" * 60)
    
    # Créer un sous-dossier avec le nom du fichier analysé (sans extension)
    nom_fichier = Path(args.fichier).stem  # ex: "DumpFile" ou "fichier182"
    dossier_rapports = f'../rapports/{nom_fichier}'
    
    try:
        generer_rapports(df, alertes, dossier_rapports)
    except Exception as e:
        print(f"[ERREUR] Problème lors de la génération des rapports: {e}")
        return
    
    # === RÉSUMÉ FINAL ===
    print("\n" + "=" * 60)
    print("                    ANALYSE TERMINÉE")
    print("=" * 60)
    print(f"\n✅ {len(df)} paquets analysés")
    print(f"⚠️  {len(alertes)} anomalie(s) détectée(s)")
    print(f"📁 Rapports sauvegardés dans: {dossier_rapports}/")
    print()


# Point d'entrée du script
if __name__ == "__main__":
    main()
