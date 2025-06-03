# BruteForce-Auto-Script-GUI
Brute Force script GUI
# Multi Protocol Attack GUI — Documentation Utilisateur
#Prérequis
Avant d’exécuter le script, assurez-vous d’avoir les dépendances suivantes installées :

pip install paramiko pysmb

#Fichiers requis
users.txt : liste des noms d’utilisateurs à tester (un par ligne)

passwords.txt : liste des mots de passe à tester (un par ligne)

Le script Python (.py) ou l'exécutable

Facultatif : vous pouvez aussi définir votre propre fichier rapport.txt

 #Lancement du programme
➤ Via Python
BruteForce Auto Script GUI.py
➤ Via l’exécutable
BruteForce Auto Script GUI.exe
#Fonctionnalités
#Interface graphique (GUI)
L’interface s’ouvre automatiquement si un environnement graphique est détecté (DISPLAY sur Linux, ou Windows GUI).

Champs de saisie :
Adresse IP / Host : IP ou nom de domaine de la cible

Protocole : SSH, Telnet, FTP, SMB

Fichier utilisateurs : sélectionner le fichier users.txt

Fichier mots de passe : sélectionner le fichier passwords.txt

Type d’attaque : (actuellement disponible : Brute force)

Bouton :
Démarrer l'attaque : lance la tentative de connexion pour chaque couple utilisateur/mot de passe.
