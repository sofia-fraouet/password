import random
import string
import hashlib

def check_password_strength(password):
    # Vérifie si le mot de passe répond aux exigences de sécurité
    if len(password) < 8 or \
            not any(c.isupper() for c in password) or \
            not any(c.islower() for c in password) or \
            not any(c.isdigit() for c in password) or \
            not any(c in '!@#$%^&*()_+-={}[]|<\:;"\'>,.?/' for c in password):
        return False
    return True

def get_valid_password():
    while True:
        password = input("Veuillez entrer un mot de passe : ")
        if check_password_strength(password):
            return password
        else:
            print("Le mot de passe ne respecte pas les exigences de sécurité. Veuillez réessayer. Le mot de passe doit contenir huit caractères, une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial")

def hash_password(password):
    # Utilise l'algorithme SHA-256 pour crypter le mot de passe
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def main():
    print("Bienvenue !")
    valid_password = get_valid_password()
    hashed_password = hash_password(valid_password)
    
    print("Mot de passe valide !")
    print("Mot de passe crypté (SHA-256) :", hashed_password)

if __name__ == "__main__":
    main()


