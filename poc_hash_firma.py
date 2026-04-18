# -*- coding: utf-8 -*-
"""
PoC: Hash y Firma Digital en Python
Requiere: Python 3.x
Dependencias: cryptography

Este script realiza:
1. Generación de hash con SHA-256
2. Generación de hash con SHA-512
3. Generación de claves RSA
4. Firma digital del mensaje con la clave privada
5. Verificación de la firma con la clave pública
"""

# Importa funciones para generar hashes
import hashlib

# Importa funciones para generar claves RSA y realizar firma digital
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Importa funciones hash de la librería cryptography para la firma
from cryptography.hazmat.primitives import hashes, serialization

# Backend criptográfico por defecto
from cryptography.hazmat.backends import default_backend


def generar_hashes(mensaje):
    """
    Genera dos hashes del mismo mensaje:
    - SHA-256
    - SHA-512
    """
    print("🔎 GENERACIÓN DE HASHES")
    print(f"📨 Mensaje original: {mensaje}")

    # Convierte el mensaje de texto a bytes
    mensaje_bytes = mensaje.encode()

    # Genera hash SHA-256
    hash_sha256 = hashlib.sha256(mensaje_bytes).hexdigest()
    print(f"🔐 Hash SHA-256: {hash_sha256}")

    # Genera hash SHA-512
    hash_sha512 = hashlib.sha512(mensaje_bytes).hexdigest()
    print(f"🔐 Hash SHA-512: {hash_sha512}")

    print()
    return hash_sha256, hash_sha512


def firma_digital(mensaje):
    """
    Genera un par de claves RSA, firma digitalmente el mensaje
    con la clave privada y luego verifica la firma con la clave pública.
    """
    print("✍️ FIRMA DIGITAL CON RSA-2048")

    # Genera la clave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # A partir de la clave privada se obtiene la clave pública
    public_key = private_key.public_key()

    # Convierte las claves a formato PEM para poder visualizarlas
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("🔑 Clave pública (PEM):")
    print(public_pem.decode())

    print("🔐 Clave privada (PEM):")
    print(private_pem.decode())

    # Convierte el mensaje a bytes para poder firmarlo
    mensaje_bytes = mensaje.encode()

    # Firma digital del mensaje usando la clave privada
    firma = private_key.sign(
        mensaje_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print(f"📨 Mensaje firmado: {mensaje}")
    print(f"🖊️ Firma digital (hex): {firma.hex()[:100]}...")

    # Verificación de la firma con la clave pública
    try:
        public_key.verify(
            firma,
            mensaje_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✅ Verificación de firma: válida")
    except Exception:
        print("❌ Verificación de firma: inválida")

    print()


if __name__ == "__main__":
    # Mensaje de prueba
    mensaje = "Hola Blockchain"

    # Llamada a la función de hashes
    generar_hashes(mensaje)

    # Llamada a la función de firma digital
    firma_digital(mensaje)