from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


def ajustar_clave(nombre, key, longitud):
    key_bytes = key.encode('utf-8')

    if len(key_bytes) < longitud:
        faltan = longitud - len(key_bytes)
        relleno = get_random_bytes(faltan)
        key_bytes += relleno
        print(f"  [warning] {nombre} demasiado corta. Se añadieron {faltan} bytes aleatorios.")
    elif len(key_bytes) > longitud:
        key_bytes = key_bytes[:longitud]
        print(f"  [warning] {nombre} demasiado larga. Se truncó a {longitud} bytes.")
    else:
        print(f"  [OK] {nombre} tiene la longitud correcta ({longitud} bytes).")

    print(f"  {nombre} final utilizada (Hex): {key_bytes.hex().upper()}")
    return key_bytes


def cifrar_y_descifrar(algoritmo, key, iv, texto):
    data = texto.encode('utf-8')

    if algoritmo == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, DES.block_size))
        decipher = DES.new(key, DES.MODE_CBC, iv)
        plain = unpad(decipher.decrypt(ciphertext), DES.block_size)

    elif algoritmo == '3DES':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, DES3.block_size))
        decipher = DES3.new(key, DES3.MODE_CBC, iv)
        plain = unpad(decipher.decrypt(ciphertext), DES3.block_size)

    elif algoritmo == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        decipher = AES.new(key, AES.MODE_CBC, iv)
        plain = unpad(decipher.decrypt(ciphertext), AES.block_size)

    else:
        raise ValueError("Algoritmo no válido.")

    return base64.b64encode(ciphertext).decode('utf-8'), plain.decode('utf-8')


def main():
    print("1. DES (clave de 8 bytes, IV de 8 bytes)")
    print("2. 3DES (clave de 24 bytes, IV de 8 bytes)")
    print("3. AES-256 (clave de 32 bytes, IV de 16 bytes)")

    opcion = input("Selecciona el algoritmo (1, 2 o 3): ").strip()

    if opcion == '1':
        algoritmo = 'DES'
        key_len, iv_len = 8, 8
    elif opcion == '2':
        algoritmo = '3DES'
        key_len, iv_len = 24, 8
    elif opcion == '3':
        algoritmo = 'AES'
        key_len, iv_len = 32, 16
    else:
        print("Opción no válida.")
        return

    print(f"\n🔑 Has elegido {algoritmo}")
    print(f"La clave debe tener {key_len} bytes.")
    print(f"El vector de inicialización (IV) debe tener {iv_len} bytes.\n")

    key_input = input("Ingrese la clave: ")
    iv_input = input("Ingrese el IV: ")
    texto = input("Ingrese el texto a cifrar: ")

    key = ajustar_clave("Clave", key_input, key_len)
    iv = ajustar_clave("IV", iv_input, iv_len)


    cifrado, descifrado = cifrar_y_descifrar(algoritmo, key, iv, texto)

    print(f" Texto cifrado (Base64): {cifrado}")
    print(f"Texto descifrado: {descifrado}")



if __name__ == "__main__":
    main()
