
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ============================================================
# AP 23 - PROGRAMA CON AES
# ============================================================
#
# AES es un algoritmo de cifrado simetrico.
# Utiliza la misma clave para cifrar y descifrar.
#
# AES admite claves de:
# - 128 bits = 16 bytes
# - 192 bits = 24 bytes
# - 256 bits = 32 bytes
#
# El tamano de bloque de AES siempre es de 16 bytes,
# independientemente del tamano de la clave.
# ============================================================


def aes_mode_ecb_basic(texto_plano, clave_cifrado):
    """
    Cifra un mensaje utilizando AES en modo ECB.
    ECB necesita que el texto tenga una longitud multiplo
    de 16 bytes. Por eso, en este ejemplo anadimos padding.
    """

    print("\n========== AES MODO ECB ==========")

    # --------------------------------------------------------
    # PREGUNTA 1:
    # ¿Que ocurre si intentamos cifrar el texto plano
    # directamente, sin padding?
    #
    # RESPUESTA:
    # Si su longitud no es multiplo de 16 bytes, PyCryptodome
    # devuelve un ValueError porque ECB cifra bloques completos.
    # --------------------------------------------------------

    try:
        algoritmo = AES.new(clave_cifrado, AES.MODE_ECB)
        algoritmo.encrypt(texto_plano)
        print("El cifrado directo ha funcionado.")
    except ValueError as error:
        print(f"Error al cifrar sin padding: {error}")

    # --------------------------------------------------------
    # Anadir padding con bytes nulos.
    # Repetimos hasta que la longitud sea multiplo de 16
    # --------------------------------------------------------

    texto_padding = texto_plano

    while len(texto_padding) % AES.block_size != 0:
        texto_padding += b"\x00"

    print(f"\nTexto plano en bytes: {texto_plano}")
    print(f"Texto con padding: {texto_padding}")
    print(f"Longitud con padding: {len(texto_padding)} bytes")

    # Cifrar el texto con padding
    algoritmo = AES.new(clave_cifrado, AES.MODE_ECB)
    texto_cifrado = algoritmo.encrypt(texto_padding)

    print(f"Texto cifrado ECB (hex): {texto_cifrado.hex()}")
    print(f"Longitud cifrado ECB: {len(texto_cifrado)} bytes")

    # --------------------------------------------------------
    # PREGUNTA 2:
    # ¿Cual es el tamano del texto cifrado?
    #
    # RESPUESTA:
    # Es un multiplo de 16 bytes. Con este codigo, el padding
    # se anade solo cuando hace falta completar un bloque.
    # --------------------------------------------------------

    return texto_cifrado


def aes_mode_ctr(texto_plano, clave_cifrado):
    """
    Cifra un mensaje utilizando AES en modo CTR.
    No necesita padding y permite cifrar mensajes de cualquier
    longitud.
    """

    print("\n========== AES MODO CTR ==========")

    # PyCryptodome genera un nonce para CTR si no se especifica.
    # Hay que conservarlo para poder descifrar posteriormente.
    algoritmo = AES.new(clave_cifrado, AES.MODE_CTR)
    texto_cifrado = algoritmo.encrypt(texto_plano)

    print(f"Texto cifrado CTR (hex): {texto_cifrado.hex()}")
    print(f"Longitud cifrado CTR: {len(texto_cifrado)} bytes")

    # --------------------------------------------------------
    # PREGUNTA 3:
    # ¿Que ocurre si intentamos cifrar el texto plano en CTR?
    #
    # RESPUESTA:
    # El cifrado funciona aunque el texto no tenga una longitud
    # multiplo de 16 bytes, porque CTR no necesita padding.
    #
    # PREGUNTA 4:
    # ¿Cual es el tamano del texto cifrado en CTR?
    #
    # RESPUESTA:
    # Es exactamente igual a la longitud del texto plano,
    # en bytes.
    # --------------------------------------------------------

    return texto_cifrado, algoritmo.nonce


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # PARTE 1:
    # La clave original de la practica tiene 16 bytes:
    # 16 * 8 = 128 bits.
    # --------------------------------------------------------

    clave_128 = b'A\x83\xbeU\xd7\xa9b\x18\x85AN0\xbft\xc3\xab'

    mensaje = input("Introduce un mensaje para Bob: ")
    texto_plano = mensaje.encode("utf-8")

    print("\n========== DATOS DEL MENSAJE ==========")
    print(f"Texto original: {mensaje}")
    print(f"Longitud del texto plano: {len(texto_plano)} bytes")
    print(f"Longitud de la clave: {len(clave_128) * 8} bits")

    # Ejecutar ECB y CTR con clave de 128 bits
    aes_mode_ecb_basic(texto_plano, clave_128)
    aes_mode_ctr(texto_plano, clave_128)

    # --------------------------------------------------------
    # PARTE 2:
    # Aumentamos la clave a 256 bits.
    #
    # 32 bytes * 8 = 256 bits.
    #
    # Se genera una clave aleatoria nueva. En un programa real,
    # habria que guardarla de forma segura para poder descifrar.
    # --------------------------------------------------------

    print("\n========== PARTE 2: CLAVE DE 256 BITS ==========")

    clave_256 = get_random_bytes(32)

    print(f"Longitud de la nueva clave: {len(clave_256) * 8} bits")

    # Cifrar el mismo texto con ambos modos y clave de 256 bits
    cifrado_ecb_256 = aes_mode_ecb_basic(texto_plano, clave_256)
    cifrado_ctr_256, nonce_ctr_256 = aes_mode_ctr(
        texto_plano, clave_256
    )

    # --------------------------------------------------------
    # PREGUNTA 5:
    # ¿Que diferencias hay en el tamano del texto cifrado
    # entre ECB y CTR con una clave de 256 bits?
    #
    # RESPUESTA:
    # ECB produce una longitud multiplo de 16 bytes porque
    # utiliza bloques completos y este programa anade padding
    # con bytes nulos cuando es necesario.
    #
    # CTR produce un cifrado de la misma longitud que el
    # texto plano. No necesita padding.
    #
    # Cambiar la clave de 128 a 256 bits NO cambia estas reglas.
    # --------------------------------------------------------

    print("\n========== COMPARACION FINAL ==========")
    print(f"Texto plano: {len(texto_plano)} bytes")
    print(f"ECB con clave de 256 bits: {len(cifrado_ecb_256)} bytes")
    print(f"CTR con clave de 256 bits: {len(cifrado_ctr_256)} bytes")
    print(f"Nonce CTR (hex): {nonce_ctr_256.hex()}")

    # NOTA DE SEGURIDAD:
    # No reutilices el mismo nonce con la misma clave en CTR.
    # ECB no proporciona confidencialidad adecuada para datos
    # estructurados y ninguno de estos modos autentica por si
    # solo el mensaje. Para aplicaciones reales, considera AES-GCM.
