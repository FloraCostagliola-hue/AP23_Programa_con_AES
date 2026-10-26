 --------------------------------------------------------
    # PREGUNTA 1:
    # ¿Que ocurre si intentamos cifrar el texto plano
    # directamente, sin padding?
    #
    # RESPUESTA:
    # Si su longitud no es multiplo de 16 bytes, PyCryptodome
    # devuelve un ValueError porque ECB cifra bloques completos.
    # --------------------------------------------------------
     --------------------------------------------------------
    # PREGUNTA 2:
    # ¿Cual es el tamano del texto cifrado?
    #
    # RESPUESTA:
    # Es un multiplo de 16 bytes. Con este codigo, el padding
    # se anade solo cuando hace falta completar un bloque.
    # --------------------------------------------------------
    # --------------------------------------------------------
    # PREGUNTA 3:
    # ¿Que ocurre si intentamos cifrar el texto plano en CTR?
    #
    # RESPUESTA:
    # El cifrado funciona aunque el texto no tenga una longitud
    # multiplo de 16 bytes, porque CTR no necesita padding.
    #-------------------------------------------------------
    # --------------------------------------------------------
    # PREGUNTA 4:
    # ¿Cual es el tamano del texto cifrado en CTR?
    #
    # RESPUESTA:
    # Es exactamente igual a la longitud del texto plano,
    # en bytes.
    # --------------------------------------------------------
     --------------------------------------------------------
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