# ENCRIPTADO
Repositorio para el código de las prácticas de la Asignatura de TEORÍA DE CÓDIGOS Y CRIPTOGRAFÍA

graph TD
    A[Inicio] --> B[Configuración inicial]
    B --> C{Fuente de audio}
    C -->|Micrófono| D[Captura audio del mic]
    C -->|Archivo| E[Lee audio del archivo]
    D --> F[Empaqueta datos]
    E --> F
    F --> G[Envía por UDP]
    H[Recibe datos UDP] --> I[Desempaqueta]
    I --> J[Reproduce audio]
    
    subgraph Estadísticas y Visualización
    K[Muestra estadísticas] 
    L[Visualización espectro]
    end
