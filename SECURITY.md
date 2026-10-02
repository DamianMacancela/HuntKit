# Security Policy

## Versiones soportadas

| Versión | Soporte activo |
|---------|----------------|
| 0.1.x   | Sí             |

## Cómo reportar una vulnerabilidad

Si descubres un problema de seguridad en HuntKit (por ejemplo, una regla de detección que puede ser bypasseada de forma trivial, o un bug que cause comportamiento inesperado con privilegios elevados), **no lo hagas público como issue de GitHub**.

Escribe un correo a: **damianmacancela@gmail.com** con el asunto `[SECURITY] HuntKit – <descripción breve>`.

Recibirás respuesta en 72 horas. El reporte incluirá:
- Confirmación de recepción.
- Evaluación de severidad.
- Plan de remediación o explicación si se considera out-of-scope.

## Alcance (scope)

**In-scope:**
- Evasión trivial de las reglas de detección del módulo.
- Escritura fuera de la ruta esperada en `Save-PersistenceBaseline`.
- Comportamiento inesperado con permisos elevados.

**Out-of-scope:**
- Bypassear Script Block Logging a nivel de política de Windows (limitación documentada).
- Manipulación del baseline por un atacante con acceso de escritura al sistema (limitación documentada).

## Créditos

Los investigadores que reporten vulnerabilidades válidas serán mencionados en el CHANGELOG de la siguiente release (si lo desean).
