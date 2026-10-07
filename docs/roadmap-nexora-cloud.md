# Roadmap Nexora Cloud (posterior a v1.0)

> **Estado:** documento de planificación. No contiene diseño de código, esquemas
> definitivos ni compromisos de fecha. Describe qué construir, en qué orden y
> bajo qué condiciones se avanza.
>
> **Marca:** Nexora. Los identificadores internos `auditoria-*` de v1.0 se
> mantienen hasta que una versión posterior decida explícitamente migrarlos.

## 1. Visión

Nexora Cloud convierte el producto de v1.0 (un agente y una API central por
instalación) en una plataforma administrada para varias empresas y varios
servidores.

Flujo de un cliente:

1. Crea una cuenta e inicia sesión.
2. Pertenece a una **organización**.
3. Agrega un servidor y recibe un comando/token de instalación de un solo uso.
4. Instala **Nexora Agent**.
5. El servidor aparece en Nexora Cloud.
6. Monitorea el servidor.
7. Recibe alertas.
8. Revisa incidentes.
9. Gestiona operaciones (backups, certificados, actualizaciones, políticas).

### Modelo conceptual

```
Nexora Cloud
   └── Organization (tenant)
         ├── Users (con rol)
         ├── Servers
         │     └── Agents
         ├── Events
         ├── Detections
         ├── Incidents
         ├── Responses
         ├── Notifications
         ├── Policies
         ├── Backups
         └── Metrics
```

Principio rector: **todo dato pertenece a exactamente una organización** y
ninguna consulta, ruta, token ni tarea en segundo plano puede cruzar esa
frontera.

### Línea de versiones

| Versión | Nombre | Entrega principal |
|---|---|---|
| v1.1 | SaaS Foundation / Multi-tenancy | Organizaciones, aislamiento estricto, onboarding |
| v1.2 | Monitoring | Métricas de host y modelo métrica→regla→evento→incidente |
| v1.3 | Operations | Backups, certificados SSL, servicios, actualizaciones, reboot, tareas |
| v1.4 | Notifications | Email con reglas, digest, preferencias; diseño de canales futuros |
| v1.5 | Policies / Fleet | Políticas centralizadas, actualización y rollout de agentes |
| v1.6 | Security Expansion | FIM, inventario/CMDB, vulnerabilidades, reportes, integraciones |

Cada versión se cierra con su **demo mínima** y sus **criterios de aceptación**.
No se inicia la siguiente mientras no se cumplan las condiciones de avance.

---

## 2. v1.1 — SaaS Foundation / Multi-tenancy

### Objetivo

Que varias empresas usen la misma plataforma sin que una pueda ver, modificar ni
inferir la existencia de datos de otra.

### Alcance

- **Organización/Tenant** como entidad raíz, con identificador estable.
- **Aislamiento estricto en backend**: el `organization_id` se deriva siempre de
  la credencial autenticada (sesión de usuario o identidad de agente), nunca de
  un parámetro enviado por el cliente.
- **Usuarios por organización** y **roles** (propietario, administrador,
  operador, solo lectura), con permisos evaluados en el servidor.
- **Servidores y agentes** pertenecen a una organización; un agente no puede
  cambiar de organización.
- **Tokens de registro** ligados a una organización, de un solo uso, con
  caducidad corta y revocables.
- **Onboarding de servidor**: "Agregar servidor" → comando de instalación con
  `<TOKEN_TEMPORAL>` → el servidor aparece al registrarse.
- **Dashboard por tenant**: todas las vistas actuales (resumen, incidentes,
  servidores, evidencia, respuestas) filtradas por organización.
- **Superadmin de plataforma**: rol separado de los roles de organización, para
  operar la plataforma (alta/baja de organizaciones, soporte), con acceso a
  datos de clientes únicamente mediante acción explícita y auditada.
- Auditoría de acciones administrativas (quién, qué organización, cuándo).

### Qué NO incluye

- Facturación, planes ni límites comerciales.
- SSO/SAML/OIDC corporativo.
- Métricas, notificaciones nuevas, políticas centralizadas.
- Interfaz de autoservicio de superadmin completa (basta una vía mínima y
  auditada).
- Migración automática de instalaciones v1.0 existentes (se documenta el
  procedimiento manual).

### Riesgos principales

| Riesgo | Efecto | Mitigación prevista |
|---|---|---|
| Consulta sin filtro de organización | Fuga de datos entre empresas | Filtro obligatorio en una única capa de acceso a datos; pruebas negativas por cada endpoint |
| `organization_id` aceptado desde el cliente | Suplantación de tenant | Se deriva solo de la credencial |
| Identificadores secuenciales o predecibles | Enumeración de recursos ajenos | Identificadores no adivinables; respuesta idéntica para "no existe" y "no es suyo" |
| Tareas en segundo plano sin contexto de tenant | Mezcla de datos en procesos internos | Todo trabajo en segundo plano lleva su organización explícita |
| Superadmin con acceso silencioso | Abuso o fuga interna | Acceso explícito, registrado y visible para el cliente |
| Reutilización del token de registro | Servidor ajeno en la organización | Un solo uso, caducidad, revocación, vínculo a organización |

### Dependencias

- v1.0 cerrada y validada con `docs/qa-nexora-v1.0.md` sin FAIL crítico.
- Decisión sobre base de datos de la nube (ver sección 9): SQLite por
  instalación no sirve para multi-tenant compartido.
- Decisión sobre la autenticación SaaS (ver sección 9).

### Criterios de aceptación

**Aislamiento entre empresas (bloqueantes):**

1. Con dos organizaciones A y B, un usuario de A que solicita cualquier recurso de
   B (servidor, agente, evento, incidente, evidencia, respuesta, notificación)
   por su identificador recibe la **misma respuesta** que para un identificador
   inexistente.
2. Ningún listado, búsqueda, conteo, paginación, exportación ni estadística de A
   incluye datos de B.
3. Modificar el `organization_id` en cuerpo, consulta, cabecera o ruta no cambia
   el tenant efectivo.
4. Un token de registro de A solo registra agentes en A; usado dos veces, falla;
   caducado o revocado, falla.
5. Un agente de A no puede enviar eventos, latidos ni evidencia atribuidos a un
   servidor de B; el intento se rechaza y se registra.
6. Una sesión de A no puede aprobar ni rechazar acciones de respuesta de B.
7. Un usuario con rol de solo lectura no puede ejecutar acciones de escritura.
8. El superadmin de plataforma no usa las mismas rutas que los usuarios de
   organización, y cada acceso a datos de un cliente queda auditado.
9. Existe una **batería automática de pruebas de aislamiento** que recorre todos
   los endpoints con credenciales de otra organización y falla si alguno
   devuelve datos ajenos; se ejecuta en cada cambio.
10. Revisión manual independiente de todos los puntos de acceso a datos,
    registrada en el repositorio.

**Funcionales:**

11. Una organización puede crear usuarios, asignar roles y agregar servidores.
12. El onboarding completo funciona de extremo a extremo en un servidor limpio.
13. Revocar un servidor o usuario surte efecto de inmediato.

### Demo mínima

1. Crear las organizaciones "Empresa A" y "Empresa B" con un usuario cada una.
2. Agregar un servidor a cada una con su comando de instalación.
3. Generar un incidente en cada servidor.
4. Mostrar que cada usuario ve solo su servidor e incidente.
5. Intentar desde A abrir por identificador el incidente de B: respuesta idéntica
   a "no existe".
6. Ejecutar la batería de pruebas de aislamiento: sin fallos.

### Condiciones para avanzar a v1.2

- Todos los criterios 1–10 cumplidos y evidenciados.
- Cero hallazgos abiertos de aislamiento (críticos o altos).
- Procedimiento de recuperación de la base de la nube probado (backup/restore).
- Dogfooding de v1.1 iniciado (sección 8).

---

## 3. v1.2 — Monitoring

### Objetivo

Observar el estado de salud de cada servidor y convertir desviaciones en
incidentes accionables, **sin intentar reemplazar a Grafana**.

### Alcance

Métricas por servidor:

| Grupo | Métricas |
|---|---|
| CPU | Uso total |
| Memoria | RAM usada/disponible |
| Carga | Load average 1/5/15 min |
| Disco | Uso y espacio libre |
| Filesystem | Puntos de montaje, espacio e inodos |
| Swap | Uso |
| Red | Bytes RX/TX por interfaz |
| Uptime | Tiempo encendido y reinicios |
| Servicios | Estado de servicios elegidos |
| Disponibilidad | Servidor con/sin latidos |

**Modelo de Nexora (el que lo diferencia de un panel de métricas):**

```
métrica → regla → evento → incidente → notificación → respuesta opcional
```

- Reglas por umbral y duración (por ejemplo "disco > 90 % durante 10 min").
- Un incumplimiento genera un **evento**; los eventos relacionados se agrupan en
  un **incidente** con los mismos estados que la seguridad (abierto, observado,
  contenido, cerrado).
- Reglas con valores por defecto sensatos y sobrescribibles por organización.
- Vista por servidor: estado actual y tendencia corta (últimas horas/días).
- Retención definida y acotada por tipo de métrica.
- Detección de **servidor sin latidos** como disponibilidad.

### Qué NO incluye

- Editor de consultas, paneles arbitrarios o lenguaje de consulta propio.
- Métricas de aplicaciones o personalizadas definidas por el usuario.
- Trazas y logs completos de aplicación.
- Detección por aprendizaje automático o anomalías estadísticas.
- Respuestas automáticas a métricas (solo diseñadas como paso opcional; ver
  v1.5).

### Riesgos principales

| Riesgo | Efecto | Mitigación prevista |
|---|---|---|
| Volumen de métricas en un almacenamiento no apto | Costos y lentitud | Almacenamiento específico para series temporales o agregación y retención desde el diseño |
| Falsos positivos por umbrales rígidos | Fatiga de alertas | Duración mínima, histéresis, valores por defecto conservadores, medición en dogfooding |
| Sobrecarga del agente | El monitor degrada el servidor | Presupuesto de CPU/memoria del agente, intervalos mínimos, medición |
| Mezcla de métricas entre tenants | Fuga de datos | Misma frontera de v1.1 en el almacenamiento de métricas |
| Alcance que crece hacia "otro Grafana" | Retraso | Lista cerrada de métricas y vistas |

### Dependencias

- v1.1 completa (tenant en todo dato).
- Decisión de almacenamiento de métricas (sección 9).
- Latido del agente existente como base de disponibilidad.

### Criterios de aceptación

1. Todas las métricas de la tabla se recogen y se muestran por servidor.
2. Una regla de umbral con duración genera un evento solo si se mantiene el
   tiempo configurado.
3. El evento se agrupa en un incidente con línea de tiempo.
4. Un incidente de monitoreo se notifica con el mecanismo vigente.
5. Servidor apagado o sin conexión genera incidente de disponibilidad y se
   cierra al volver.
6. El consumo del agente con monitoreo activo respeta el presupuesto definido y
   está medido.
7. Las métricas respetan el aislamiento de v1.1 (se repite la batería).
8. La retención se aplica y se comprueba.
9. La tasa de falsos positivos de las reglas por defecto se ha medido en
   dogfooding y es aceptable según el umbral acordado.

### Demo mínima

1. Servidor con agente mostrando CPU, RAM, disco y red.
2. Llenar un disco de pruebas por encima del umbral: aparece evento, incidente y
   notificación.
3. Liberar espacio: el incidente se cierra.
4. Apagar el servidor: incidente de disponibilidad.

### Condiciones para avanzar a v1.3

- Criterios 1–9 cumplidos.
- Al menos dos semanas de observación sin pérdida de datos ni crecimiento
  descontrolado del almacenamiento.
- Consumo del agente dentro del presupuesto en los servidores de dogfooding.

---

## 4. v1.3 — Operations

### Objetivo

Cubrir las operaciones recurrentes de un servidor, de modo que Nexora avise de
lo que **debía pasar y no pasó**, además de lo que pasó.

### Alcance

- **Backups:** el agente reporta eventos `BACKUP_STARTED`, `BACKUP_SUCCESS`,
  `BACKUP_FAILED` y `BACKUP_MISSED` (este último cuando no llega éxito en la
  ventana esperada). Definición de ventana y antigüedad máxima por servidor.
- **Certificados SSL:** inventario de certificados configurados y alertas por
  próximo vencimiento.
- **Servicios:** lista de servicios críticos por servidor, con estado y
  alertas de caída.
- **Actualizaciones:** paquetes pendientes y, por separado, actualizaciones de
  seguridad.
- **Reboot required:** detección y alerta con antigüedad.
- **Tareas programadas:** registro de tareas (por ejemplo cron/timers
  configurados) y alerta si no se ejecutan en su ventana.
- Todos estos hallazgos siguen el mismo modelo evento → incidente →
  notificación.

### Qué NO incluye

- Ejecutar backups por cuenta del cliente (Nexora observa y alerta; no
  sustituye su herramienta de backup).
- Instalar actualizaciones o reiniciar servidores automáticamente.
- Renovación automática de certificados.
- Orquestación de tareas remotas arbitrarias.
- Almacenar copias de seguridad de los clientes.

### Riesgos principales

| Riesgo | Efecto | Mitigación prevista |
|---|---|---|
| Cada cliente respalda distinto | Integración frágil | Contrato simple de eventos, con un reporte de ejemplo por método habitual |
| `BACKUP_MISSED` mal calibrado | Falsas alarmas | Ventana configurable, tolerancia y zona horaria explícitas |
| Reportes falsificados | Falso sentido de seguridad | Eventos firmados por la identidad del agente |
| Comandos de inventario con privilegios | Superficie de ataque | Solo lectura, lista cerrada de comprobaciones |
| Relojes desfasados | Alertas incorrectas | Marca de tiempo del servidor de la nube como referencia de ventanas |

### Dependencias

- v1.2 (modelo métrica/regla/evento).
- Canal de eventos firmados del agente (ya existente en v1.0 mediante identidad).

### Criterios de aceptación

1. Los cuatro eventos de backup se reciben, se muestran y se asocian al
   servidor correcto.
2. Un backup que no llega en su ventana produce `BACKUP_MISSED` e incidente.
3. Un certificado a menos de N días de vencer genera alerta con severidad
   escalonada.
4. Un servicio crítico detenido genera incidente y se cierra al recuperarse.
5. Se informan actualizaciones pendientes y reboot requerido sin ejecutar
   ninguna acción en el servidor.
6. Una tarea programada que no corre genera alerta.
7. Aislamiento entre organizaciones verificado también para estos datos.

### Demo mínima

1. Ejecutar un backup de prueba que reporta inicio y éxito.
2. Ejecutar otro que falla: `BACKUP_FAILED`.
3. Omitir uno: `BACKUP_MISSED` tras la ventana.
4. Mostrar un certificado próximo a vencer y un servicio detenido.

### Condiciones para avanzar a v1.4

- Criterios cumplidos.
- Al menos tres tipos de operación observados en servidores reales durante
  varias semanas sin falsos `MISSED` sin explicación.
- Volumen de notificaciones generado medido (insumo para v1.4).

---

## 5. v1.4 — Notifications

### Objetivo

Que cada cliente reciba lo que le importa, en el momento adecuado y sin ruido
innecesario.

### Alcance

- **Email** como canal implementado.
- **Reglas por severidad** (por ejemplo "críticos y altos de inmediato").
- **Reglas por evento/tipo** (por ejemplo "siempre `BACKUP_FAILED`").
- **Configuración por cliente (organización)** y **preferencias por usuario**.
- **Digest** (resumen periódico) para eventos de menor severidad.
- Agrupación y control de repetición para evitar tormentas de correo.
- Historial de notificaciones enviadas y su resultado.
- **Diseño preparado para canales futuros** (webhook, Slack, Teams, Telegram):
  un modelo de "canal" con tipo, destino, secreto y reglas, de modo que agregar
  un canal no cambie el motor de reglas. **No se implementan** en esta versión.

### Qué NO incluye

- Implementación de webhook, Slack, Teams o Telegram.
- SMS o llamadas.
- Guardias, escalamiento entre personas o calendarios de turnos.
- Plantillas de correo totalmente personalizables por el cliente.

### Riesgos principales

| Riesgo | Efecto | Mitigación prevista |
|---|---|---|
| Entregabilidad del correo | Alertas que no llegan | Dominio de envío configurado correctamente, seguimiento de rebotes |
| Fuga entre tenants en destinatarios | Correo a la empresa equivocada | Destinatarios solo de la organización dueña del incidente |
| Tormenta de alertas | Fatiga y bajas | Agrupación, límites y digest |
| Secretos de canales futuros | Exposición | Diseñar almacenamiento cifrado antes de implementar canales |
| Contenido sensible en el correo | Fuga por email | Mensaje breve con enlace; la evidencia se queda en Nexora |

### Dependencias

- v1.1 (organizaciones y usuarios).
- Eventos de v1.2 y v1.3 como fuente.
- Servicio de correo transaccional elegido (sección 9).

### Criterios de aceptación

1. Una regla por severidad envía solo lo configurado.
2. Una regla por tipo de evento funciona de forma independiente de la severidad.
3. El digest agrupa lo esperado y se envía en su horario.
4. Un usuario puede ajustar sus preferencias sin alterar las de la organización
   más allá de lo permitido por su rol.
5. Un incidente de la organización A nunca genera correo a destinatarios de B.
6. Si el envío falla, se reintenta de forma acotada y queda registrado; no se
   pierde en silencio.
7. El modelo de canal está documentado y revisado, sin canales nuevos
   implementados.

### Demo mínima

1. Configurar una regla "críticos inmediato, resto en digest".
2. Provocar un incidente crítico y uno bajo.
3. Mostrar el correo inmediato y, después, el digest.
4. Mostrar el historial y un envío fallido con su reintento.

### Condiciones para avanzar a v1.5

- Criterios cumplidos.
- Volumen y tasa de ruido medidos en dogfooding, con ajustes aplicados.
- Revisión del modelo de canal con al menos un caso de uso real documentado.

---

## 6. v1.5 — Policies / Fleet Management

### Objetivo

Administrar muchos agentes de forma consistente y segura, sin entrar a cada
servidor.

### Alcance

**Políticas centralizadas, asignables a uno o varios agentes:**

- Modo de respuesta (`audit_only`, `assisted`, `automatic`).
- Duración de bloqueos y escalamiento por reincidencia.
- Captura de evidencia (qué y cuánta).
- Umbrales de detección y de métricas.
- Actualizaciones, backups y operaciones esperadas.
- **Configuración versionada y firmada**: el agente solo aplica políticas con
  firma válida y versión mayor a la actual; registra qué versión aplicó.
- Las protecciones (administrador de confianza, sesión SSH, IP local, gateway,
  Tailscale) **no pueden ser desactivadas por una política remota**.

**Gestión de la versión del agente:**

- Versión de agente visible por servidor.
- Actualización de Nexora Agent desde la nube con **rollout por etapas**
  (grupo piloto → resto).
- **Rollback** de agente y de política al estado anterior.
- Reglas de compatibilidad entre versiones de agente y de plataforma.

### Qué NO incluye

- Ejecución remota arbitraria de comandos.
- Políticas condicionales complejas o lenguaje de políticas propio.
- Actualización del sistema operativo del cliente.
- Cambio de política sin registro de quién y cuándo.

### Riesgos principales

| Riesgo | Efecto | Mitigación prevista |
|---|---|---|
| Compromiso de la nube = control de todos los agentes | Impacto masivo | Firma de configuración y artefactos, claves fuera del servidor de aplicación, alcance limitado de lo que una política puede ordenar |
| Política errónea aplicada a toda la flota | Bloqueos masivos | Rollout por etapas, validación previa, rollback, protecciones no desactivables |
| Actualización de agente fallida | Servidores sin monitoreo | Verificación posterior, reversión automática local, grupo piloto |
| Agentes desactualizados o desconectados | Flota heterogénea | Matriz de compatibilidad y visibilidad de versión |
| Mezcla de tenants en la asignación | Política ajena aplicada | Asignación solo dentro de una organización |

### Dependencias

- v1.1 a v1.4.
- Gestión de claves de firma y su rotación (sección 9).
- Mecanismo de actualización del agente (hoy `actualizar.sh`/`rollback.sh` son
  manuales y locales).

### Criterios de aceptación

1. Una política asignada a un grupo de agentes se aplica y cada agente reporta la
   versión aplicada.
2. Una política con firma inválida o versión anterior es rechazada y registrada.
3. Una política no puede desactivar las protecciones de red.
4. Un rollout por etapas se detiene si el grupo piloto reporta fallos.
5. El rollback de política y de agente devuelve el estado anterior y se verifica.
6. Un agente que pierde conexión conserva su última política válida y continúa
   operando.
7. Aislamiento entre organizaciones verificado en políticas, grupos y rollouts.

### Demo mínima

1. Crear una política con modo `assisted` y asignarla a dos servidores.
2. Cambiarla a `automatic` solo para el grupo piloto.
3. Provocar una política inválida y mostrar su rechazo.
4. Actualizar el agente en el piloto y luego en el resto; después, revertir.

### Condiciones para avanzar a v1.6

- Criterios cumplidos.
- Al menos un ciclo completo de actualización de agente (con rollback) ejecutado
  en dogfooding.
- Revisión de seguridad específica del canal de configuración y actualización.

---

## 7. v1.6 — Security Expansion

### Objetivo

Ampliar la superficie de seguridad con capacidades de integridad, inventario y
reporte, apoyadas en la base ya probada.

### Alcance

- **FIM (integridad de archivos):** línea base y detección de cambios en rutas
  definidas por política.
- **Inventario / CMDB:** servidores, paquetes, servicios, usuarios y puertos
  abiertos con histórico de cambios.
- **Vulnerabilidades:** correlación de paquetes del inventario con fuentes
  públicas de vulnerabilidades, con priorización básica.
- **Reportes:** reportes periódicos por organización (incidentes, estado de
  flota, operaciones), exportables.
- **Integraciones:** API pública documentada y con credenciales por organización
  para consumir datos y enviarlos a otras herramientas.

### Qué NO incluye

- Escáner activo de vulnerabilidades sobre la red del cliente.
- Antivirus o análisis de malware.
- SIEM completo ni correlación entre clientes.
- Marketplace de integraciones.

### Riesgos principales

| Riesgo | Efecto | Mitigación prevista |
|---|---|---|
| Ruido de FIM | Alertas inútiles | Rutas acotadas por política, exclusiones, línea base explícita |
| Datos de vulnerabilidades desactualizados o erróneos | Falsa confianza | Mostrar fuente y fecha, no prometer cobertura total |
| API pública mal aislada | Fuga entre tenants | Credenciales por organización, límites de uso, batería de aislamiento ampliada |
| Reportes con datos sensibles | Exposición | Control por rol y acceso auditado |
| Crecimiento de alcance | Retraso | Entrega incremental por capacidad |

### Dependencias

- v1.5 (políticas para activar y acotar FIM e inventario).
- Almacenamiento y retención adecuados para inventarios históricos.

### Criterios de aceptación

1. Un cambio en un archivo vigilado genera evento e incidente con evidencia.
2. El inventario refleja instalación y eliminación de un paquete y de un puerto.
3. Una vulnerabilidad conocida del inventario aparece con severidad, fuente y
   fecha de la información.
4. Un reporte se genera para una organización sin incluir datos de otra.
5. Una credencial de API de A no accede a datos de B.
6. La política puede activar y desactivar cada capacidad por servidor.

### Demo mínima

1. Activar FIM sobre un archivo de prueba y modificarlo.
2. Instalar un paquete y ver el cambio de inventario.
3. Generar un reporte y consultar un dato por API.

### Condiciones para continuar

- Criterios cumplidos y revisión de seguridad externa o independiente antes de
  abrir la plataforma a clientes de pago a escala.

---

## 8. Dogfooding antes de vender a terceros

Compilar o pasar la suite de pruebas **no** equivale a "production ready
comercial". Antes de vender a terceros se exige:

1. **Usar Nexora Cloud con nuestros propios servidores**, como cliente real de
   la plataforma, no en un entorno de laboratorio aislado.
2. **Usar CORSgt como entorno real controlado**: un sistema con tráfico y
   operación reales, con riesgo acotado y acuerdo previo.
3. **Observar durante varias semanas** sin intervención manual, registrando
   incidentes, alertas y operaciones.
4. **Medir falsos positivos**: proporción de alertas e incidentes sin acción
   necesaria, por tipo de regla; ajustar y volver a medir.
5. **Probar upgrades**: actualización de plataforma y de agentes con datos
   existentes, incluyendo rollback.
6. **Probar caídas del central**: los agentes continúan, la cola (outbox) se
   acumula y se sincroniza al volver; sin pérdida ni duplicados.
7. **Probar recuperación**: restauración de la base de la nube desde backup y
   reinicio de servicios, con tiempos medidos.
8. **Validar aislamiento entre organizaciones**: al menos dos organizaciones
   propias, batería automática y revisión manual.

Criterios de salida (todos obligatorios):

| Criterio | Evidencia requerida |
|---|---|
| Observación continua suficiente | Registro de semanas de operación sin incidentes críticos de plataforma sin resolver |
| Falsos positivos aceptables | Informe de medición y decisión explícita del umbral aceptado |
| Upgrades con rollback verificados | Registro de al menos un ciclo completo |
| Caída del central sin pérdida de datos | Registro de la prueba y conteos antes/después |
| Recuperación dentro del tiempo objetivo | Tiempos medidos |
| Aislamiento entre organizaciones | Batería automática en verde y revisión manual archivada |
| Sin FAIL crítico abierto | Tablas de QA firmadas |

Sin esta evidencia, la plataforma se describe como "en validación", no como
"lista para producción comercial".

---

## 9. De v1.0 académica a producto comercial

### 9.1 Qué se reutiliza

| Componente actual | Uso en Nexora Cloud |
|---|---|
| Agente | Base de Nexora Agent; se amplía con métricas y operaciones |
| Registro | Flujo de alta, ahora con token ligado a organización |
| Identidad del agente | Identidad firmada por agente, base del aislamiento y de la autenticación de eventos |
| Heartbeat | Disponibilidad y versión del agente |
| Outbox | Entrega confiable con tolerancia a caídas del central |
| Detecciones | Reglas de seguridad existentes, ahora configurables por política |
| Incidentes | Modelo de estados y línea de tiempo, compartido con monitoreo y operaciones |
| Evidencia | Captura forense y su vínculo con incidentes |
| Motor de respuesta | Decisión, validación de protecciones y ejecución; modos `audit_only`, `assisted`, `automatic` |
| nftables | Mecanismo de bloqueo por IP e IP+puerto en el servidor |
| Conceptos del dashboard | Resumen, incidentes, servidores, aprobaciones; ahora por organización |

### 9.2 Qué requiere rediseño

| Área | Por qué no basta lo actual | Dirección |
|---|---|---|
| Multi-tenancy | v1.0 asume una sola organización por instalación | `organization_id` obligatorio y derivado de la credencial en cada acceso (v1.1) |
| Base de datos de la nube | SQLite por instalación no soporta alta concurrencia ni aislamiento compartido | Base gestionada y con backups, con migraciones controladas; decisión explícita antes de v1.1 |
| Autenticación SaaS | Usuarios locales de una instalación | Cuentas, verificación de correo, recuperación de acceso, MFA, sesiones por organización |
| Onboarding | Registro manual con token | Flujo guiado de alta de servidor con comando de instalación |
| Almacenamiento de métricas | No existe volumen de series temporales | Almacén específico con retención y agregación (v1.2) |
| Facturación futura | No hay planes ni medición de uso | Registro de uso por organización desde el principio, aunque no se cobre aún |
| Actualización de agentes | Hoy manual (`actualizar.sh`, `rollback.sh`) | Rollout firmado y por etapas con reversión (v1.5) |
| Observabilidad de Nexora mismo | Registros locales por servicio | Métricas, alertas y trazas de la propia plataforma, con Nexora monitoreando a Nexora |

### 9.3 Decisiones abiertas que condicionan el plan

1. Motor de base de datos de la nube y estrategia de migración desde SQLite.
2. Estrategia de autenticación SaaS (propia o proveedor de identidad).
3. Almacenamiento de métricas.
4. Servicio de correo transaccional.
5. Custodia y rotación de claves de firma.
6. Modelo de despliegue y regiones de datos.
7. Política de retención y de datos personales por cliente.

Cada decisión se registra antes de iniciar la versión que depende de ella.

---

## 10. Diagrama de flujo conceptual

```
        Nexora Agent
  (detección, métricas, evidencia,
   respuesta local, outbox)
              ↓
        Nexora Cloud API
  (autenticación de agente y usuario)
              ↓
        Tenant isolation
  (organization_id derivado de la credencial;
   ninguna ruta lo acepta del cliente)
              ↓
  Processing / incidents / metrics
  (eventos, reglas, incidentes, almacén
   de métricas, evidencia)
              ↓
        Nexora Web
  (dashboard por organización)
              ↓
  Notifications / Operations / Policies
  (alertas, backups y certificados,
   políticas y flota; respuesta opcional
   de vuelta hacia el agente)
```

---

## 11. Resumen de puertas de avance

| De → A | Puerta principal |
|---|---|
| v1.0 → v1.1 | QA de `docs/qa-nexora-v1.0.md` sin FAIL crítico |
| v1.1 → v1.2 | Aislamiento entre empresas demostrado y revisado |
| v1.2 → v1.3 | Métricas estables, falsos positivos medidos, consumo del agente medido |
| v1.3 → v1.4 | Operaciones observadas semanas sin falsos `MISSED` inexplicados |
| v1.4 → v1.5 | Ruido de notificaciones medido y ajustado |
| v1.5 → v1.6 | Ciclo completo de actualización con rollback; revisión de seguridad |
| v1.6 → venta a terceros | Dogfooding completo (sección 8) y revisión independiente |
