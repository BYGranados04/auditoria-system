# Documentación de Nexora v1.0.0

Índice de la documentación vigente. La portada del proyecto está en el
[README principal](../README.md).

## Primeros pasos

- [Instalación](instalacion.md): requisitos, scripts de instalación por rol,
  registro de agentes y validación posterior.
- [Configuración](configuracion.md): `agent.env`, defaults seguros, variables
  que habilitan acciones activas y referencia completa de variables.
- [Operación](operacion.md): servicios, health, logs, eventos, incidentes,
  modo `assisted` y notificaciones.

## Arquitectura

- [Arquitectura](arquitectura.md): roles central y agent, flujo de un evento,
  componentes del código, directorios y servicios.
- [Referencia técnica](referencia-tecnica.md): rutas, servicios, bases SQLite,
  scripts, CLIs, API HTTP, tipos de evento, estados, roles y modos.

## Seguridad y respuesta

- [Respuesta defensiva](respuesta-defensiva.md): modos, bloqueos temporales,
  protecciones, nftables, reincidencia, vencimiento (QA-01) y recuperación.
- [Incidentes y evidencia](incidentes-y-evidencia.md): agrupación, timeline,
  aprobaciones, evidencia forense local y qué se sincroniza.
- [Seguridad](seguridad.md): modelo de confianza, mínimo privilegio, permisos,
  secretos, identidad del agente y limitaciones conocidas.
- [Motor defensivo](motor-defensivo-incidentes.md): diseño interno del motor,
  separación de capas, captura forense, esquemas y API de incidentes.

## Mantenimiento

- [Actualización](actualizacion.md): uso de `actualizar.sh`, migraciones y
  rollback automático o manual.
- [Backup, restore y rollback](backup-restore-rollback.md): sintaxis, flujos por
  rol, validación SQLite y precauciones.
- [Solución de problemas](troubleshooting.md): síntomas, causas, diagnóstico y
  acciones seguras.

## QA y release

- [QA de Nexora v1.0](qa-nexora-v1.0.md): procedimiento y resumen del QA físico
  en Ubuntu Server 24.04.5 LTS.
- [Release v1.0.0](release-v1.0.0.md): notas de la versión, migraciones,
  validación y limitaciones.

## Futuro

- [Roadmap Nexora Cloud](roadmap-nexora-cloud.md): planificación posterior a
  v1.0. Las capacidades nuevas que describe no están implementadas en v1.0.0.

## Documentos históricos

`v0.6-exponer.md` y `v0.7-autenticacion.md` describen versiones anteriores y no
reflejan v1.0.0.
