# НЕЙРОЗАВОД — единый Qwen + Windows SCM кандидат (21.10.2026)

**Статус: DRAFT; NO MERGE / NO PROD / NO HANDOFF / NO SKILLS ACTIVATION.**

Исходный защищённый SCM → Git → CORE: ветка `neurofactory-scm-git-child-diagnostics-20261021`, SHA `a2ce43e2925bd811a7570cdcb1f6fb32df2a5dc8` (PR #54).
Локальная UI → Qwen → одноразовое непроверенное текстовое предложение и резервные копии: `neurofactory-onepc-unified-qwen-core-ui-20261020` (PR #51).

## Изменения в этой интеграционной ветке
- Сохранены без изменений новый CORE git.exe CREATE_NO_WINDOW фикс, restricted service SID, Ed25519, Named Pipe, отказ от повтора подписанного разрешения, отдельный подписант и запрет привилегий у UI.
- Перенесены точные Git blobs из PR #51: локальный Qwen draft provider, SQLite v3 (только черновики), восстановление v2/v3, существующие кнопки UI, изолированные тесты, добавление draft_provider только в непривилегированный Inno per-user installer.
- Включена отдельная fail-closed облачная проверка Windows: unit/negative tests плюс фактическая три-SID SCM подписанная очередь с отказом повторов.
- Рабочий запуск, автоматическое применение текста Qwen, постановка в очередь из браузера, выполнение HOST и отправка в GitHub запрещены до независимой проверки.

## Что обязательно проверить перед следующей фазой
1. Оба новых Windows jobs реально PASS на точном HEAD; отдельно проверить логи, не принимать простой зелёный status без завершённого unittest.
2. Новый installer workflow PASS с установленным Python и v3 SQLite, данные переживают перезапуск, restore в новую папку.
3. Отдельно повторить реальную генерацию Qwen на **этой** объединённой ветке (не переносить результат прежнего PR автоматически).
4. Только потом начать HOST effect → signed receipt → CORE completed, crash/unknown/replay negative tests.
5. Трёхролевой доверенный установщик, защищённые operator public key pins, SCM-права и обновления, независимый REVIEW Issue #11 на точном SHA.
