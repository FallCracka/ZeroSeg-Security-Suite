#!/bin/bash
# Запрещаем зависание при запросе пароля
export GIT_TERMINAL_PROMPT=0

# Твои данные
TOKEN="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"
REPO="github.com/FallCracka/ZeroSeg-Security-Suite.git"
URL="https://FallCracka:${TOKEN}@${REPO}"

# Настройка репозитория
git remote set-url origin "$URL" 2>/dev/null || git remote add origin "$URL"
git config user.name "FallCracka"
git config user.email "fall@fall.fall"

echo "[*] ZeroSeg: Синхронизация отчетов..."

# Добавляем файлы (базу и все отчеты из папки)
git add audit_results.db reports/*.txt 2>/dev/null

# Проверяем, есть ли новые изменения
if git diff-index --quiet HEAD --; then
    echo "[i] Новых изменений в файлах не обнаружено."
else
    git commit -m "Security Audit: $(hostname) - $(date +'%Y-%m-%d %H:%M:%S')"
fi

# Отправка в ветку main
echo "[*] Выполняю push на GitHub..."
if git push origin main; then
    echo "[v] УСПЕХ: Все данные синхронизированы!"
else
    echo "[x] ОШИБКА: GitHub отклонил запрос. Проверь статус токена."
fi
