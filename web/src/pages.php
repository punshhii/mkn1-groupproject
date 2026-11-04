<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      pages
 * Назначение:  разделы меню (таблица 7, столбец Web). В режиме аварийной поддержки
 *              доступны только «Состояние», «Журналы», «Конфигурация» (просмотр)
 *              и «Система»; остальные запросы отклоняются с M10 (FR-49, README ПС-4).
 * Методы:
 *   - FW_SECTIONS — разделы меню: идентификатор -> название
 *   - FW_EMERGENCY_SECTIONS — разделы аварийного режима: true — с изменениями, false — только просмотр
 *   - fw_page_denied — код отказа для раздела: null или M10
 */

declare(strict_types=1);

const FW_SECTIONS = [
    'state' => 'Состояние',
    'rules' => 'Правила фильтрации',
    'logs' => 'Журналы',
    'config' => 'Конфигурация',
    'users' => 'Учётные записи',
    'sessions' => 'Сеансы',
    'interfaces' => 'Интерфейсы',
    'routes' => 'Маршруты',
    'system' => 'Система',
];

const FW_EMERGENCY_SECTIONS = [
    'state' => true,
    'logs' => true,
    'config' => false,  // только просмотр
    'system' => true,
];

/**
 * Можно ли открыть раздел section; modify — запрос изменяет данные (POST),
 * emergency — режим аварийной поддержки (FwInbox::emergency). null — можно, M10 — нет.
 */
function fw_page_denied(string $section, bool $modify, bool $emergency): ?string
{
    if (!$emergency) {
        return null;
    }
    if (!array_key_exists($section, FW_EMERGENCY_SECTIONS)) {
        return 'M10';
    }
    return ($modify && !FW_EMERGENCY_SECTIONS[$section]) ? 'M10' : null;
}
