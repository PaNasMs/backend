package oled

var labels = map[string][3]string{
	"read-only":         {"READ ONLY", "ТОЛЬКО ЧТЕНИЕ", "ЛИШЕ ЧИТАННЯ"},
	"starting-services": {"STARTING SERVICES", "ЗАПУСК СЛУЖБ", "ЗАПУСК СЛУЖБ"},
	"checking":          {"CHECKING", "ПРОВЕРКА", "ПЕРЕВІРКА"}, "downloading": {"DOWNLOADING", "ЗАГРУЗКА", "ЗАВАНТАЖЕННЯ"}, "preparing": {"PREPARING", "ПОДГОТОВКА", "ПІДГОТОВКА"}, "backing-up": {"BACKING UP", "РЕЗЕРВНАЯ КОПИЯ", "РЕЗЕРВНА КОПІЯ"}, "installing": {"INSTALLING", "УСТАНОВКА", "ВСТАНОВЛЕННЯ"}, "verifying": {"VERIFYING", "ПРОВЕРКА", "ПЕРЕВІРКА"}, "rolling-back": {"ROLLING BACK", "ОТКАТ", "ВІДКОЧУВАННЯ"}, "problem-resolved": {"PROBLEM RESOLVED", "ПРОБЛЕМА УСТРАНЕНА", "ПРОБЛЕМУ УСУНЕНО"},

	"storage": {"STORAGE", "ХРАНИЛИЩЕ", "СХОВИЩЕ"}, "free": {"FREE", "СВОБОДНО", "ВІЛЬНО"}, "healthy": {"HEALTHY", "ИСПРАВЕН", "СПРАВНИЙ"}, "degraded": {"DEGRADED", "ДЕГРАДАЦИЯ", "ДЕГРАДАЦІЯ"}, "inactive": {"INACTIVE", "НЕАКТИВЕН", "НЕАКТИВНИЙ"}, "unknown": {"UNKNOWN", "НЕИЗВЕСТНО", "НЕВІДОМО"},
	"status-unavailable": {"STATUS UNAVAILABLE", "СТАТУС НЕДОСТУПЕН", "СТАТУС НЕДОСТУПНИЙ"}, "waiting-data": {"WAITING FOR DATA", "ОЖИДАНИЕ ДАННЫХ", "ОЧІКУВАННЯ ДАНИХ"}, "no-storage": {"NO STORAGE", "НЕТ ХРАНИЛИЩ", "НЕМАЄ СХОВИЩ"},
	"raid-recover": {"RAID REBUILD", "ВОССТАНОВЛЕНИЕ RAID", "ВІДНОВЛЕННЯ RAID"}, "raid-resync": {"RAID SYNC", "СИНХРОНИЗАЦИЯ RAID", "СИНХРОНІЗАЦІЯ RAID"}, "raid-reshape": {"RAID RESHAPE", "ПЕРЕСТРОЙКА RAID", "ПЕРЕБУДОВА RAID"}, "raid-check": {"RAID CHECK", "ПРОВЕРКА RAID", "ПЕРЕВІРКА RAID"}, "raid-repair": {"RAID REPAIR", "ИСПРАВЛЕНИЕ RAID", "ВИПРАВЛЕННЯ RAID"}, "raid-done": {"RAID WORK FINISHED", "РАБОТА RAID ОКОНЧЕНА", "РОБОТУ RAID ЗАВЕРШЕНО"}, "raid-problem": {"CHECK RAID", "ПРОВЕРЬТЕ RAID", "ПЕРЕВІРТЕ RAID"},
	"running": {"RUNNING", "ВЫПОЛНЯЕТСЯ", "ВИКОНУЄТЬСЯ"}, "queued": {"QUEUED", "В ОЧЕРЕДИ", "У ЧЕРЗІ"}, "paused": {"PAUSED", "ПАУЗА", "ПАУЗА"}, "cancelling": {"CANCELLING", "ОТМЕНА", "СКАСУВАННЯ"}, "working": {"IN PROGRESS", "ВЫПОЛНЯЕТСЯ", "ВИКОНУЄТЬСЯ"}, "elapsed": {"ELAPSED", "ПРОШЛО", "МИНУЛО"}, "min-left": {"MIN LEFT", "МИН ОСТАЛОСЬ", "ХВ ЗАЛИШИЛОСЬ"},
	"operation": {"OPERATION", "ОПЕРАЦИЯ", "ОПЕРАЦІЯ"}, "copy": {"COPY FILES", "КОПИРОВАНИЕ", "КОПІЮВАННЯ"}, "move": {"MOVE FILES", "ПЕРЕМЕЩЕНИЕ", "ПЕРЕМІЩЕННЯ"}, "delete": {"DELETE FILES", "УДАЛЕНИЕ", "ВИДАЛЕННЯ"}, "upload": {"UPLOAD TO NAS", "ЗАГРУЗКА НА NAS", "ЗАВАНТАЖЕННЯ НА NAS"}, "download": {"DOWNLOAD FROM NAS", "СКАЧИВАНИЕ С NAS", "ЗАВАНТАЖЕННЯ З NAS"}, "update": {"SYSTEM UPDATE", "ОБНОВЛЕНИЕ СИСТЕМЫ", "ОНОВЛЕННЯ СИСТЕМИ"}, "backup": {"BACKUP", "РЕЗЕРВНАЯ КОПИЯ", "РЕЗЕРВНА КОПІЯ"},
	"succeeded": {"TASK COMPLETED", "ЗАДАЧА ЗАВЕРШЕНА", "ЗАВДАННЯ ЗАВЕРШЕНО"}, "failed": {"TASK FAILED", "ОШИБКА ЗАДАЧИ", "ПОМИЛКА ЗАВДАННЯ"}, "cancelled": {"TASK CANCELLED", "ЗАДАЧА ОТМЕНЕНА", "ЗАВДАННЯ СКАСОВАНО"}, "interrupted": {"TASK INTERRUPTED", "ЗАДАЧА ПРЕРВАНА", "ЗАВДАННЯ ПЕРЕРВАНО"},
	"device-connected": {"DRIVE CONNECTED", "ДИСК ПОДКЛЮЧЕН", "ДИСК ПІДКЛЮЧЕНО"}, "device-disconnected": {"DRIVE DISCONNECTED", "ДИСК ОТКЛЮЧЕН", "ДИСК ВІДКЛЮЧЕНО"}, "device-ejected": {"DRIVE CAN BE REMOVED", "МОЖНО ИЗВЛЕЧЬ ДИСК", "МОЖНА ВИЙНЯТИ ДИСК"}, "network-ready": {"NETWORK CONNECTED", "СЕТЬ ПОДКЛЮЧЕНА", "МЕРЕЖУ ПІДКЛЮЧЕНО"}, "network-lost": {"NETWORK UNAVAILABLE", "СЕТЬ НЕДОСТУПНА", "МЕРЕЖА НЕДОСТУПНА"},
	"cpu-hot": {"CPU OVERHEATING", "ПЕРЕГРЕВ CPU", "ПЕРЕГРІВ CPU"}, "system-full": {"SYSTEM DISK FULL", "СИСТЕМНЫЙ ДИСК ПОЛОН", "СИСТЕМНИЙ ДИСК ПОВНИЙ"}, "smart": {"DISK HEALTH WARNING", "ПРОБЛЕМА С ДИСКОМ", "ПРОБЛЕМА З ДИСКОМ"}, "heat": {"DISK OVERHEATING", "ПЕРЕГРЕВ ДИСКА", "ПЕРЕГРІВ ДИСКА"}, "cooling-stale": {"COOLING DATA STALE", "НЕТ ДАННЫХ ОХЛАЖДЕНИЯ", "НЕМАЄ ДАНИХ ОХОЛОДЖ."}, "update-available": {"UPDATE AVAILABLE", "ДОСТУПНО ОБНОВЛЕНИЕ", "ДОСТУПНЕ ОНОВЛЕННЯ"}, "update-result": {"UPDATE RESULT", "РЕЗУЛЬТАТ ОБНОВЛЕНИЯ", "РЕЗУЛЬТАТ ОНОВЛЕННЯ"},
	"info": {"INFORMATION", "ИНФОРМАЦИЯ", "ІНФОРМАЦІЯ"}, "success": {"COMPLETED", "ЗАВЕРШЕНО", "ЗАВЕРШЕНО"}, "warning": {"WARNING", "ВНИМАНИЕ", "УВАГА"}, "error": {"ERROR", "ОШИБКА", "ПОМИЛКА"}, "critical": {"CRITICAL", "КРИТИЧЕСКОЕ СОБЫТИЕ", "КРИТИЧНА ПОДІЯ"}, "attention": {"ATTENTION", "ТРЕБУЕТ ВНИМАНИЯ", "ПОТРЕБУЄ УВАГИ"}, "details-web": {"DETAILS IN WEB UI", "ПОДРОБНОСТИ В ВЕБ-UI", "ДОКЛАДНІШЕ У ВЕБ-UI"},
}

func label(language, key string) string {
	v, ok := labels[key]
	if !ok {
		return key
	}
	i := 0
	if language == "ru" {
		i = 1
	}
	if language == "uk" {
		i = 2
	}
	return v[i]
}
