export type Language = 'en' | 'ru' | 'kk';

export const translations = {
    en: {
        appTitle: "NETSHIELD",
        status: {
            connected: "PROTECTED",
            offline: "OFFLINE",
        },
        map: {
            title: "Active Threat Map",
        },
        chart: {
            title: "Live Traffic Analysis",
            bandwidth: "Bandwidth",
        },
        stats: {
            totalPackets: "Total Packets",
            blockedPackets: "Blocked Packets",
        },
        history: {
            title: "History Log",
            viewAll: "VIEW ALL",
            modalTitle: "Traffic History Log",
            empty: "No traffic logs yet. Start the NetShield engine to generate data.",
            columns: {
                time: "Time",
                ip: "IP",
                country: "Country",
                action: "Action",
                score: "Score",
                signature: "Signature",
            },
            showingLast: "Showing last",
            entries: "entries",
            source: "Source",
        },
        widget: {
            noData: "NO DATA",
            waiting: "Waiting for data..."
        },
        theme: {
            forest: "Forest",
            cyber: "Cyber"
        }
    },
    ru: {
        appTitle: "NETSHIELD",

        status: {
            connected: "ЗАЩИЩЕНО",
            offline: "ОФФЛАЙН",
        },
        map: {
            title: "Карта Активных Угроз",
        },
        chart: {
            title: "Анализ Трафика (Live)",
            bandwidth: "Пропускная способность",
        },
        stats: {
            totalPackets: "Всего пакетов",
            blockedPackets: "Заблокировано",
        },
        history: {
            title: "Журнал (Логи)",
            viewAll: "ВЕСЬ СПИСОК",
            modalTitle: "Журнал Истории Трафика",
            empty: "Нет данных. Запустите движок NetShield для генерации трафика.",
            columns: {
                time: "Время",
                ip: "IP адрес",
                country: "Страна",
                action: "Действие",
                score: "Уровень",
                signature: "Сигнатура",
            },
            showingLast: "Показано последних",
            entries: "записей",
            source: "Источник",
        },
        widget: {
            noData: "НЕТ ДАННЫХ",
            waiting: "Ожидание данных..."
        },
        theme: {
            forest: "Лес",
            cyber: "Кибер"
        }
    },
    kk: {
        appTitle: "NETSHIELD",
        status: {
            connected: "ҚОРҒАЛҒАН",
            offline: "ОФФЛАЙН",
        },
        map: {
            title: "Белсенді Қауіптер Картасы",
        },
        chart: {
            title: "Трафик Анализі (Live)",
            bandwidth: "Өткізу қабілеті",
        },
        stats: {
            totalPackets: "Жалпы пакеттер",
            blockedPackets: "Бұғатталған",
        },
        history: {
            title: "Тарих Журналы",
            viewAll: "БАРЛЫҒЫН КӨРУ",
            modalTitle: "Трафик Тарихы Журналы",
            empty: "Деректер жоқ. Трафик жасау үшін NetShield қозғалтқышын іске қосыңыз.",
            columns: {
                time: "Уақыт",
                ip: "IP мекенжайы",
                country: "Ел",
                action: "Әрекет",
                score: "Деңгей",
                signature: "Қолтаңба",
            },
            showingLast: "Соңғы",
            entries: "жазба көрсетілді",
            source: "Дереккөз",
        },
        widget: {
            noData: "ДЕРЕК ЖОҚ",
            waiting: "Деректер күтілуде..."
        },
        theme: {
            forest: "Орман",
            cyber: "Кибер"
        }
    }
};
