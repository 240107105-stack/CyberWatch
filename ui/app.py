"""CyberWatch graphical user interface."""

import sqlite3
import tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from config import (
    APP_NAME,
    BG,
    PANEL,
    PANEL_2,
    BORDER,
    TEXT,
    MUTED,
    GREEN,
    RED,
    AMBER,
    BLUE,
    PURPLE,
)
from db.database import (
    DB_PATH,
    add_event_record,
    initialize_database,
    connect_database,
    get_setting,
    set_setting,
    change_alert_status,
    add_alert_note,
    get_alert_notes,
)
from services.detection import run_detection as detect_threats
from services.ingestion import import_log_file, ingest_lines
from services.live import LogTailer
from services.demo import add_demo_events as seed_demo
from services.reporting import event_filter, export_events_csv, export_report_html

class CyberWatchApp:
    """Local educational SIEM with SQLite storage and explainable detections."""

    def __init__(self, root: tk.Tk, db_path=None):
        self.root = root
        self.root.title(f"{APP_NAME} · 2.0")
        self.root.geometry("1420x900")
        self.root.minsize(1180, 760)
        self.root.configure(bg=BG)
        self.db = connect_database(db_path if db_path is not None else DB_PATH)
        self.threshold = 5
        self.window_minutes = 10
        self.port_threshold = 10
        self.tailer = None
        self.live_job = None
        self.live_imported = 0
        self.live_skipped = 0
        self._closed = False
        self.severity_filter = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Готов к работе · Локальная база событий")
        self._load_rule_settings()
        self._configure_styles()
        self._build_interface()
        self.refresh_all()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    # --------------------------- DATABASE ---------------------------
    def _init_database(self) -> None:
        initialize_database(self.db)

    def add_event(
        self,
        source_ip: str | None,
        event_type: str,
        severity: str,
        message: str,
        timestamp: str | None = None,
    ) -> None:
        add_event_record(
            self.db,
            source_ip,
            event_type,
            severity,
            message,
            timestamp,
        )

    # --------------------------- STYLE / UI ---------------------------
    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=0)
        style.layout("TNotebook.Tab", [])
        style.configure("Treeview", background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, rowheight=38, borderwidth=0,
                        font=("Helvetica Neue", 10))
        style.configure("Treeview.Heading", background=PANEL_2, foreground=MUTED,
                        font=("Helvetica Neue", 9, "bold"), padding=(12, 12), relief="flat")
        style.map("Treeview", background=[("selected", "#203d52")],
                  foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", PANEL_2)])
        style.configure("TCombobox", fieldbackground=PANEL_2, background=PANEL_2,
                        foreground=TEXT, arrowcolor=MUTED, padding=8)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL_2)],
                  foreground=[("readonly", TEXT)], selectbackground=[("readonly", PANEL_2)])
        style.configure("TButton", font=("Helvetica Neue", 10, "bold"), padding=(14, 10),
                        background=PANEL_2, foreground=TEXT, borderwidth=0, relief="flat")
        style.map("TButton", background=[("active", "#293c50")])
        style.configure("Accent.TButton", background=GREEN, foreground="#071a16")
        style.map("Accent.TButton", background=[("active", "#62e9c0")])
        style.configure("Vertical.TScrollbar", background=PANEL_2, troughcolor=PANEL,
                        arrowcolor=MUTED, borderwidth=0)
        style.configure("Horizontal.TScrollbar", background=PANEL_2, troughcolor=PANEL,
                        arrowcolor=MUTED, borderwidth=0)

    def _build_interface(self) -> None:
        sidebar = tk.Frame(self.root, bg="#0b1420", width=216)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="◈  CYBERWATCH", bg="#0b1420", fg=GREEN,
                 font=("Helvetica Neue", 19, "bold")).pack(anchor="w", padx=20, pady=(32, 3))
        tk.Label(sidebar, text="SECURITY WORKSPACE", bg="#0b1420", fg=MUTED,
                 font=("Helvetica Neue", 8, "bold")).pack(anchor="w", padx=23)
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=22, pady=28)
        tk.Label(sidebar, text="МОНИТОРИНГ", bg="#0b1420", fg="#5c7087",
                 font=("Helvetica Neue", 8, "bold")).pack(anchor="w", padx=24, pady=(0, 12))
        self.nav_buttons = []
        labels = (("◫", "Обзор"), ("≡", "Журнал событий"),
                  ("◇", "Центр оповещений"), ("◉", "Наблюдение за логом"),
                  ("⚙", "Правила детекции"), ("↗", "Отчёты"))
        for index, (icon, label) in enumerate(labels):
            button = tk.Label(sidebar, text=f"{icon}   {label}", anchor="w", padx=14, pady=13,
                              bg="#0b1420", fg=MUTED, cursor="hand2", takefocus=True,
                              font=("Helvetica Neue", 11))
            button.pack(fill="x", padx=12, pady=3)
            button.bind("<Button-1>", lambda event, i=index: self.notebook.select(i))
            button.bind("<Return>", lambda event, i=index: self.notebook.select(i))
            button.bind("<space>", lambda event, i=index: self.notebook.select(i))
            self.root.bind(f"<Alt-Key-{index + 1}>", lambda event, i=index: self.notebook.select(i))
            self.nav_buttons.append(button)
        bottom = tk.Frame(sidebar, bg="#0b1420")
        bottom.pack(side="bottom", fill="x", padx=23, pady=24)
        tk.Label(bottom, text="●  ЛОКАЛЬНЫЙ РЕЖИМ", bg="#0b1420", fg=GREEN,
                 font=("Helvetica Neue", 9, "bold")).pack(anchor="w")
        tk.Label(bottom, text="Версия 2.0 · Локальные данные", bg="#0b1420", fg=MUTED,
                 font=("Helvetica Neue", 9)).pack(anchor="w", pady=(7, 0))
        main = tk.Frame(self.root, bg=BG)
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg=BG, padx=26, pady=22)
        header.pack(fill="x")
        tk.Label(header, text="РАБОЧЕЕ ПРОСТРАНСТВО  /  БЕЗОПАСНОСТЬ", bg=BG, fg=MUTED,
                 font=("Helvetica Neue", 9, "bold")).pack(side="left")
        self.clock_var = tk.StringVar()
        tk.Label(header, textvariable=self.clock_var, bg=BG, fg=MUTED,
                 font=("Helvetica Neue", 10)).pack(side="right")
        self._update_clock()
        tk.Frame(main, bg=BORDER, height=1).pack(fill="x")
        footer = tk.Frame(main, bg=BG, padx=26, pady=12)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED,
                 font=("Helvetica Neue", 9), anchor="w", wraplength=900).pack(fill="x")
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill="both", expand=True, padx=6)
        self.overview_tab = tk.Frame(self.notebook, bg=BG)
        self.events_tab = tk.Frame(self.notebook, bg=BG)
        self.alerts_tab = tk.Frame(self.notebook, bg=BG)
        self.live_tab = tk.Frame(self.notebook, bg=BG)
        self.rules_tab = tk.Frame(self.notebook, bg=BG)
        self.reports_tab = tk.Frame(self.notebook, bg=BG)
        for tab in (self.overview_tab, self.events_tab, self.alerts_tab, self.live_tab, self.rules_tab, self.reports_tab):
            self.notebook.add(tab)
        self._build_overview()
        self._build_events()
        self._build_alerts()
        self._build_live()
        self._build_rules()
        self._build_reports()
        self.notebook.bind("<<NotebookTabChanged>>", self._update_navigation)
        self._update_navigation()

    def _update_navigation(self, event=None) -> None:
        current = self.notebook.index(self.notebook.select())
        for index, button in enumerate(self.nav_buttons):
            button.configure(bg="#18332f" if index == current else "#0b1420",
                             fg=GREEN if index == current else MUTED)

    def _update_clock(self) -> None:
        self.clock_var.set(datetime.now().strftime("%d.%m.%Y   ·   %H:%M"))
        self.clock_job = self.root.after(1000, self._update_clock)

    def _section_title(self, parent: tk.Widget, title: str, subtitle: str = "") -> None:
        box = tk.Frame(parent, bg=BG)
        box.pack(fill="x", padx=20, pady=(20, 13))
        tk.Label(box, text=title, bg=BG, fg=TEXT,
                 font=("Helvetica Neue", 17, "bold")).pack(anchor="w")
        if subtitle:
            tk.Label(box, text=subtitle, bg=BG, fg=MUTED,
                     font=("Helvetica Neue", 9)).pack(anchor="w", pady=(4, 0))

    def _card(self, parent: tk.Widget, title: str, variable: tk.StringVar,
              accent: str, hint: str) -> None:
        card = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1,
                        padx=18, pady=16)
        card.pack(side="left", fill="both", expand=True, padx=6)
        tk.Label(card, text=title, bg=PANEL, fg=MUTED,
                 font=("Helvetica Neue", 9, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=variable, bg=PANEL, fg=accent,
                 font=("Helvetica Neue", 28, "bold")).pack(anchor="w", pady=(7, 2))
        tk.Label(card, text=hint, bg=PANEL, fg="#71839b",
                 font=("Helvetica Neue", 8)).pack(anchor="w")

    def _build_overview(self) -> None:
        self._section_title(self.overview_tab, "Обзор безопасности",
                            "События, источники и сигналы угроз — в одном рабочем пространстве.")
        cards = tk.Frame(self.overview_tab, bg=BG)
        cards.pack(fill="x", padx=14)
        self.total_var = tk.StringVar(value="0")
        self.alert_count_var = tk.StringVar(value="0")
        self.open_alert_var = tk.StringVar(value="0")
        self.ip_count_var = tk.StringVar(value="0")
        self._card(cards, "ВСЕГО СОБЫТИЙ", self.total_var, BLUE, "Записей в локальной базе")
        self._card(cards, "ОПОВЕЩЕНИЯ HIGH", self.alert_count_var, RED, "Сигналов высокого приоритета")
        self._card(cards, "ОТКРЫТЫЕ СИГНАЛЫ", self.open_alert_var, AMBER, "Ожидают проверки")
        self._card(cards, "ИСТОЧНИКИ", self.ip_count_var, PURPLE, "Уникальных IP-адресов")
        chart_frame = tk.Frame(self.overview_tab, bg=PANEL, highlightbackground=BORDER,
                              highlightthickness=1)
        chart_frame.pack(fill="x", padx=20, pady=(18, 0))
        chart_header = tk.Frame(chart_frame, bg=PANEL)
        chart_header.pack(fill="x", padx=18, pady=(14, 0))
        tk.Label(chart_header, text="АКТИВНОСТЬ СОБЫТИЙ", bg=PANEL, fg=TEXT,
                 font=("Helvetica Neue", 10, "bold")).pack(side="left")
        tk.Label(chart_header, text="●  Все события   /   Последние 24 часа", bg=PANEL, fg=BLUE,
                 font=("Helvetica Neue", 9)).pack(side="right")
        self.activity_chart = tk.Canvas(chart_frame, bg=PANEL, height=135, highlightthickness=0)
        self.activity_chart.pack(fill="x", padx=12, pady=(4, 8))
        self.activity_chart.bind("<Configure>", lambda event: self._draw_activity())
        body = tk.Frame(self.overview_tab, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=(18, 0))
        left = tk.Frame(body, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        left.pack(side="left", fill="both", expand=True, padx=(0, 14))
        right = tk.Frame(body, bg=PANEL, highlightbackground=BORDER, highlightthickness=1,
                         width=265)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        tk.Label(left, text="ПОСЛЕДНИЕ СОБЫТИЯ", bg=PANEL, fg=TEXT,
                 font=("Helvetica Neue", 10, "bold")).pack(anchor="w", padx=16, pady=14)
        recent_frame = tk.Frame(left, bg=PANEL)
        recent_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.recent_tree = self._make_tree(recent_frame, ("time", "ip", "type", "severity"),
                                           (150, 125, 160, 90))
        self._attach_scrollbars(recent_frame, self.recent_tree)
        tk.Label(right, text="БЫСТРЫЕ ДЕЙСТВИЯ", bg=PANEL, fg=TEXT,
                 font=("Helvetica Neue", 10, "bold")).pack(anchor="w", padx=16, pady=(16, 10))
        ttk.Button(right, text="Запустить детекцию  →", command=self.run_detection,
                   style="Accent.TButton").pack(fill="x", padx=14, pady=4)
        self._action_button(right, "Импортировать лог", self.load_log_file)
        self._action_button(right, "Добавить демо-события", self.add_demo_events)
        self._action_button(right, "Обновить данные", self.refresh_all)
        tk.Frame(right, bg=BORDER, height=1).pack(fill="x", padx=16, pady=12)
        tk.Label(right, text="АКТИВНОЕ ПРАВИЛО", bg=PANEL, fg=MUTED,
                 font=("Helvetica Neue", 8, "bold")).pack(anchor="w", padx=16)
        self.profile_var = tk.StringVar()
        tk.Label(right, textvariable=self.profile_var, bg=PANEL, fg=GREEN,
                 font=("Helvetica Neue", 10), wraplength=232, justify="left").pack(
                     anchor="w", padx=16, pady=(7, 8))

    def _draw_activity(self) -> None:
        canvas = self.activity_chart
        canvas.delete("all")
        width = max(canvas.winfo_width(), 200)
        start = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
        buckets = [0] * 24
        for timestamp, count in self.db.execute(
                "SELECT strftime('%Y-%m-%d %H:00:00', timestamp), COUNT(*) FROM events "
                "WHERE timestamp >= ? GROUP BY 1", (start.strftime("%Y-%m-%d %H:%M:%S"),)):
            if timestamp:
                index = int((datetime.fromisoformat(timestamp) - start).total_seconds() // 3600)
                if 0 <= index < 24:
                    buckets[index] = count
        maximum = max(max(buckets), 1)
        left, right, top, bottom = 40, width - 15, 15, 104
        for fraction in (0, 0.5, 1):
            y = bottom - fraction * (bottom - top)
            canvas.create_line(left, y, right, y, fill=BORDER, dash=(2, 5))
            canvas.create_text(left - 8, y, text=f"{maximum * fraction:g}", anchor="e",
                               fill=MUTED, font=("Helvetica Neue", 8))
        step = (right - left) / 24
        for index, count in enumerate(buckets):
            x = left + index * step
            if count:
                canvas.create_rectangle(x + 4, bottom - count / maximum * (bottom - top),
                                        x + step - 4, bottom, fill=BLUE, outline="")
            if index % 4 == 0 or index == 23:
                canvas.create_text(x + step / 2, bottom + 18,
                                   text=(start + timedelta(hours=index)).strftime("%H:%M"),
                                   fill=MUTED, font=("Helvetica Neue", 8))
        if not any(buckets):
            canvas.create_text((left + right) / 2, 52, text="За последние 24 часа событий нет",
                               fill=MUTED, font=("Helvetica Neue", 11))

    def _action_button(self, parent: tk.Widget, label: str, command) -> None:
        ttk.Button(parent, text=label, command=command).pack(fill="x", padx=14, pady=4)

    def _make_tree(self, parent: tk.Widget, columns: tuple[str, ...],
                   widths: tuple[int, ...]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        labels = {"time": "ВРЕМЯ", "ip": "IP-ИСТОЧНИК", "type": "ТИП СОБЫТИЯ",
                  "severity": "ПРИОРИТЕТ", "message": "СООБЩЕНИЕ", "rule": "ПРАВИЛО",
                  "status": "СТАТУС", "id": "ID", "port": "ПОРТ", "source": "ИСТОЧНИК", "previous": "ПРЕЖНИЙ СТАТУС"}
        for column, width in zip(columns, widths):
            tree.heading(column, text=labels.get(column, column.upper()))
            tree.column(column, width=width, minwidth=70, anchor="w")
        tree.tag_configure("alternate", background="#142235")
        tree.tag_configure("HIGH", foreground=RED)
        tree.tag_configure("MEDIUM", foreground=AMBER)
        tree.tag_configure("LOW", foreground=GREEN)
        tree.tag_configure("OPEN", foreground=RED)
        tree.tag_configure("ACKNOWLEDGED", foreground=AMBER)
        tree.tag_configure("RESOLVED", foreground=GREEN)
        return tree

    def _build_events(self) -> None:
        self._section_title(self.events_tab, "Журнал событий", "Поиск, фильтрация и экспорт собранных событий безопасности.")
        controls = tk.Frame(self.events_tab, bg=BG)
        controls.pack(fill="x", padx=20, pady=(0, 12))
        tk.Label(controls, text="ПОИСК", bg=BG, fg=MUTED,
                 font=("Helvetica Neue", 8, "bold")).pack(side="left", padx=(0, 8))
        search = tk.Entry(controls, textvariable=self.search_var, bg=PANEL_2, fg=TEXT,
                          insertbackground=TEXT, relief="flat", width=32,
                          font=("Helvetica Neue", 10))
        search.pack(side="left", ipady=7, padx=(0, 12))
        search.bind("<KeyRelease>", lambda _event: self.refresh_events())
        tk.Label(controls, text="ПРИОРИТЕТ", bg=BG, fg=MUTED,
                 font=("Helvetica Neue", 8, "bold")).pack(side="left", padx=(0, 8))
        severity = ttk.Combobox(controls, textvariable=self.severity_filter,
                                values=("ALL", "HIGH", "MEDIUM", "LOW"),
                                state="readonly", width=11)
        severity.pack(side="left", padx=(0, 12))
        severity.bind("<<ComboboxSelected>>", lambda _event: self.refresh_events())
        ttk.Button(controls, text="Экспорт CSV", command=self.export_events).pack(side="right")
        ttk.Button(controls, text="Импорт лога", command=self.load_log_file).pack(side="right", padx=8)
        frame = tk.Frame(self.events_tab, bg=BG)
        frame.pack(fill="both", expand=True, padx=20, pady=(0, 18))
        self.events_tree = self._make_tree(frame, ("time", "ip", "type", "severity", "message", "port", "source"),
                                           (160, 150, 165, 95, 440, 75, 220))
        self._attach_scrollbars(frame, self.events_tree)
        self.events_tree.bind("<Double-1>", lambda _event: self.show_event_details())
        self.events_count_var = tk.StringVar()
        tk.Label(self.events_tab, textvariable=self.events_count_var, bg=BG, fg=MUTED,
                 font=("Helvetica Neue", 9)).pack(anchor="w", padx=20, pady=(0, 6))

    def _build_alerts(self) -> None:
        self._section_title(self.alerts_tab, "Центр оповещений", "Проверяйте сигналы угроз и отслеживайте ход расследования.")
        controls = tk.Frame(self.alerts_tab, bg=BG)
        controls.pack(fill="x", padx=20, pady=(0, 12))
        ttk.Button(controls, text="Взять в работу", command=lambda: self.update_alert_status("ACKNOWLEDGED")).pack(side="left")
        ttk.Button(controls, text="Закрыть сигнал", command=lambda: self.update_alert_status("RESOLVED")).pack(side="left", padx=8)
        ttk.Button(controls, text="Открыть повторно", command=lambda: self.update_alert_status("OPEN")).pack(side="left")
        ttk.Button(controls, text="Расследование и заметки", command=self.show_alert_details).pack(side="right")
        frame = tk.Frame(self.alerts_tab, bg=BG)
        frame.pack(fill="both", expand=True, padx=20, pady=(0, 18))
        self.alerts_tree = self._make_tree(frame, ("id", "time", "ip", "rule", "severity", "status", "message"),
                                           (55, 155, 130, 190, 90, 125, 420))
        self._attach_scrollbars(frame, self.alerts_tree)
        self.alerts_tree.bind("<Double-1>", lambda _event: self.show_alert_details())

    def _build_rules(self) -> None:
        self._section_title(self.rules_tab, "Правила детекции", "Три правила анализируют время самих событий, включая импортированные архивные логи.")
        card = tk.Frame(self.rules_tab, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1, padx=24, pady=22)
        card.pack(fill="x", padx=22, pady=8)
        tk.Label(card, text="ПРАВИЛО 001  /  ПЕРЕБОР ПАРОЛЕЙ SSH",
                 bg=PANEL, fg=GREEN, font=("Helvetica Neue", 11, "bold")).pack(anchor="w")
        tk.Label(card, text="Находит повторные неудачные попытки входа с одного IP-адреса за заданный интервал времени.",
                 bg=PANEL, fg=MUTED, font=("Helvetica Neue", 9), wraplength=760,
                 justify="left").pack(anchor="w", pady=(8, 18))
        form = tk.Frame(card, bg=PANEL)
        form.pack(anchor="w")
        tk.Label(form, text="ПОРОГ НЕУДАЧНЫХ ПОПЫТОК", bg=PANEL, fg=MUTED,
                 font=("Helvetica Neue", 8, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 10))
        tk.Label(form, text="ИНТЕРВАЛ В МИНУТАХ", bg=PANEL, fg=MUTED,
                 font=("Helvetica Neue", 8, "bold")).grid(row=0, column=1, sticky="w", padx=(18, 10))
        self.threshold_var = tk.StringVar(value=str(self.threshold))
        self.window_var = tk.StringVar(value=str(self.window_minutes))
        tk.Spinbox(form, from_=2, to=100, textvariable=self.threshold_var, width=8,
                   bg=PANEL_2, fg=TEXT, insertbackground=TEXT, relief="flat").grid(
                       row=1, column=0, sticky="w", pady=(8, 0))
        tk.Spinbox(form, from_=1, to=1440, textvariable=self.window_var, width=8,
                   bg=PANEL_2, fg=TEXT, insertbackground=TEXT, relief="flat").grid(
                       row=1, column=1, sticky="w", padx=(18, 10), pady=(8, 0))
        tk.Label(form, text="УНИКАЛЬНЫХ ПОРТОВ", bg=PANEL, fg=MUTED,
                 font=("Helvetica Neue", 8, "bold")).grid(row=0, column=2, sticky="w", padx=(18, 10))
        self.port_threshold_var = tk.StringVar(value=str(self.port_threshold))
        tk.Spinbox(form, from_=2, to=1000, textvariable=self.port_threshold_var, width=8,
                   bg=PANEL_2, fg=TEXT, insertbackground=TEXT, relief="flat").grid(
                       row=1, column=2, sticky="w", padx=(18, 10), pady=(8, 0))
        ttk.Button(form, text="Применить настройки", command=self.save_rule_settings).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(18, 0))
        tk.Label(card, text="Правило 002: успешный вход после серии неудачных попыток с того же IP. "
                            "Правило 003: обращения к разным портам назначения. Повторная проверка не создаёт дубли сигналов.",
                 bg=PANEL, fg="#71839b", font=("Helvetica Neue", 8), wraplength=760,
                 justify="left").pack(anchor="w", pady=(20, 0))
        info = tk.Frame(self.rules_tab, bg="#172b40", padx=20, pady=16)
        info.pack(fill="x", padx=22, pady=14)
        tk.Label(info, text="О ПРОЕКТЕ", bg="#172b40", fg=BLUE,
                 font=("Helvetica Neue", 9, "bold")).pack(anchor="w")
        tk.Label(info, text="Порог попыток применяется к правилам 001 и 002, порог портов — к правилу 003. "
                            "Интервал общий для трёх правил. Настройки сохраняются в локальной базе. Закрытый сигнал сохраняет свой статус.",
                 bg="#172b40", fg=TEXT, font=("Helvetica Neue", 9), wraplength=760,
                 justify="left").pack(anchor="w", pady=(6, 0))

    def _attach_scrollbars(self, parent: tk.Widget, tree: ttk.Treeview) -> None:
        ybar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        xbar = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

    # --------------------------- INGESTION ---------------------------
    def add_demo_events(self) -> None:
        try:
            count = seed_demo(self.db)
            self.status_var.set(f"Добавлено демо-событий: {count}. Запустите детекцию: доступны три сценария угроз.")
            self.refresh_all()
        except (sqlite3.Error, ValueError) as error:
            messagebox.showerror("Ошибка демо-данных", str(error), parent=self.root)

    def load_log_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Импорт журнала событий",
            filetypes=(("Логи и события", "*.log *.txt *.out *.jsonl *.csv"), ("Все файлы", "*.*")))
        if not filename:
            return
        self.root.configure(cursor="watch")
        self.root.update_idletasks()
        try:
            result = import_log_file(self.db, filename)
            self.status_var.set(f"Импортировано: {result.imported} · Повторов: {result.duplicates} · "
                                f"Пропущено: {result.skipped} · {Path(filename).name}")
            self.refresh_all()
        except (OSError, sqlite3.Error, ValueError) as error:
            messagebox.showerror("Ошибка импорта", str(error), parent=self.root)
        finally:
            self.root.configure(cursor="")

    def save_rule_settings(self) -> None:
        try:
            threshold = int(self.threshold_var.get())
            window = int(self.window_var.get())
            ports = int(self.port_threshold_var.get())
            if not 2 <= threshold <= 100 or not 1 <= window <= 1440 or not 2 <= ports <= 1000:
                raise ValueError("Попытки: 2–100; интервал: 1–1440 минут; порты: 2–1000.")
            with self.db:
                for key, value in (("threshold", threshold), ("window_minutes", window), ("port_threshold", ports)):
                    set_setting(self.db, key, str(value))
            self.threshold, self.window_minutes, self.port_threshold = threshold, window, ports
            self.refresh_dashboard()
            self.status_var.set("Настройки сохранены и будут восстановлены при следующем запуске.")
        except (ValueError, sqlite3.Error) as error:
            messagebox.showwarning("Проверьте настройки", str(error), parent=self.root)

    def run_detection(self) -> None:
        self._perform_detection(select_results=True)

    def _perform_detection(self, select_results=False) -> None:
        try:
            result = detect_threats(self.db, self.threshold, self.window_minutes,
                                    port_threshold=self.port_threshold)
            self.status_var.set(f"Проверка завершена · Подозрительных IP: {result.suspicious_ips} · "
                                f"Новых сигналов: {result.new_alerts}")
            self.refresh_all()
            if select_results:
                self.notebook.select(self.alerts_tab)
        except (ValueError, sqlite3.Error) as error:
            messagebox.showerror("Ошибка детекции", str(error), parent=self.root)

    def update_alert_status(self, status: str) -> None:
        selected = self.alerts_tree.selection()
        if not selected:
            messagebox.showinfo("Выберите сигнал", "Сначала выберите строку в центре оповещений.", parent=self.root)
            return
        alert_id = int(self.alerts_tree.item(selected[0], "values")[0])
        try:
            changed = change_alert_status(self.db, alert_id, status)
            self.status_var.set(f"Сигнал №{alert_id}: {status}." if changed else "Статус уже установлен.")
            self.refresh_all()
        except (sqlite3.Error, ValueError) as error:
            messagebox.showerror("Ошибка изменения статуса", str(error), parent=self.root)

    def show_alert_details(self) -> None:
        selected = self.alerts_tree.selection()
        if not selected:
            messagebox.showinfo("Выберите сигнал", "Выберите строку оповещения для расследования.", parent=self.root)
            return
        alert_id = int(self.alerts_tree.item(selected[0], "values")[0])
        row = self.db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if row is None:
            return
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Расследование · Сигнал №{alert_id}")
        dialog.geometry("970x780")
        dialog.minsize(820, 680)
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        tk.Label(dialog, text=f"{row['rule_name']}  /  {row['source_ip']}", bg=BG, fg=TEXT,
                 font=("Helvetica Neue", 17, "bold")).pack(anchor="w", padx=22, pady=(20, 8))
        tk.Label(dialog, text=row['description'], bg=BG, fg=MUTED, wraplength=880,
                 justify="left", font=("Helvetica Neue", 10)).pack(anchor="w", padx=22, pady=(0, 14))
        notebook = ttk.Notebook(dialog)
        # The main navigation uses hidden notebook tabs; this dialog uses explicit buttons.
        tabs = [tk.Frame(notebook, bg=BG) for _ in range(3)]
        actions = tk.Frame(dialog, bg=BG)
        actions.pack(fill="x", padx=20)
        for index, title in enumerate(("События-основания", "Заметки аналитика", "История статусов")):
            ttk.Button(actions, text=title, command=lambda i=index: notebook.select(i)).pack(side="left", padx=(0, 8))
            notebook.add(tabs[index])
        notebook.pack(fill="both", expand=True, padx=20, pady=12)
        evidence_frame = tk.Frame(tabs[0], bg=BG)
        evidence_frame.pack(fill="both", expand=True)
        tree = self._make_tree(evidence_frame, ("time", "type", "port", "message"), (160, 170, 75, 490))
        self._attach_scrollbars(evidence_frame, tree)
        evidence = self.db.execute("SELECT e.timestamp,e.event_type,e.destination_port,e.message "
                                   "FROM events e JOIN alert_events ae ON ae.event_id=e.id "
                                   "WHERE ae.alert_id=? ORDER BY e.timestamp,e.id", (alert_id,)).fetchall()
        for event in evidence:
            tree.insert("", "end", values=tuple('' if value is None else value for value in event))
        tk.Label(tabs[0], text=f"Событий-оснований: {len(evidence)}. У старых сигналов связи с событиями могут отсутствовать.",
                 bg=BG, fg=MUTED, font=("Helvetica Neue", 9)).pack(anchor="w", pady=8)
        notes_view = tk.Text(tabs[1], height=12, bg=PANEL, fg=TEXT, relief="flat",
                             wrap="word", font=("Helvetica Neue", 11), padx=12, pady=12)
        notes_view.pack(fill="both", expand=True)
        entry = tk.Text(tabs[1], height=4, bg=PANEL_2, fg=TEXT, insertbackground=TEXT,
                        relief="flat", wrap="word", font=("Helvetica Neue", 11), padx=10, pady=10)
        entry.pack(fill="x", pady=(12, 8))
        def refresh_notes():
            notes_view.configure(state="normal")
            notes_view.delete("1.0", "end")
            for note in get_alert_notes(self.db, alert_id):
                notes_view.insert("end", f"{note['created_at']}\n{note['note']}\n\n")
            if not notes_view.get("1.0", "end").strip():
                notes_view.insert("end", "Заметок пока нет. Добавьте выводы расследования ниже.")
            notes_view.configure(state="disabled")
        def save_note():
            try:
                add_alert_note(self.db, alert_id, entry.get("1.0", "end").strip())
                entry.delete("1.0", "end")
                refresh_notes()
                self.status_var.set(f"Заметка к сигналу №{alert_id} сохранена.")
            except (ValueError, sqlite3.Error) as error:
                messagebox.showwarning("Заметка не сохранена", str(error), parent=dialog)
        ttk.Button(tabs[1], text="Сохранить заметку", command=save_note, style="Accent.TButton").pack(anchor="e")
        refresh_notes()
        history_frame = tk.Frame(tabs[2], bg=BG)
        history_frame.pack(fill="both", expand=True)
        history = self._make_tree(history_frame, ("time", "previous", "status"), (180, 230, 230))
        self._attach_scrollbars(history_frame, history)
        for item in self.db.execute("SELECT changed_at,from_status,to_status FROM alert_history WHERE alert_id=? ORDER BY id", (alert_id,)):
            history.insert("", "end", values=tuple('Создан' if value is None else value for value in item))
        ttk.Button(dialog, text="Закрыть расследование", command=dialog.destroy).pack(anchor="e", padx=20, pady=(0, 16))

    def show_event_details(self) -> None:
        selected = self.events_tree.selection()
        if not selected:
            return
        event_id = int(selected[0].split("-")[-1])
        row = self.db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if row:
            messagebox.showinfo("Подробности события",
                f"Время: {row['timestamp']}\nIP-источник: {row['source_ip']}\n"
                f"Назначение: {row['destination_ip'] or '—'}:{row['destination_port'] or '—'}\n"
                f"Тип: {row['event_type']} · Приоритет: {row['severity']}\n"
                f"Файл: {row['source_file'] or '—'}\n\n{row['message']}", parent=self.root)

    def refresh_all(self) -> None:
        self.refresh_dashboard()
        self._draw_activity()
        self.refresh_events()
        self.refresh_alerts()

    def refresh_dashboard(self) -> None:
        self.total_var.set(str(self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]))
        self.alert_count_var.set(str(self.db.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]))
        self.open_alert_var.set(str(self.db.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0]))
        self.ip_count_var.set(str(self.db.execute("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL").fetchone()[0]))
        self.profile_var.set(f"3 правила · {self.window_minutes} мин\nПеребор: {self.threshold} попыток\nПорты: {self.port_threshold} уникальных")
        for item in self.recent_tree.get_children():
            self.recent_tree.delete(item)
        rows = self.db.execute("SELECT timestamp, source_ip, event_type, severity FROM events ORDER BY id DESC LIMIT 12").fetchall()
        for index, row in enumerate(rows):
            self.recent_tree.insert("", "end", values=tuple(row), tags=(row["severity"], "alternate" if index % 2 else ""))

    def refresh_events(self) -> None:
        if not hasattr(self, "events_tree"):
            return
        self.events_tree.delete(*self.events_tree.get_children())
        where, params = event_filter(self.search_var.get().strip(), self.severity_filter.get())
        total = self.db.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()[0]
        rows = self.db.execute("SELECT id,timestamp,source_ip,event_type,severity,message,destination_port,source_file "
                               "FROM events" + where + " ORDER BY timestamp DESC,id DESC LIMIT 2000", params)
        shown = 0
        for index, row in enumerate(rows):
            self.events_tree.insert("", "end", iid=f"event-{row['id']}",
                values=tuple('' if value is None else value for value in tuple(row)[1:]),
                tags=(row['severity'], "alternate" if index % 2 else ""))
            shown += 1
        self.events_count_var.set(f"Показано: {shown} из {total}. CSV включает все найденные события.")

    def refresh_alerts(self) -> None:
        selected = self.alerts_tree.selection()
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        rows = self.db.execute("SELECT id,created_at,source_ip,rule_name,severity,status,description FROM alerts ORDER BY id DESC LIMIT 1000")
        for index, row in enumerate(rows):
            self.alerts_tree.insert("", "end", iid=f"alert-{row['id']}", values=tuple(row),
                                   tags=(row['status'], "alternate" if index % 2 else ""))
        if selected and self.alerts_tree.exists(selected[0]):
            self.alerts_tree.selection_set(selected[0])

    def export_events(self) -> None:
        filename = filedialog.asksaveasfilename(title="Экспорт событий", defaultextension=".csv",
            filetypes=(("Файлы CSV", "*.csv"),), initialfile="cyberwatch_events.csv")
        if not filename:
            return
        try:
            count = export_events_csv(self.db, filename, search=self.search_var.get().strip(),
                                      severity=self.severity_filter.get())
            self.status_var.set(f"Экспортировано событий: {count} · {Path(filename).name}")
            messagebox.showinfo("Экспорт завершён", f"Сохранено событий: {count}", parent=self.root)
        except (OSError, sqlite3.Error, ValueError) as error:
            messagebox.showerror("Ошибка экспорта", str(error), parent=self.root)

    def _load_rule_settings(self) -> None:
        for key, default, low, high in (("threshold", 5, 2, 100), ("window_minutes", 10, 1, 1440),
                                         ("port_threshold", 10, 2, 1000)):
            try:
                value = int(get_setting(self.db, key, str(default)))
                if not low <= value <= high:
                    raise ValueError
            except (ValueError, TypeError):
                value = default
            setattr(self, key, value)

    def _build_live(self) -> None:
        self._section_title(self.live_tab, "Наблюдение за логом",
                            "Новые строки выбранного файла поступают в журнал и проверяются правилами детекции.")
        card = tk.Frame(self.live_tab, bg=PANEL, padx=24, pady=24,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=20)
        self.live_path_var = tk.StringVar(value=get_setting(self.db, "last_live_path", ""))
        tk.Label(card, text="ФАЙЛ ЖУРНАЛА", bg=PANEL, fg=MUTED,
                 font=("Helvetica Neue", 9, "bold")).pack(anchor="w")
        self.live_path_entry = tk.Entry(card, textvariable=self.live_path_var, bg=PANEL_2, fg=TEXT,
                                       insertbackground=TEXT, relief="flat", font=("Helvetica Neue", 11))
        self.live_path_entry.pack(fill="x", ipady=9, pady=(10, 14))
        controls = tk.Frame(card, bg=PANEL)
        controls.pack(fill="x")
        ttk.Button(controls, text="Выбрать лог", command=self.choose_live_file).pack(side="left", padx=(0, 8))
        self.live_start_button = ttk.Button(controls, text="Начать наблюдение", style="Accent.TButton", command=self.start_live)
        self.live_start_button.pack(side="left", padx=(0, 8))
        self.live_stop_button = ttk.Button(controls, text="Остановить", command=self.stop_live, state="disabled")
        self.live_stop_button.pack(side="left")
        self.live_auto_var = tk.BooleanVar(value=True)
        tk.Checkbutton(card, text="Автоматически проверять новые события", variable=self.live_auto_var,
                       bg=PANEL, fg=TEXT, activebackground=PANEL, activeforeground=TEXT,
                       selectcolor=PANEL_2, font=("Helvetica Neue", 10)).pack(anchor="w", pady=(18, 4))
        self.live_status_var = tk.StringVar(value="Остановлено · Выберите файл и начните наблюдение.")
        tk.Label(card, textvariable=self.live_status_var, bg=PANEL, fg=GREEN,
                 font=("Helvetica Neue", 11), wraplength=760, justify="left").pack(anchor="w", pady=(14, 0))
        info = tk.Frame(self.live_tab, bg="#172b40", padx=22, pady=20)
        info.pack(fill="x", padx=20, pady=18)
        tk.Label(info, text="КАК ЭТО РАБОТАЕТ", bg="#172b40", fg=BLUE,
                 font=("Helvetica Neue", 10, "bold")).pack(anchor="w")
        tk.Label(info, text="Наблюдение начинается с конца файла: существующие строки можно загрузить через импорт. "
                 "Приложение читает только добавленные завершённые строки, учитывает обнуление и замену файла. "
                 "Поддерживаются текстовые SSH, UFW и JSONL-логи. CSV загружайте через импорт. "
                 "После закрытия приложения наблюдение останавливается.", bg="#172b40", fg=TEXT,
                 wraplength=760, justify="left", font=("Helvetica Neue", 11)).pack(anchor="w", pady=(10, 0))

    def choose_live_file(self) -> None:
        if self.tailer is not None:
            messagebox.showinfo("Наблюдение активно", "Остановите наблюдение перед сменой файла.", parent=self.root)
            return
        filename = filedialog.askopenfilename(title="Выберите лог для наблюдения",
            filetypes=(("Текстовые журналы", "*.log *.txt *.out *.jsonl"), ("Все файлы", "*.*")))
        if filename:
            self.live_path_var.set(filename)

    def start_live(self) -> None:
        if self.tailer is not None:
            return
        filename = self.live_path_var.get().strip()
        if not filename:
            messagebox.showinfo("Выберите лог", "Укажите путь к текстовому журналу.", parent=self.root)
            return
        try:
            if Path(filename).suffix.lower() == ".csv":
                raise ValueError("Для CSV используйте импорт в журнале событий.")
            self.tailer = LogTailer(filename, from_start=False)
            with self.db:
                set_setting(self.db, "last_live_path", str(Path(filename).expanduser().resolve()))
            self.live_imported = self.live_skipped = 0
            self.live_path_entry.configure(state="disabled")
            self.live_start_button.configure(state="disabled")
            self.live_stop_button.configure(state="normal")
            self.live_status_var.set("● Наблюдение активно · Ожидание новых строк…")
            self.live_job = self.root.after(1000, self._poll_live)
        except (OSError, ValueError, sqlite3.Error) as error:
            if self.tailer is not None:
                self.tailer.close()
                self.tailer = None
            messagebox.showerror("Не удалось начать наблюдение", str(error), parent=self.root)

    def _poll_live(self) -> None:
        self.live_job = None
        if self.tailer is None or self._closed:
            return
        try:
            lines = self.tailer.read_new()
            if lines:
                with self.db:
                    result = ingest_lines(self.db, lines, self.tailer.source_id,
                                          source_file=str(Path(self.live_path_var.get()).expanduser().resolve()))
                self.live_imported += result.imported
                self.live_skipped += result.skipped
                self.live_status_var.set(f"● Наблюдение активно · Добавлено: {self.live_imported} · Пропущено: {self.live_skipped}")
                if result.imported:
                    if self.live_auto_var.get():
                        self._perform_detection()
                    else:
                        self.refresh_all()
            self.live_job = self.root.after(1000, self._poll_live)
        except (OSError, ValueError, sqlite3.Error) as error:
            self.stop_live()
            self.live_status_var.set(f"Наблюдение остановлено: {error}")
            self.status_var.set("Проверьте доступ к выбранному логу и начните наблюдение снова.")

    def stop_live(self) -> None:
        if self.live_job is not None:
            self.root.after_cancel(self.live_job)
            self.live_job = None
        if self.tailer is not None:
            self.tailer.close()
            self.tailer = None
        if hasattr(self, "live_status_var"):
            self.live_status_var.set(f"Остановлено · Добавлено за сеанс: {self.live_imported}")
            self.live_path_entry.configure(state="normal")
            self.live_start_button.configure(state="normal")
            self.live_stop_button.configure(state="disabled")

    def _build_reports(self) -> None:
        self._section_title(self.reports_tab, "Отчёты и демонстрация",
                            "Сохраните результаты расследования или покажите работу приложения на учебных сценариях.")
        for title, description, button, command in (
            ("Отчёт по безопасности", "Автономный HTML-файл: показатели, сигналы, события-основания, заметки и история статусов. "
             "Его можно открыть в браузере без интернета.", "Сохранить отчёт HTML", self.export_report),
            ("События в CSV", "Экспорт учитывает поиск и приоритет, выбранные в журнале событий. В файл попадут все "
             "найденные записи, включая те, что не поместились в таблице.", "Экспорт событий CSV", self.export_events),
            ("Три сценария угроз", "Учебные данные: перебор паролей, успешный вход после серии отказов и обращения "
             "к множеству портов. После добавления запустите детекцию. Повторное добавление не создаёт дубли.",
             "Добавить демо-события", self.add_demo_events),
        ):
            card = tk.Frame(self.reports_tab, bg=PANEL, padx=22, pady=18,
                            highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", padx=20, pady=(0, 14))
            ttk.Button(card, text=button, command=command).pack(side="right", padx=(20, 0))
            tk.Label(card, text=title, bg=PANEL, fg=TEXT, font=("Helvetica Neue", 13, "bold")).pack(anchor="w")
            tk.Label(card, text=description, bg=PANEL, fg=MUTED, font=("Helvetica Neue", 10),
                     wraplength=530, justify="left").pack(anchor="w", pady=(8, 0))

    def export_report(self) -> None:
        filename = filedialog.asksaveasfilename(title="Сохранить отчёт по безопасности", defaultextension=".html",
            filetypes=(("HTML-отчёт", "*.html"),), initialfile="cyberwatch_report.html")
        if not filename:
            return
        try:
            count = export_report_html(self.db, filename)
            self.status_var.set(f"Отчёт сохранён · Сигналов: {count} · {Path(filename).name}")
            messagebox.showinfo("Отчёт готов", f"Сохранён файл {Path(filename).name}. Откройте его в браузере.", parent=self.root)
        except (OSError, ValueError, sqlite3.Error) as error:
            messagebox.showerror("Ошибка отчёта", str(error), parent=self.root)


    def close(self) -> None:
        if self._closed:
            return
        self.stop_live()
        self._closed = True
        self.root.after_cancel(self.clock_job)
        self.db.close()
        self.root.destroy()
