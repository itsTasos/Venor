#include "mainwindow.h"
#include <algorithm>
#include <cmath>
#include <tlhelp32.h>
namespace vnr {
static QFont mono() {
    QFont f("Cascadia Mono", 10);
    f.setStyleHint(QFont::Monospace);
    return f;
}
static QString link(quint64 a, QString label = {}) {
    return "<a title='" + hex(a) + "' href='va:" + QString::number(a, 16) + "'>" +
           (label.isEmpty() ? hex(a) : label.toHtmlEscaped()) + "</a>";
}
QVariant InstructionModel::headerData(int s, Qt::Orientation o, int role) const {
    return role == Qt::DisplayRole && o == Qt::Horizontal
               ? QStringList{"State", "Address", "Bytes", "Instruction", "Annotation"}.value(s)
               : QVariant();
}
QVariant InstructionModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= code.size())
        return {};
    const auto &i = code[index.row()];
    if (role == Qt::UserRole)
        return QVariant::fromValue(i.address);
    if (role == Qt::FontRole) {
        auto font = mono();
        font.setPointSize(fontPointSize);
        return font;
    }
    if (role == Qt::BackgroundRole && i.address == ip)
        return QColor("#254864");
    if (role == Qt::ForegroundRole && i.address == ip)
        return QColor("#e3e8ee");
    if (role == Qt::ToolTipRole)
        return i.fact + "\n" + i.unknown;
    if (role != Qt::DisplayRole)
        return {};
    switch (index.column()) {
    case 0: {
        QString marks = i.address == ip ? "IP " : "";
        if (workspace) {
            if (workspace->bookmarks.contains(i.address))
                marks += "◆ ";
            for (auto &b : workspace->breakpoints)
                if (b.bound == i.address && b.enabled)
                    marks += "●";
        }
        return marks;
    }
    case 1:
        return hex(i.address);
    case 2:
        return QString::fromLatin1(i.bytes.toHex(' '));
    case 3:
        return i.text;
    case 4:
        return workspace ? workspace->renames.value(i.address) + " " + workspace->comments.value(i.address)
                         : QString();
    }
    return {};
}
QVariant RowModel::data(const QModelIndex &i, int role) const {
    if (!i.isValid() || i.row() >= rows.size())
        return {};
    auto &r = rows[i.row()];
    if (role == Qt::UserRole)
        return QVariant::fromValue(r.address);
    if (role == Qt::FontRole && i.column() == 0)
        return mono();
    if (role == Qt::ToolTipRole)
        return r.name + "\n" + r.detail;
    if (role != Qt::DisplayRole)
        return {};
    return i.column() == 0 ? hex(r.address) : i.column() == 1 ? r.name : r.detail;
}
QTableView *MainWindow::table(QAbstractItemModel *m) {
    auto *t = new QTableView;
    t->setModel(m);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setAlternatingRowColors(true);
    t->verticalHeader()->hide();
    t->verticalHeader()->setDefaultSectionSize(25);
    t->horizontalHeader()->setStretchLastSection(true);
    t->setWordWrap(false);
    t->setSortingEnabled(false);
    t->setColumnWidth(0, 165);
    t->setColumnWidth(1, 190);
    t->setContextMenuPolicy(Qt::ActionsContextMenu);
    auto *copyValue = new QAction("Copy selected value", t);
    copyValue->setShortcut(QKeySequence::Copy);
    copyValue->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    t->addAction(copyValue);
    connect(copyValue, &QAction::triggered, t, [t] {
        if (t->currentIndex().isValid())
            QApplication::clipboard()->setText(t->currentIndex().data().toString());
    });
    auto *copyAddress = new QAction("Copy address / raw value", t);
    t->addAction(copyAddress);
    connect(copyAddress, &QAction::triggered, t, [t] {
        if (t->currentIndex().isValid())
            QApplication::clipboard()->setText(hex(t->currentIndex().data(Qt::UserRole).toULongLong()));
    });
    return t;
}
QDockWidget *MainWindow::dock(QString title, QString id, QWidget *content, Qt::DockWidgetArea area) {
    auto *d = new QDockWidget(title, this);
    d->setObjectName(id);
    d->setWidget(content);
    d->setMinimumSize(180, 100);
    addDockWidget(area, d);
    docks << d;
    return d;
}
MainWindow::MainWindow(AiService *ai) : debugger(this), providedAiService(ai) {
    auto available = QGuiApplication::primaryScreen()->availableGeometry().size();
    resize(std::min(1520, available.width() - 40), std::min(940, available.height() - 60));
    setMinimumSize(900, 600);
    setAcceptDrops(true);
    setDockNestingEnabled(true);
    setWindowTitle(QApplication::applicationDisplayName() + "[*] — Windows x64 workstation");
    auto *file = menuBar()->addMenu("&File");
    auto *debug = menuBar()->addMenu("&Debug");
    auto *investigate = menuBar()->addMenu("&Investigate");
    auto *view = menuBar()->addMenu("&View");
    auto *help = menuBar()->addMenu("&Help");
    auto action = [&](QMenu *menu, QString title, QKeySequence key, auto fn) {
        auto *a = menu->addAction(title);
        a->setShortcut(key);
        a->setToolTip(title + " (" + key.toString() + ")");
        connect(a, &QAction::triggered, this, fn);
        return a;
    };
    auto *open = action(file, "Open &Binary…", QKeySequence::Open, [this] { chooseBinary(); });
    open->setObjectName("openBinaryAction");
    action(file, "Open &Investigation…", QKeySequence("Ctrl+Shift+O"), [this] { chooseInvestigation(); });
    auto *save = action(file, "&Save Investigation", QKeySequence::Save, [this] { saveInvestigation(); });
    save->setIconText("Save");
    action(file, "Save Investigation As…", QKeySequence("Ctrl+Shift+S"), [this] {
        QString p = QFileDialog::getSaveFileName(this, "Save Investigation", {}, "Investigation (*.venor)");
        if (!p.isEmpty())
            saveInvestigation(p);
    });
    recentMenu = file->addMenu("Recent Investigations");
    file->addSeparator();
    action(file, "Exit", QKeySequence("Alt+F4"), [this] { close(); });
    launchAction = action(debug, "Start Target…", QKeySequence("Ctrl+F5"), [this] { launch(); });
    attachAction = action(debug, "Attach to Process…", QKeySequence("Ctrl+Alt+A"), [this] { attach(); });
    debug->addSeparator();
    runAction = action(debug, "Continue", QKeySequence("F5"), [this] { debugger.command("run"); });
    pauseAction = action(debug, "Pause", QKeySequence("F6"), [this] { debugger.pause(); });
    intoAction = action(debug, "Step Into", QKeySequence("F7"), [this] { debugger.command("into"); });
    overAction = action(debug, "Step Over", QKeySequence("F8"), [this] { debugger.command("over"); });
    outAction = action(debug, "Step Out", QKeySequence("Shift+F8"), [this] { debugger.command("out"); });
    auto *currentInstruction = action(debug, "Show Current Instruction", QKeySequence("Ctrl+I"),
                                      [this] { debugger.command("refresh"); });
    currentInstruction->setObjectName("currentInstructionAction");
    currentInstruction->setEnabled(false);
    connect(&debugger, &Debugger::stateChanged, currentInstruction,
            [currentInstruction](Debugger::State state, QString) {
                currentInstruction->setEnabled(state == Debugger::State::Paused);
            });
    action(debug, "Continue Exception as Unhandled", QKeySequence("Ctrl+F9"),
           [this] { debugger.command("pass"); });
    action(debug, "Continue Exception as Handled", QKeySequence("Ctrl+Shift+F9"),
           [this] { debugger.command("handled"); });
    detachAction = action(debug, "Detach (leave target running)", QKeySequence("Shift+F5"),
                          [this] { debugger.command("detach"); });
    debug->addSeparator();
    action(debug, "New Breakpoint…", QKeySequence("Ctrl+B"), [this] { editBreakpoint(); });
    auto *toggleBreakpoint = action(debug, "Toggle Breakpoint at Selection", QKeySequence("F9"), [this] {
        if (loading) {
            statusBar()->showMessage("Wait for analysis or cancel it before changing breakpoints.", 4000);
            return;
        }
        if (!work.selected)
            return;
        if (evidenceCode) {
            error("Saved runtime addresses may belong to a past process. Use a module+RVA or a current "
                  "runtime address in the custom breakpoint editor.");
            return;
        }
        QString expr = liveCode ? hex(work.selected)
                       : image  ? QFileInfo(image->path).completeBaseName() + "+0x" +
                                      QString::number(work.selected - image->base, 16)
                                : hex(work.selected);
        auto it = std::find_if(work.breakpoints.begin(), work.breakpoints.end(),
                               [&](auto &b) { return b.expression == expr; });
        if (it != work.breakpoints.end())
            work.breakpoints.erase(it);
        else {
            Breakpoint b;
            b.expression = expr;
            work.breakpoints << b;
        }
        changed();
        refreshBreakpoints();
        syncPolicies();
    });
    action(debug, "Breakpoint Presets…", QKeySequence("Ctrl+Shift+B"), [this] { presets(); });
    action(investigate, "Go to Address / Symbol…", QKeySequence("Ctrl+G"), [this] {
        bool ok;
        auto s = QInputDialog::getText(
            this, "Navigate", "Hex address, function, import, export or renamed symbol:", QLineEdit::Normal,
            {}, &ok);
        if (ok)
            goExpression(s);
    });
    auto *searchAction = action(investigate, "Search Binary…", QKeySequence::Find, [this] { search(); });
    searchAction->setIconText("Search…");
    action(investigate, "Follow Operand / Value", QKeySequence("Return"), [this] { follow(); });
    action(investigate, "Cross References", QKeySequence("X"), [this] { xrefs(); });
    action(investigate, "Comment…", QKeySequence(";"), [this] { annotate("Comment"); });
    action(investigate, "Rename Symbol…", QKeySequence("N"), [this] { annotate("Rename"); });
    action(investigate, "Bookmark…", QKeySequence("Ctrl+D"), [this] { annotate("Bookmark"); });
    auto *backAction = action(investigate, "Back", QKeySequence("Alt+Left"), [this] {
        if (historyIndex > 0)
            navigate(history[--historyIndex], false);
    });
    auto *forwardAction = action(investigate, "Forward", QKeySequence("Alt+Right"), [this] {
        if (historyIndex + 1 < history.size())
            navigate(history[++historyIndex], false);
    });
    action(investigate, "Command Palette…", QKeySequence("Ctrl+Shift+P"), [this] { commandPalette(); });
    auto *toolbar = addToolBar("Main controls");
    toolbar->setObjectName("mainToolbar");
    toolbar->setMovable(false);
    toolbar->addAction(open);
    toolbar->addAction(save);
    toolbar->addAction(searchAction);
    toolbar->addSeparator();
    toolbar->addAction(launchAction);
    toolbar->addAction(attachAction);
    toolbar->addSeparator();
    for (auto *a : {runAction, pauseAction, intoAction, overAction, outAction})
        toolbar->addAction(a);
    launchAction->setIconText("Start Debugging…");
    intoAction->setToolTip("Step Into (F7) — execute one instruction; enter a called function");
    overAction->setToolTip("Step Over (F8) — execute the next instruction; stop after a normal call returns");
    outAction->setToolTip("Step Out (Shift+F8) — continue until the current function returns");
    auto *navigateToolbar = addToolBar("Navigation");
    navigateToolbar->setObjectName("navigationToolbar");
    addToolBarBreak();
    addToolBar(Qt::TopToolBarArea, navigateToolbar);
    navigateToolbar->addAction(backAction);
    navigateToolbar->addAction(forwardAction);
    location = new QLineEdit;
    location->setObjectName("location");
    location->setPlaceholderText("Address or symbol   ·   Ctrl+G to navigate, Ctrl+F to search");
    location->setMinimumWidth(180);
    location->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    location->setAccessibleName("Navigate to address or symbol");
    connect(location, &QLineEdit::returnPressed, this, [this] { goExpression(location->text()); });
    navigateToolbar->addWidget(location);
    workspaceCombo = new QComboBox;
    workspaceCombo->setObjectName("workspacePreset");
    workspaceCombo->addItems({"Beginner", "Analyst", "Expert"});
    workspaceCombo->setCurrentText("Analyst");
    workspaceCombo->setToolTip("Workspace density — every pane remains available from View");
    navigateToolbar->addWidget(workspaceCombo);
    connect(workspaceCombo, &QComboBox::currentTextChanged, this, &MainWindow::presetLayout);
    stateLabel = new QLabel("STATIC FILE");
    stateLabel->setObjectName("sessionState");
    stateLabel->setContentsMargins(16, 0, 8, 0);
    navigateToolbar->addWidget(stateLabel);
    pages = new QStackedWidget;
    auto *content = new QWidget;
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(8, 4, 8, 4);
    auto *sessionRow = new QHBoxLayout;
    sessionInfo = new QLabel(
        "Open a binary to inspect code. Start Debugging or Attach only when you choose to execute.");
    sessionInfo->setObjectName("sessionContext");
    sessionInfo->setWordWrap(true);
    sessionInfo->setTextFormat(Qt::PlainText);
    sessionInfo->setTextInteractionFlags(Qt::TextSelectableByMouse);
    sessionRow->addWidget(sessionInfo, 1);
    auto *returnToStop = new QToolButton;
    returnToStop->setDefaultAction(currentInstruction);
    returnToStop->setText("Current instruction");
    returnToStop->setToolTip("Return to the actual stopped instruction without executing (Ctrl+I)");
    returnToStop->setToolButtonStyle(Qt::ToolButtonTextOnly);
    sessionRow->addWidget(returnToStop);
    contentLayout->addLayout(sessionRow);
    contentLayout->addWidget(pages, 1);
    setCentralWidget(content);
    auto *welcome = new QWidget;
    welcome->setObjectName("welcome");
    auto *wl = new QVBoxLayout(welcome);
    wl->setContentsMargins(56, 36, 56, 36);
    wl->addStretch();
    auto *title = new QLabel(QApplication::applicationDisplayName());
    QFont titleFont = title->font();
    titleFont.setPointSize(30);
    titleFont.setBold(true);
    title->setFont(titleFont);
    wl->addWidget(title);
    auto *subtitle = new QLabel("Understand native code. Follow the evidence.");
    subtitle->setWordWrap(true);
    QFont sf = subtitle->font();
    sf.setPointSize(16);
    subtitle->setFont(sf);
    wl->addWidget(subtitle);
    auto *desc = new QLabel(
        "Open a Windows x64 executable or DLL to inspect its assembly, imports and structure.\nStart or "
        "attach a target only when you choose. Analysis and investigations stay local.");
    desc->setWordWrap(true);
    wl->addSpacing(14);
    wl->addWidget(desc);
    wl->addSpacing(22);
    auto *buttons = new QHBoxLayout;
    for (auto pair : QList<QPair<QString, QAction *>>{{"Open Binary…", open},
                                                      {"Start Debugging…", launchAction},
                                                      {"Attach to Process…", attachAction}}) {
        auto *b = new QPushButton(pair.first);
        b->setMinimumHeight(38);
        connect(b, &QPushButton::clicked, pair.second, &QAction::trigger);
        buttons->addWidget(b);
    }
    buttons->addStretch();
    wl->addLayout(buttons);
    wl->addSpacing(28);
    wl->addWidget(new QLabel("RECENT INVESTIGATIONS"));
    recents = new QListWidget;
    recents->setMaximumHeight(145);
    wl->addWidget(recents);
    connect(recents, &QListWidget::itemActivated, this,
            [this](auto *i) { openInvestigation(i->data(Qt::UserRole).toString()); });
    wl->addStretch();
    pages->addWidget(welcome);
    center = new QTabWidget;
    center->setDocumentMode(true);
    center->setObjectName("codeTabs");
    pages->addWidget(center);
    codeModel = new InstructionModel(this);
    codeModel->workspace = &work;
    codeView = table(codeModel);
    codeView->setObjectName("disassembly");
    codeView->setColumnWidth(0, 52);
    codeView->setColumnWidth(1, 164);
    codeView->setColumnWidth(2, 165);
    codeView->setColumnWidth(3, 370);
    center->addTab(codeView, "Assembly");
    connect(codeView->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](auto current, auto) { selectInstruction(current); });
    flowScene = new QGraphicsScene(this);
    flowView = new QGraphicsView(flowScene);
    flowView->setRenderHint(QPainter::Antialiasing);
    flowView->setDragMode(QGraphicsView::ScrollHandDrag);
    flowView->setObjectName("flowGraph");
    center->addTab(flowView, "Flow");
    readable = new QTextBrowser;
    readable->setOpenLinks(false);
    readable->setObjectName("meaning");
    readable->setFont(QApplication::font());
    auto explanationFont = QApplication::font();
    explanationFont.setPointSizeF(10);
    readable->setFont(explanationFont);
    readable->document()->setDefaultStyleSheet(
        "h3 { margin-bottom: 5px; } p { margin-top: 5px; margin-bottom: 10px; } td { padding: 4px; }");
    center->addTab(readable, "Meaning");
    center->setTabToolTip(0, "Exact decoded instructions; shared selection with Meaning and Flow");
    center->setTabToolTip(1, "Basic-block control flow; double-click a block to select it");
    center->setTabToolTip(2, "Block-local high-level explanations with links to the source instructions");
    connect(readable, &QTextBrowser::anchorClicked, this, &MainWindow::contextLink);
    auto *mem = new QWidget;
    auto *ml = new QVBoxLayout(mem);
    auto *mbar = new QHBoxLayout;
    auto *ma = new QLineEdit;
    ma->setPlaceholderText("Hex address or debugger expression, e.g. @rsp");
    auto *read = new QPushButton("Read Memory");
    mbar->addWidget(ma);
    mbar->addWidget(read);
    ml->addLayout(mbar);
    hexView = new QPlainTextEdit;
    hexView->setReadOnly(true);
    hexView->setFont(mono());
    ml->addWidget(hexView);
    center->addTab(mem, "Hex / Memory");
    connect(read, &QPushButton::clicked, this, [this, ma] {
        if (debugger.state() == Debugger::State::Paused)
            debugger.command("memory", ma->text());
        else {
            bool ok;
            auto a = ma->text().toULongLong(&ok, 16);
            if (ok && image) {
                navigate(a);
                center->setCurrentIndex(3);
            } else
                error("A valid file address or paused debug session is required.");
        }
    });
    navModel = new RowModel(this);
    navProxy = new QSortFilterProxyModel(this);
    navProxy->setSourceModel(navModel);
    navProxy->setFilterKeyColumn(-1);
    navProxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    navView = table(navProxy);
    navView->hideColumn(2);
    navView->horizontalHeader()->moveSection(1, 0);
    navView->horizontalHeader()->setStretchLastSection(false);
    navView->setColumnWidth(0, 160);
    navView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    navView->setObjectName("navigator");
    navView->installEventFilter(this);
    auto *explorer = new QWidget;
    auto *el = new QVBoxLayout(explorer);
    el->setContentsMargins(6, 6, 6, 6);
    navKind = new QComboBox;
    navKind->addItems({"Functions", "Imports", "Exports / Symbols", "Strings", "Sections", "Metadata",
                       "Bookmarks", "History / Trail", "Xrefs"});
    navFilter = new QLineEdit;
    navFilter->setPlaceholderText("Filter navigator…");
    el->addWidget(navKind);
    el->addWidget(navFilter);
    el->addWidget(navView);
    exploreDock = dock("Explorer", "explorer", explorer, Qt::LeftDockWidgetArea);
    connect(navKind, &QComboBox::currentIndexChanged, this, [this] { refreshNavigation(); });
    connect(navFilter, &QLineEdit::textChanged, navProxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(navView, &QTableView::activated, this, [this](auto i) {
        auto address = i.siblingAtColumn(0).data(Qt::UserRole).toULongLong();
        navigate(navKind->currentIndex() < 6 ? relocateStatic(address) : address);
    });
    auto *context = new QTabWidget;
    inspector = new QTextBrowser;
    inspector->setObjectName("explanation");
    inspector->setOpenLinks(false);
    inspector->setFont(explanationFont);
    inspector->document()->setDefaultStyleSheet(
        "h3 { margin-top: 6px; margin-bottom: 6px; } td { padding: 4px; } p { margin-bottom: 10px; }");
    auto *explanationPage = new QWidget;
    auto *explanationLayout = new QVBoxLayout(explanationPage);
    explanationLayout->setContentsMargins(0, 0, 0, 0);
    explanationLayout->addWidget(inspector, 1);
    auto *explanationActions = new QHBoxLayout;
    technicalToggle = new QToolButton;
    technicalToggle->setObjectName("instructionDetails");
    technicalToggle->setText("Instruction details");
    technicalToggle->setCheckable(true);
    technicalToggle->setArrowType(Qt::RightArrow);
    technicalToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    explanationActions->addWidget(technicalToggle);
    auto *assemblyButton = new QPushButton("Assembly");
    assemblyButton->setToolTip("Show the exact instructions for this selection");
    explanationActions->addWidget(assemblyButton);
    explanationLayout->addLayout(explanationActions);
    auto *breakpointButton = new QToolButton;
    breakpointButton->setDefaultAction(toggleBreakpoint);
    breakpointButton->setText("Toggle breakpoint (F9)");
    breakpointButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    explanationLayout->addWidget(breakpointButton);
    context->addTab(explanationPage, "Explanation");
    connect(assemblyButton, &QPushButton::clicked, this, [this] {
        center->setCurrentIndex(0);
        codeView->setFocus();
    });
    connect(technicalToggle, &QToolButton::toggled, this, [this](bool expanded) {
        technicalExpanded = expanded;
        technicalToggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
        auto row = codeView->currentIndex().row();
        if (row >= 0 && row < codeModel->code.size())
            explain(codeModel->code[row]);
    });
    notes = new QPlainTextEdit;
    notes->setObjectName("investigationNotes");
    notes->setPlaceholderText("Investigation notes — saved locally with the workspace");
    context->addTab(notes, "Notes");
    contextDock = dock("Explanation / Context", "context", context, Qt::RightDockWidgetArea);
    contextDock->setMinimumWidth(300);
    connect(notes, &QPlainTextEdit::textChanged, this, [this] {
        work.notes = notes->toPlainText();
        changed();
    });
    connect(inspector, &QTextBrowser::anchorClicked, this, &MainWindow::contextLink);
    regModel = new RowModel(this);
    stackModel = new RowModel(this);
    frameModel = new RowModel(this);
    threadModel = new RowModel(this);
    moduleModel = new RowModel(this);
    regModel->headers = {"Value", "Register / flags", "Meaning"};
    threadModel->headers = {"Engine ID", "Windows thread ID", "State"};
    auto *regs = table(regModel);
    registerDock = dock("Registers / Flags", "registers", regs, Qt::BottomDockWidgetArea);
    auto *stack = table(stackModel);
    stackDock = dock("Stack", "stack", stack, Qt::BottomDockWidgetArea);
    auto *frames = table(frameModel);
    framesDock = dock("Call Stack", "frames", frames, Qt::BottomDockWidgetArea);
    auto *threads = table(threadModel);
    threadsDock = dock("Threads", "threads", threads, Qt::BottomDockWidgetArea);
    auto *modules = table(moduleModel);
    modulesDock = dock("Modules", "modules", modules, Qt::BottomDockWidgetArea);
    connect(regs, &QTableView::activated, this,
            [this](auto i) { navigate(regModel->rows[i.row()].address); });
    connect(stack, &QTableView::activated, this,
            [this](auto i) { goExpression(stackModel->rows[i.row()].name); });
    connect(frames, &QTableView::activated, this,
            [this](auto i) { navigate(frameModel->rows[i.row()].address); });
    connect(modules, &QTableView::activated, this, [this](auto i) {
        debugger.command("memory", hex(moduleModel->rows[i.row()].address));
        center->setCurrentIndex(3);
    });
    connect(threads, &QTableView::activated, this, [this](auto i) {
        debugger.command("thread", QString::number(threadModel->rows[i.row()].address));
    });
    bpModel = new QStandardItemModel(this);
    bpView = table(bpModel);
    bpView->setObjectName("breakpoints");
    auto *bps = new QWidget;
    auto *bl = new QVBoxLayout(bps);
    bl->setContentsMargins(4, 4, 4, 4);
    auto *bb = new QHBoxLayout;
    auto bpButton = [&](QString name, auto fn) {
        auto *b = new QPushButton(name);
        bb->addWidget(b);
        connect(b, &QPushButton::clicked, this, fn);
    };
    bpButton("New…", [this] { editBreakpoint(); });
    bpButton("Presets…", [this] { presets(); });
    bpButton("Edit…", [this] {
        auto i = bpView->currentIndex();
        if (i.isValid())
            editBreakpoint(i.row());
    });
    bpButton("Enable / Disable", [this] {
        auto i = bpView->currentIndex();
        if (i.isValid()) {
            work.breakpoints[i.row()].enabled = !work.breakpoints[i.row()].enabled;
            changed();
            refreshBreakpoints();
            syncPolicies();
        }
    });
    bpButton("Remove", [this] {
        auto i = bpView->currentIndex();
        if (i.isValid()) {
            work.breakpoints.removeAt(i.row());
            changed();
            refreshBreakpoints();
            syncPolicies();
        }
    });
    bpButton("Group…", [this] {
        bool ok;
        QStringList groups;
        for (auto &b : work.breakpoints)
            if (!groups.contains(b.group))
                groups << b.group;
        if (groups.isEmpty())
            return;
        auto group = QInputDialog::getItem(this, "Breakpoint group", "Group", groups, 0, false, &ok);
        if (!ok)
            return;
        auto enable = QMessageBox::question(this, "Group state",
                                            "Enable all breakpoints in " + group + "? Choose No to disable.",
                                            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);
        if (enable == QMessageBox::Cancel)
            return;
        for (auto &b : work.breakpoints)
            if (b.group == group)
                b.enabled = enable == QMessageBox::Yes;
        changed();
        refreshBreakpoints();
        syncPolicies();
    });
    bb->addStretch();
    bl->addLayout(bb);
    bl->addWidget(bpView);
    breakpointsDock = dock("Breakpoints", "breakpointsDock", bps, Qt::BottomDockWidgetArea);
    connect(bpView, &QTableView::doubleClicked, this, [this](auto i) { editBreakpoint(i.row()); });
    timelineModel = new QStandardItemModel(this);
    timelineView = table(timelineModel);
    timelineView->setObjectName("timeline");
    auto *events = new QTabWidget;
    auto *eventPane = new QWidget;
    auto *evl = new QVBoxLayout(eventPane);
    evl->setContentsMargins(4, 4, 4, 4);
    auto *eventFilter = new QLineEdit;
    eventFilter->setPlaceholderText("Search captured events (type, address, details)…");
    evl->addWidget(eventFilter);
    // Side-by-side event list/details avoid imposing two scroll-area minimum
    // heights on every dock tab, including empty Registers at high DPI.
    auto *split = new QSplitter(Qt::Horizontal);
    split->addWidget(timelineView);
    eventDetail = new QTextBrowser;
    eventDetail->setObjectName("eventDetail");
    eventDetail->setOpenLinks(false);
    split->addWidget(eventDetail);
    evl->addWidget(split);
    events->addTab(eventPane, "Observed events");
    eventScene = new QGraphicsScene(this);
    eventView = new QGraphicsView(eventScene);
    eventView->setDragMode(QGraphicsView::ScrollHandDrag);
    events->addTab(eventView, "Evidence relationships");
    timelineDock = dock("Timeline / Evidence", "timeline", events, Qt::BottomDockWidgetArea);
    connect(eventFilter, &QLineEdit::textChanged, this, [this](const QString &filter) {
        for (int n = 0; n < work.events.size(); n++) {
            auto &e = work.events[n];
            timelineView->setRowHidden(
                n, !(e.type + e.detail + hex(e.address)).contains(filter, Qt::CaseInsensitive));
        }
    });
    connect(timelineView->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](auto i, auto) { eventSelection(i); });
    connect(eventDetail, &QTextBrowser::anchorClicked, this, [this](QUrl u) {
        if (u.scheme() == "evidence") {
            int index = timelineView->currentIndex().row();
            if (index >= 0 && index < work.events.size()) {
                const auto &event = work.events[index];
                if (!event.code.isEmpty()) {
                    displayedEvidence = event;
                    evidenceCode = true;
                    liveCode = false;
                    codeModel->ip = 0;
                    codeModel->reset(decode(event.code, event.ip));
                    navigate(event.ip);
                    center->setCurrentIndex(0);
                    fileLabel->setText("Saved process bytes · " + event.time + " UTC · thread " +
                                       QString::number(event.thread));
                }
            }
        } else
            navigate(u.toString().mid(3).toULongLong(nullptr, 16));
    });
    output = new QPlainTextEdit;
    output->setReadOnly(true);
    output->setFont(mono());
    output->setMaximumBlockCount(5000);
    outputDock = dock("Output / Diagnostics", "output", output, Qt::BottomDockWidgetArea);
    auto *settingsMenu = new QMenu("&Settings", this);
    menuBar()->insertMenu(help->menuAction(), settingsMenu);
    setupAi(investigate, settingsMenu);
    setupDecompiler(investigate, settingsMenu);
    for (auto *d : docks)
        view->addAction(d->toggleViewAction());
    view->addSeparator();
    action(view, "Restore Current Workspace Layout", {},
           [this] { presetLayout(workspaceCombo->currentText()); });
    auto *light = view->addAction("Light theme");
    light->setCheckable(true);
    connect(light, &QAction::toggled, this, [this](bool l) {
        theme(l);
        QSettings().setValue("light", l);
    });
    light->setChecked(QSettings().value("light", false).toBool());
    theme(light->isChecked());
    action(view, "Zoom In", QKeySequence::ZoomIn, [this] {
        if (center->currentIndex() == 1)
            flowView->scale(1.2, 1.2);
        else if (center->currentIndex() == 2)
            readable->zoomIn();
        else if (center->currentIndex() == 4)
            pseudocode->zoomIn();
        else {
            codeModel->fontPointSize = std::min(22, codeModel->fontPointSize + 1);
            auto font = mono();
            font.setPointSize(codeModel->fontPointSize);
            hexView->setFont(font);
            codeView->verticalHeader()->setDefaultSectionSize(QFontMetrics(font).height() + 8);
            codeView->viewport()->update();
        }
    });
    action(view, "Zoom Out", QKeySequence::ZoomOut, [this] {
        if (center->currentIndex() == 1)
            flowView->scale(1 / 1.2, 1 / 1.2);
        else if (center->currentIndex() == 2)
            readable->zoomOut();
        else if (center->currentIndex() == 4)
            pseudocode->zoomOut();
        else {
            codeModel->fontPointSize = std::max(8, codeModel->fontPointSize - 1);
            auto font = mono();
            font.setPointSize(codeModel->fontPointSize);
            hexView->setFont(font);
            codeView->verticalHeader()->setDefaultSectionSize(QFontMetrics(font).height() + 8);
            codeView->viewport()->update();
        }
    });
    action(help, "Keyboard Shortcuts / Guide", QKeySequence("F1"), [this] {
        QMessageBox::information(
            this, "Investigation guide",
            "Open PE: Ctrl+O · Save: Ctrl+S · Navigate: Ctrl+G · Search: Ctrl+F\nCommand palette: "
            "Ctrl+Shift+P · Back/Forward: Alt+Left/Right\nBreakpoint: F9 · Custom: Ctrl+B · Presets: "
            "Ctrl+Shift+B\nStart: Ctrl+F5 · Continue: F5 · Pause: F6 · Into: F7 · Over: F8 · Out: "
            "Shift+F8\nFollow: Enter · Xrefs: X · Comment: ; · Rename: N · Bookmark: Ctrl+D\n\nStatic "
            "analysis uses preferred PE addresses. Live code uses relocated process addresses. F9 on static "
            "code creates a module+RVA breakpoint.\nRun/attach always executes on this Windows machine; use "
            "an isolated VM for unknown files.\nTimeline contains captured events only, not a full execution "
            "trace.\nConditions use DbgEng MASM expressions (hex by default; 0n for decimal).\nContinue "
            "passes target exceptions unhandled; explicitly choose Handled only when appropriate.\n\nSee "
            "README.md beside the executable for limits and licensing.");
    });
    action(help, "About", {}, [this] {
        QMessageBox::about(this, QApplication::applicationDisplayName(),
                           "Native Windows x64 analysis · Qt 6 · Zydis · Microsoft DbgEng\nLocal "
                           "deterministic analysis with optional, consent-based AI explanations.\nVersion " +
                               QApplication::applicationVersion());
    });
    fileLabel = new QLabel("No binary loaded");
    statusBar()->addWidget(fileLabel, 1);
    progress = new QProgressBar;
    progress->setMaximumWidth(180);
    progress->setRange(0, 0);
    progress->hide();
    statusBar()->addPermanentWidget(progress);
    cancelAction = new QAction("Cancel analysis", this);
    connect(cancelAction, &QAction::triggered, this, [this] {
        if (cancel)
            *cancel = true;
    });
    cancelButton = new QToolButton;
    cancelButton->setDefaultAction(cancelAction);
    statusBar()->addPermanentWidget(cancelButton);
    cancelButton->hide();
    cancelAction->setVisible(false);
    connect(&watcher, &QFutureWatcher<std::shared_ptr<Binary>>::finished, this, [this] {
        loading = false;
        pages->setEnabled(true);
        notes->setEnabled(true);
        exploreDock->widget()->setEnabled(true);
        breakpointsDock->widget()->setEnabled(true);
        launchAction->setEnabled(true);
        attachAction->setEnabled(true);
        progress->hide();
        cancelAction->setVisible(false);
        cancelButton->hide();
        try {
            auto loaded = watcher.result();
            if (!loaded->analysisError.isEmpty())
                throw std::runtime_error(loaded->analysisError.toStdString());
            if (restoring && pendingWorkspace && !pendingWorkspace->hash.isEmpty() &&
                pendingWorkspace->hash != loaded->hash)
                throw std::runtime_error("Binary SHA-256 differs from saved evidence. Reopen the original "
                                         "binary; evidence was not rebound.");
            if (restoring && pendingWorkspace) {
                work = *pendingWorkspace;
                workspacePath = pendingWorkspacePath;
                pendingWorkspace.reset();
            }
            image = loaded;
            openDecompiler();
            meaningKey.clear();
            displayedEvidence.reset();
            liveCode = false;
            evidenceCode = false;
            if (!restoring) {
                work = Workspace{};
                work.binary = image->path;
                work.hash = image->hash;
                workspacePath.clear();
                notes->clear();
                history.clear();
                historyIndex = -1;
            } else {
                QSignalBlocker block(notes);
                notes->setPlainText(work.notes);
            }
            codeModel->reset(image->code);
            pages->setCurrentIndex(1);
            center->setCurrentIndex(GhidraConfig::load().error().isEmpty() ? 4 : 2);
            refreshNavigation();
            refreshBreakpoints();
            refreshTimeline();
            fileLabel->setText(QFileInfo(image->path).fileName() + " · x64 PE · " +
                               QString::number(image->code.size()) +
                               " decoded rows · static preferred addresses");
            if (restoring) {
                if (!work.layout.isEmpty())
                    restoreState(work.layout);
                if (!work.geometry.isEmpty())
                    restoreGeometry(work.geometry);
            }
            navigate(work.selected ? work.selected : image->entry);
            compactDecompilerLayout =
                restoring ? registerDock->isHidden() : GhidraConfig::load().error().isEmpty();
            if (compactDecompilerLayout)
                QTimer::singleShot(0, this, [this] {
                    if (compactDecompilerLayout && !debugger.isRunning())
                        setDebuggerPanesVisible(false);
                });
            restoring = false;
            dirty = false;
            setWindowModified(false);
            syncPolicies();
        } catch (const std::exception &e) {
            restoring = false;
            pendingWorkspace.reset();
            error(QString::fromUtf8(e.what()));
            fileLabel->setText(image ? QFileInfo(image->path).fileName() : "No binary loaded");
        }
        updateSessionInfo();
    });
    connect(&debugger, &Debugger::stopped, this, &MainWindow::snapshot);
    connect(&debugger, &Debugger::stateChanged, this, &MainWindow::debuggerState);
    connect(&debugger, &Debugger::error, this, [this](auto message) {
        output->appendPlainText("ERROR: " + message);
        statusBar()->showMessage(message, 15000);
        outputDock->show();
        outputDock->raise();
    });
    connect(&debugger, &Debugger::output, this, [this](auto text) {
        output->moveCursor(QTextCursor::End);
        output->insertPlainText(text);
    });
    connect(&debugger, &Debugger::eventRecorded, this, [this](Event e) {
        if (work.events.size() >= 10000) {
            work.events.removeFirst();
            output->appendPlainText("Timeline retention: oldest event removed at 10,000-event limit.");
        }
        work.events << e;
        changed();
        refreshTimeline();
    });
    connect(&debugger, &Debugger::breakpointChanged, this, [this](Breakpoint b) {
        for (auto &p : work.breakpoints)
            if (p.id == b.id) {
                p = b;
                break;
            }
        refreshBreakpoints();
    });
    baselineLayout = saveState();
    presetLayout("Analyst");
    QSettings settings;
    if (settings.contains("layout"))
        restoreState(settings.value("layout").toByteArray());
    if (settings.contains("geometry"))
        restoreGeometry(settings.value("geometry").toByteArray());
    updateRecents();
    refreshBreakpoints();
    debuggerState(Debugger::State::Disconnected, "Static inspection · disconnected");
    inspector->setHtml("<h3>Explanation / Context</h3><p>Select an instruction to inspect facts, derived "
                       "relationships and uncertainties, with links back to the bytes.</p><p>Open a binary "
                       "for static inspection. Runtime values appear only after a real debugger stop.</p>");
}
void MainWindow::changed() {
    dirty = true;
    setWindowModified(true);
}
void MainWindow::error(QString message) {
    output->appendPlainText("ERROR: " + message);
    QMessageBox::warning(this, "Investigation could not continue", message);
}
bool MainWindow::confirmDiscard() {
    if (!dirty)
        return true;
    auto a = QMessageBox::question(this, "Unsaved investigation",
                                   "Save your notes, breakpoints and captured evidence before continuing?",
                                   QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    return a == QMessageBox::Discard || (a == QMessageBox::Save && saveInvestigation());
}
void MainWindow::chooseBinary() {
    auto path = QFileDialog::getOpenFileName(this, "Open PE for static inspection — does not execute", {},
                                             "Windows x64 PE (*.exe *.dll);;All files (*)");
    if (!path.isEmpty())
        openBinary(path);
}
void MainWindow::chooseInvestigation() {
    auto p = QFileDialog::getOpenFileName(this, "Open Investigation", {}, "Investigation (*.venor)");
    if (!p.isEmpty())
        openInvestigation(p);
}
void MainWindow::openBinary(const QString &path, bool restore) {
    if (aiPanel)
        aiPanel->sourceChanged(QUuid::createUuid().toByteArray());
    if (loading) {
        statusBar()->showMessage("Wait for analysis to finish or cancel it.");
        return;
    }
    if (debugger.isRunning()) {
        error("Detach the current target before opening a different binary.");
        return;
    }
    if (!restore && !confirmDiscard())
        return;
    restoring = restore;
    if (decompiler)
        decompiler->close();
    decompiled.reset();
    requestedDecompilation.clear();
    loading = true;
    pages->setEnabled(false);
    notes->setEnabled(false);
    exploreDock->widget()->setEnabled(false);
    breakpointsDock->widget()->setEnabled(false);
    launchAction->setEnabled(false);
    attachAction->setEnabled(false);
    cancel = std::make_shared<std::atomic_bool>(false);
    progress->show();
    cancelAction->setVisible(true);
    cancelButton->show();
    fileLabel->setText("Analyzing " + QFileInfo(path).fileName() + "…");
    updateSessionInfo();
    auto cancellation = cancel;
    watcher.setFuture(QtConcurrent::run([path, cancellation] {
        try {
            return analyze(path, cancellation);
        } catch (const std::exception &e) {
            auto failed = std::make_shared<Binary>();
            failed->analysisError = QString::fromUtf8(e.what());
            return failed;
        }
    }));
}
void MainWindow::openInvestigation(const QString &path) {
    if (loading || debugger.isRunning()) {
        error("Finish analysis and detach the target before opening an investigation.");
        return;
    }
    if (!confirmDiscard())
        return;
    try {
        auto loaded = loadWorkspace(path);
        if (aiPanel)
            aiPanel->sourceChanged(QUuid::createUuid().toByteArray());
        if (loaded.binary.isEmpty() && loaded.hash.isEmpty()) {
            work = std::move(loaded);
            workspacePath = path;
            image.reset();
            meaningKey.clear();
            meaning = {};
            displayedEvidence.reset();
            readable->setHtml("<h2>Saved investigation</h2><p>Select a Timeline event and open its captured "
                              "instruction bytes.</p>");
            flowScene->clear();
            liveCode = false;
            evidenceCode = false;
            codeModel->ip = 0;
            codeModel->reset({});
            pages->setCurrentIndex(1);
            {
                QSignalBlocker block(notes);
                notes->setPlainText(work.notes);
            }
            history = work.trail;
            historyIndex = history.size() - 1;
            timelineModel->removeRows(0, timelineModel->rowCount());
            refreshNavigation();
            refreshBreakpoints();
            refreshTimeline();
            if (!work.geometry.isEmpty())
                restoreGeometry(work.geometry);
            if (!work.layout.isEmpty())
                restoreState(work.layout);
            timelineDock->show();
            timelineDock->raise();
            inspector->setHtml(
                "<h3>Saved investigation</h3><p>This investigation has no associated static binary. Select "
                "an event in Timeline to inspect captured context and open its saved instruction bytes.</p>");
            fileLabel->setText("Saved evidence · no associated static binary");
            stateLabel->setText("SAVED INVESTIGATION");
            sessionInfo->setText("Saved investigation · no live process. Choose an event in Timeline to "
                                 "inspect its historical snapshot.");
            location->setText(work.selected ? hex(work.selected) : QString());
            updateRecents(path);
            syncPolicies();
            dirty = false;
            setWindowModified(false);
            return;
        }
        if (!QFileInfo::exists(loaded.binary)) {
            auto replacement = QFileDialog::getOpenFileName(
                this, "Locate original binary (SHA-256 must match)", {}, "Windows PE (*.exe *.dll)");
            if (replacement.isEmpty())
                return;
            loaded.binary = replacement;
        }
        pendingWorkspace = loaded;
        pendingWorkspacePath = path;
        updateRecents(path);
        openBinary(loaded.binary, true);
    } catch (const std::exception &e) {
        error(QString::fromUtf8(e.what()));
    }
}
bool MainWindow::saveInvestigation(QString path) {
    if (loading) {
        error("Wait for analysis before saving.");
        return false;
    }
    if (path.isEmpty())
        path = workspacePath;
    if (path.isEmpty())
        path = QFileDialog::getSaveFileName(this, "Save Investigation", {}, "Investigation (*.venor)");
    if (path.isEmpty())
        return false;
    if (!path.endsWith(".venor", Qt::CaseInsensitive))
        path += ".venor";
    try {
        work.layout = saveState();
        work.geometry = saveGeometry();
        saveWorkspace(path, work);
        workspacePath = path;
        dirty = false;
        setWindowModified(false);
        updateRecents(path);
        statusBar()->showMessage(
            "Investigation saved locally — historical evidence is separate from live state", 6000);
        return true;
    } catch (const std::exception &e) {
        error(QString::fromUtf8(e.what()));
        return false;
    }
}
void MainWindow::closeEvent(QCloseEvent *e) {
    if (!confirmDiscard()) {
        e->ignore();
        return;
    }
    if (debugger.isRunning()) {
        auto response = QMessageBox::question(this, "Active debug session",
                                              "Detach and close? The target will continue running.",
                                              QMessageBox::Yes | QMessageBox::Cancel);
        if (response != QMessageBox::Yes) {
            e->ignore();
            return;
        }
        debugger.command("detach");
        debugger.pause();
    }
    if (cancel)
        *cancel = true;
    watcher.waitForFinished();
    QSettings s;
    s.setValue("layout", saveState());
    s.setValue("geometry", saveGeometry());
    e->accept();
}
void MainWindow::dragEnterEvent(QDragEnterEvent *e) {
    if (e->mimeData()->hasUrls() && e->mimeData()->urls().size() == 1 &&
        e->mimeData()->urls().first().isLocalFile())
        e->acceptProposedAction();
}
void MainWindow::dropEvent(QDropEvent *e) {
    auto path = e->mimeData()->urls().first().toLocalFile();
    if (path.endsWith(".venor", Qt::CaseInsensitive))
        openInvestigation(path);
    else
        openBinary(path);
}
void MainWindow::resizeEvent(QResizeEvent *event) {
    QMainWindow::resizeEvent(event);
    if (!codeView || !center)
        return;
    codeView->setColumnHidden(2, center->width() < 700);
    codeView->setColumnHidden(4, center->width() < 1000);
}
bool MainWindow::eventFilter(QObject *object, QEvent *event) {
    if (object == navView && event->type() == QEvent::Resize)
        navView->setColumnHidden(0, navView->width() < 340);
    return QMainWindow::eventFilter(object, event);
}
void MainWindow::updateRecents(QString path) {
    QSettings s;
    auto paths = s.value("recents").toStringList();
    if (!path.isEmpty()) {
        paths.removeAll(path);
        paths.prepend(path);
        while (paths.size() > 10)
            paths.removeLast();
        s.setValue("recents", paths);
    }
    recentMenu->clear();
    recents->clear();
    for (auto &p : paths) {
        auto *a = recentMenu->addAction(p);
        connect(a, &QAction::triggered, this, [this, p] { openInvestigation(p); });
        auto *item = new QListWidgetItem(QFileInfo(p).fileName() + "   ·   " + p, recents);
        item->setData(Qt::UserRole, p);
        item->setToolTip(p);
    }
    if (paths.isEmpty()) {
        auto *item = new QListWidgetItem("Saved investigations will appear here.", recents);
        item->setFlags(Qt::NoItemFlags);
    }
}
void MainWindow::refreshNavigation() {
    QVector<Row> rows;
    if (image) {
        switch (navKind->currentIndex()) {
        case 0:
            rows = image->functions;
            if (decompiler && !decompiler->functions().isEmpty()) {
                rows.clear();
                for (const auto &f : decompiler->functions())
                    rows << Row{f.entry, f.name, f.signature + " · Ghidra recovered"};
            }
            for (auto &r : rows)
                if (work.renames.contains(r.address))
                    r.name = work.renames[r.address];
            break;
        case 1:
            rows = image->imports;
            break;
        case 2:
            rows = image->exports;
            break;
        case 3:
            rows = image->strings;
            break;
        case 4:
            for (auto &s : image->sections)
                rows << Row{image->base + s.rva, s.name,
                            QString("raw %1 · virtual %2 · %3%4%5")
                                .arg(s.rawSize)
                                .arg(s.virtualSize)
                                .arg(s.flags & IMAGE_SCN_MEM_READ ? "R" : "-",
                                     s.flags & IMAGE_SCN_MEM_WRITE ? "W" : "-",
                                     s.flags & IMAGE_SCN_MEM_EXECUTE ? "X" : "-")};
            break;
        case 5:
            rows = {{image->entry, "Entry point", image->dll ? "x64 DLL" : "x64 executable"},
                    {image->base, "Preferred image base", "Image size " + hex(image->imageSize)},
                    {0, "SHA-256", image->hash},
                    {0, "File", image->path},
                    {0, "Analysis",
                     "Linear sweep of executable raw sections. Function candidates from "
                     "entry/exports/unwind/direct calls; not complete recovery."}};
            break;
        case 6:
            for (auto it = work.bookmarks.begin(); it != work.bookmarks.end(); ++it)
                rows << Row{it.key(), it.value(), work.comments.value(it.key())};
            break;
        case 7:
            for (auto a : work.trail)
                rows << Row{a, "Visited address", work.comments.value(a)};
            break;
        case 8:
            for (auto a : image->xrefs.values(work.selected))
                rows << Row{a, "Reference to " + hex(work.selected), "Decoded relative operand"};
            if (decompiled) {
                rows.clear();
                for (auto value : decompiled->data["callers"].toArray()) {
                    auto ref = value.toObject();
                    auto from = ref["from"].toString().mid(2).toULongLong(nullptr, 16);
                    rows << Row{relocateStatic(from), "Incoming " + ref["kind"].toString(),
                                "Ghidra reference to " + hex(decompiled->entry)};
                }
                for (auto value : decompiled->data["references"].toArray()) {
                    auto ref = value.toObject();
                    auto to = ref["to"].toString().mid(2).toULongLong(nullptr, 16);
                    if (!to)
                        to = ref["from"].toString().mid(2).toULongLong(nullptr, 16);
                    rows << Row{relocateStatic(to), ref["name"].toString(),
                                "Ghidra " + ref["kind"].toString() + " from " + ref["from"].toString()};
                }
            }
            break;
        }
    }
    if (!image && navKind->currentIndex() == 6)
        for (auto it = work.bookmarks.begin(); it != work.bookmarks.end(); ++it)
            rows << Row{it.key(), it.value(), work.comments.value(it.key())};
    if (!image && navKind->currentIndex() == 7)
        for (auto a : work.trail)
            rows << Row{a, "Visited address", work.comments.value(a)};
    navModel->reset(rows);
}
void MainWindow::navigate(quint64 a, bool recordHistory) {
    if (loading) {
        statusBar()->showMessage("Wait for analysis or cancel it before navigating.", 4000);
        return;
    }
    if (!a)
        return;
    if (recordHistory) {
        if (historyIndex + 1 < history.size())
            history.resize(historyIndex + 1);
        if (history.isEmpty() || history.last() != a) {
            history << a;
            historyIndex = history.size() - 1;
        }
        if (work.trail.isEmpty() || work.trail.last() != a) {
            work.trail << a;
            while (work.trail.size() > 5000)
                work.trail.removeFirst();
            changed();
        }
    }
    work.selected = a;
    location->setText(hex(a));
    int row = -1;
    auto find = [&](const QVector<Instruction> &c) {
        auto it = std::lower_bound(c.begin(), c.end(), a,
                                   [](auto &i, quint64 target) { return i.address < target; });
        return it != c.end() && it->address == a ? int(it - c.begin()) : -1;
    };
    row = find(codeModel->code);
    if (row < 0 && image && !(liveCode && debugger.state() == Debugger::State::Paused)) {
        int n = image->instructionIndex(a);
        if (n >= 0) {
            liveCode = false;
            evidenceCode = false;
            codeModel->reset(image->code);
            row = n;
        }
    }
    if (row >= 0) {
        pages->setCurrentIndex(1);
        codeView->setCurrentIndex(codeModel->index(row, 0));
        codeView->scrollTo(codeModel->index(row, 0), QAbstractItemView::PositionAtCenter);
        explain(codeModel->code[row]);
    } else if (debugger.state() == Debugger::State::Paused) {
        debugger.command("disassemble", hex(a));
        center->setCurrentIndex(0);
        statusBar()->showMessage("Reading live memory at " + hex(a), 4000);
    } else if (image) {
        auto bytes = image->bytesAt(a, 1024);
        if (bytes.isEmpty()) {
            statusBar()->showMessage("No mapped raw bytes at " + hex(a), 5000);
            return;
        }
        QString text = "Static file bytes at " + hex(a) + "\n";
        for (int n = 0; n < bytes.size(); n += 16)
            text += hex(a + n) + "  " + QString::fromLatin1(bytes.mid(n, 16).toHex(' ')) + "\n";
        hexView->setPlainText(text);
        center->setCurrentIndex(3);
        inspector->setHtml(
            "<h3>Raw data</h3><p>" + link(a) +
            "</p><p>No decoded instruction begins here. No instruction meaning is asserted.</p>");
    }
    if (navKind->currentIndex() >= 6)
        refreshNavigation();
}
void MainWindow::selectInstruction(const QModelIndex &i) {
    if (!i.isValid() || i.row() >= codeModel->code.size())
        return;
    auto instruction = codeModel->code[i.row()];
    if (work.selected != instruction.address) {
        if (historyIndex + 1 < history.size())
            history.resize(historyIndex + 1);
        history << instruction.address;
        historyIndex = history.size() - 1;
        work.trail << instruction.address;
        while (work.trail.size() > 5000)
            work.trail.removeFirst();
        changed();
    }
    work.selected = instruction.address;
    location->setText(hex(instruction.address));
    explain(instruction);
}
QVector<Instruction> MainWindow::selectedFunction() const {
    if (decompiled && !liveCode && !evidenceCode && decompiler) {
        auto *f = decompiler->containing(work.selected);
        if (f && f->entry == decompiled->entry && decompiled->edits == analysisEdits()) {
            const auto &instructions = decompiled->instructions;
            if (instructions.size() <= 1200)
                return instructions;
            auto at = std::lower_bound(instructions.begin(), instructions.end(), work.selected,
                                       [](const auto &i, quint64 a) { return i.address < a; });
            return instructions.mid(std::max(0, int(at - instructions.begin()) - 200), 512);
        }
    }
    auto &code = codeModel->code;
    if (code.isEmpty())
        return {};
    quint64 begin = work.selected, end = begin + 4096;
    if (image && !liveCode && !evidenceCode) {
        auto it = std::upper_bound(image->functions.begin(), image->functions.end(), begin,
                                   [](quint64 a, auto &r) { return a < r.address; });
        if (it != image->functions.begin()) {
            auto previous = it - 1;
            if (begin - previous->address < 65536)
                begin = previous->address;
        }
        if (it != image->functions.end())
            end = std::min(end, it->address);
    }
    auto selected = std::lower_bound(code.begin(), code.end(), work.selected,
                                     [](const Instruction &i, quint64 a) { return i.address < a; });
    auto first = std::lower_bound(code.begin(), code.end(), begin,
                                  [](const Instruction &i, quint64 a) { return i.address < a; });
    // Long functions still need to include the selection in the bounded analysis window.
    if (selected - first > 120) {
        first = selected - 64;
        begin = first->address;
        end = std::max(end, work.selected + 32);
    }
    QVector<Instruction> result;
    for (auto it = first; it != code.end() && it->address < end && result.size() < 160; ++it)
        result << *it;
    return result;
}
void MainWindow::contextLink(const QUrl &url) {
    if (url.scheme() == "details") {
        technicalToggle->toggle();
        return;
    }
    if (url.scheme() != "va" && url.scheme() != "unit" && url.scheme() != "assembly" &&
        url.scheme() != "flow")
        return;
    bool ok = false;
    auto address = url.path().toULongLong(&ok, 16);
    if (!ok)
        return;
    navigate(address);
    if (url.scheme() == "assembly")
        center->setCurrentIndex(0);
    if (url.scheme() == "flow")
        center->setCurrentIndex(1);
}
static QString argumentTable(const QVector<MeaningArgument> &arguments) {
    if (arguments.isEmpty())
        return {};
    QString html = "<table width='100%' cellspacing='0'>";
    for (auto &arg : arguments) {
        html += "<tr><td><b>" + arg.name.toHtmlEscaped() + "</b><br>" + arg.value.toHtmlEscaped() +
                "<br><small>" + arg.source.toHtmlEscaped();
        for (int n = 0; n < arg.evidence.size(); ++n)
            html += " · " + link(arg.evidence[n], "source " + QString::number(n + 1));
        html += "</small></td></tr>";
    }
    return html + "</table>";
}
void MainWindow::updateSessionInfo() {
    auto state = debugger.state();
    QString text;
    if (loading) {
        stateLabel->setText("ANALYZING");
        text = "Analyzing file bytes locally. Navigation is paused until analysis finishes or is cancelled.";
    } else if (evidenceCode && displayedEvidence) {
        stateLabel->setText("SAVED EVIDENCE");
        text = "Historical snapshot · " + displayedEvidence->time + " UTC · thread " +
               QString::number(displayedEvidence->thread) + " · " + displayedEvidence->type +
               ". These are saved values, not current process state.";
    } else if (state == Debugger::State::Running) {
        stateLabel->setText("RUNNING");
        text = "Target running. Pause to inspect current registers and memory. Captured events remain in "
               "Timeline.";
    } else if (state == Debugger::State::Paused) {
        stateLabel->setText("PAUSED · T" + QString::number(live.thread));
        text = "Why stopped: " + live.reason + " · Windows thread " + QString::number(live.thread) +
               " · stopped IP " + hex(live.ip);
        if (work.selected != live.ip)
            text += ". Browsing another address; Current instruction returns to the stop.";
    } else if (state == Debugger::State::Starting) {
        stateLabel->setText("CONNECTING");
        text = "Connecting the native debugger; wait for a stop before inspecting runtime values.";
    } else {
        stateLabel->setText("STATIC FILE");
        text =
            image ? QFileInfo(image->path).fileName() +
                        " · static inspection. Execution and API results have not been observed in this view."
                  : "Open a binary to inspect code. Start Debugging or Attach when you choose to execute.";
    }
    sessionInfo->setText(text);
    stateLabel->setToolTip(text);
}
void MainWindow::explain(const Instruction &i) {
    updateDecompilerSelection();
    if (aiPanel)
        aiPanel->sourceChanged(aiSourceIdentity());
    auto code = selectedFunction();
    QByteArray key = QByteArray::number(code.isEmpty() ? 0 : code.first().address);
    key += liveCode ? "live" : evidenceCode ? "saved" : "file";
    if (image)
        key += image->hash.toLatin1();
    for (auto &in : code) {
        key += QByteArray::number(in.address) + ":" + in.bytes;
    }
    bool rebuilt = key != meaningKey;
    if (rebuilt) {
        meaning = analyzeMeaning(code, !liveCode && !evidenceCode ? image.get() : nullptr);
        meaningKey = key;
    }
    QString source = evidenceCode ? "Saved process bytes (historical snapshot)"
                     : liveCode   ? "Observed process bytes"
                                  : "Static file bytes";
    int selectedUnit = meaning.unitAt.value(i.address, -1);
    QString title = "Instruction", summary = i.fact;
    QVector<MeaningArgument> arguments;
    QVector<quint64> evidence{i.address};
    if (selectedUnit >= 0) {
        const auto &unit = meaning.units[selectedUnit];
        title = unit.title;
        summary = unit.summary;
        arguments = unit.arguments;
        evidence = unit.evidence;
    }
    // A captured API entry is shown as a recorded event with its own time, never as a simulated call.
    const Event *captured = nullptr;
    if (evidenceCode && displayedEvidence && displayedEvidence->ip == i.address)
        captured = &*displayedEvidence;
    else if (liveCode && i.address == live.ip && debugger.state() == Debugger::State::Paused) {
        for (auto it = work.events.crbegin(); it != work.events.crend(); ++it)
            if (it->ip == i.address && it->thread == live.thread && it->registers == live.registers) {
                captured = &*it;
                break;
            }
    }
    auto recorded = captured ? recordedApiArguments(*captured) : QVector<MeaningArgument>();
    if (!recorded.isEmpty()) {
        title = "Recorded API entry · " + captured->api.section('!', 1);
        summary = "Execution reached this API entry with the recorded parameters below. This entry snapshot "
                  "does not establish the return value or successful effects.";
        arguments = recorded;
    } else if (captured && captured->type == "API return") {
        title = "Recorded API return · " + captured->api.section('!', 1);
        summary = "The paired return observer captured RAX = " + hex(captured->registers.value("rax")) +
                  ". Interpret it using the API contract; output buffers and later effects are not captured "
                  "automatically.";
    }
    QString text = "<p><b>" + source.toHtmlEscaped() + "</b></p><h3>What happens here</h3><p><b>" +
                   title.toHtmlEscaped() + "</b></p><p>" + summary.toHtmlEscaped() + "</p>";
    if (!arguments.isEmpty())
        text += "<h4>Inputs</h4>" + argumentTable(arguments);
    if (captured && (!recorded.isEmpty() || captured->type == "API return")) {
        text += "<p><b>Recorded evidence:</b> " + captured->time.toHtmlEscaped() + " UTC · thread " +
                QString::number(captured->thread) + " · " + link(captured->ip) + "</p>";
        for (auto &api : apiCatalog())
            if (api.symbol.compare(captured->api, Qt::CaseInsensitive) == 0)
                text += "<p><b>Result contract:</b> " + api.observation.toHtmlEscaped() + "</p><p>" +
                        api.limits.toHtmlEscaped() + "</p>";
    }
    const QMap<QString, quint64> *registers = nullptr;
    if (evidenceCode && displayedEvidence && i.address == displayedEvidence->ip)
        registers = &displayedEvidence->registers;
    else if (liveCode && debugger.state() == Debugger::State::Paused && i.address == live.ip)
        registers = &live.registers;
    if (registers) {
        auto read = [&](quint64 address, int count) -> QByteArray {
            auto slice = [&](quint64 base, const QByteArray &bytes) -> QByteArray {
                if (address < base || address - base > quint64(bytes.size()) || count < 0 ||
                    quint64(count) > quint64(bytes.size()) - (address - base))
                    return {};
                return bytes.mid(qsizetype(address - base), count);
            };
            if (evidenceCode && displayedEvidence)
                return slice(displayedEvidence->registers.value("rsp"), displayedEvidence->stack);
            return slice(live.memoryAddress, live.memory);
        };
        auto observations = observedOperands(i, *registers, read);
        if (!observations.isEmpty())
            text +=
                "<h4>" +
                QString(evidenceCode ? "Saved operand values" : "Current operand values at the stopped IP") +
                "</h4><p>" + observations.toHtmlEscaped().replace('\n', "<br>") + "</p>";
    }
    text += "<h4>Evidence</h4><p>";
    for (auto at : evidence)
        text += link(at) + " ";
    text += "</p><p><a href='assembly:" + QString::number(i.address, 16) +
            "'>Show assembly</a> · <a href='flow:" + QString::number(i.address, 16) + "'>Show flow</a></p>";
    if (work.comments.contains(i.address))
        text += "<h4>Your comment</h4><p>" + work.comments[i.address].toHtmlEscaped() + "</p>";
    text += "<p><b>Limits:</b> High-level relationships are derived within a bounded basic block; unknown "
            "writes, calls and path joins discard unsupported knowledge. Runtime values apply only to the "
            "labelled stop or saved event.</p>";
    if (technicalExpanded) {
        text += "<hr><h3>Instruction details</h3><p><code>" + i.text.toHtmlEscaped() + "</code><br>" +
                link(i.address) + "<br>" + QString::fromLatin1(i.bytes.toHex(' ')) +
                "</p><h4>Observed facts</h4><p>" + i.fact.toHtmlEscaped() +
                "</p><p>Register reads: " + i.reads.join(", ").toHtmlEscaped() +
                "<br>Register writes: " + i.writes.join(", ").toHtmlEscaped() +
                "</p><h4>Derived relationships</h4><p>" + i.derived.toHtmlEscaped() + "</p><p>" +
                i.unknown.toHtmlEscaped() + "</p>";
        if (i.target)
            text += "<p>Follow operand: " + link(i.target) + "</p>";
        if (captured)
            text += "<h4>Raw captured event</h4><p>" +
                    captured->detail.toHtmlEscaped().replace('\n', "<br>") + "</p>";
        text +=
            "<h4>Window bounds</h4><p>" + blockSummary(code).toHtmlEscaped().replace('\n', "<br>") + "</p>";
    }
    if (decompiled) {
        text += "<h4>Recovered function</h4><p><b>" + decompiled->signature.toHtmlEscaped() +
                "</b></p><p>Ghidra static reconstruction. Parameter and return types are inferred, not "
                "runtime values.</p>";
        for (auto variable : decompiled->data["variables"].toArray()) {
            auto v = variable.toObject();
            if (!v["parameter"].toBool())
                continue;
            text += "<p><code>" + v["type"].toString().toHtmlEscaped() + " " +
                    v["name"].toString().toHtmlEscaped() + "</code> · " +
                    v["storage"].toString().toHtmlEscaped() + "</p>";
        }
        text += "<p>Return type: " + decompiled->data["return_type"].toString().toHtmlEscaped() + "</p>";
    }
    inspector->setHtml(text);
    int oldScroll = readable->verticalScrollBar()->value();
    QString html =
        "<h2>Meaning</h2><p>" + source.toHtmlEscaped() + " · " + QString::number(code.size()) +
        " decoded instructions in this analysis window. Local derivations, not source-code decompilation or "
        "proof of execution.</p>";
    for (int n = 0; n < meaning.units.size(); ++n) {
        const auto &unit = meaning.units[n];
        auto at = meaning.steps[unit.steps.first()].address;
        QString marker = selectedUnit == n ? "Selected · " : "";
        html += "<a name='unit" + QString::number(n) + "'></a><h3>" + marker + QString::number(n + 1) +
                ". <a href='unit:" + QString::number(at, 16) + "'>" + unit.title.toHtmlEscaped() +
                "</a></h3><p>" + unit.summary.toHtmlEscaped() + "</p>";
        if (!unit.arguments.isEmpty())
            html += argumentTable(unit.arguments);
        html += "<p><small>Source instructions: ";
        for (int step : unit.steps)
            html += link(meaning.steps[step].address,
                         "+0x" + QString::number(meaning.steps[step].address - code.first().address, 16)) +
                    " ";
        html += "</small></p>";
    }
    readable->setHtml(html);
    if (selectedUnit >= 0)
        readable->scrollToAnchor("unit" + QString::number(selectedUnit));
    else if (!rebuilt)
        readable->verticalScrollBar()->setValue(oldScroll);
    graph(code);
    updateSessionInfo();
    if (evidenceCode) {
        QString bytes = "Saved instruction bytes (historical; no live memory read)\n";
        for (const auto &in : codeModel->code)
            bytes += hex(in.address) + "  " + QString::fromLatin1(in.bytes.toHex(' ')) + "\n";
        hexView->setPlainText(bytes);
    } else if (image && !liveCode) {
        auto bytes = image->bytesAt(i.address, 512);
        QString h = "Static file bytes · " + hex(i.address) + "\n";
        for (int n = 0; n < bytes.size(); n += 16)
            h += hex(i.address + n) + "  " + QString::fromLatin1(bytes.mid(n, 16).toHex(' ')) + "\n";
        hexView->setPlainText(h);
    }
}

class AddressItem : public QGraphicsRectItem {
    std::function<void()> clicked;

  public:
    AddressItem(QRectF rect, std::function<void()> fn) : QGraphicsRectItem(rect), clicked(std::move(fn)) {
        setCursor(Qt::PointingHandCursor);
    }

  protected:
    void mouseDoubleClickEvent(QGraphicsSceneMouseEvent *event) override {
        event->accept();
        // Navigation may rebuild the scene; do it after this item's event returns.
        auto callback = clicked;
        QTimer::singleShot(0, qApp, [callback] { callback(); });
    }
};
void MainWindow::graph(const QVector<Instruction> &code) {
    flowScene->clear();
    if (code.isEmpty())
        return;
    QSet<quint64> leaders{code.first().address};
    QSet<quint64> addresses;
    for (auto &i : code)
        addresses.insert(i.address);
    QMap<quint64, QVector<quint64>> recoveredSuccessors;
    bool recoveredFlow =
        decompiled && !liveCode && !evidenceCode && code.size() == decompiled->instructions.size();
    if (recoveredFlow) {
        for (auto value : decompiled->data["blocks"].toArray()) {
            auto block = value.toObject();
            auto start = block["start"].toString().mid(2).toULongLong(nullptr, 16);
            if (!addresses.contains(start))
                continue;
            leaders.insert(start);
            auto &successors = recoveredSuccessors[start];
            for (auto target : block["successors"].toArray())
                successors << target.toString().mid(2).toULongLong(nullptr, 16);
        }
    }
    for (int n = 0; n < code.size(); n++) {
        auto &i = code[n];
        if (n && code[n - 1].address + quint64(code[n - 1].size) != i.address)
            leaders.insert(i.address);
        if (i.branch && i.target && addresses.contains(i.target))
            leaders.insert(i.target);
        if ((i.branch || i.terminal) && n + 1 < code.size())
            leaders.insert(code[n + 1].address);
    }
    QVector<QVector<Instruction>> blocks;
    QMap<quint64, QGraphicsRectItem *> items;
    QMap<quint64, quint64> owner;
    for (auto &i : code) {
        if (blocks.isEmpty() || leaders.contains(i.address))
            blocks.push_back({});
        blocks.last() << i;
        owner[i.address] = blocks.last().first().address;
    }
    qreal y = 28;
    if (recoveredFlow) {
        auto *notice = flowScene->addText("Ghidra recovered control flow · static edges within this function "
                                          "view; execution is unobserved");
        notice->setDefaultTextColor(palette().color(QPalette::Text));
        notice->setTextWidth(580);
        y = notice->boundingRect().height() + 40;
    }
    if (decompiled && decompiled->instructions.size() > code.size()) {
        auto *notice =
            flowScene->addText("Large recovered function: this graph displays a bounded instruction window "
                               "around the selection. Full reconstruction is in Decompiled Code.");
        notice->setDefaultTextColor(palette().color(QPalette::Text));
        notice->setTextWidth(580);
        y = notice->boundingRect().height() + 40;
    }
    for (auto &block : blocks) {
        QString text = hex(block.first().address) + "\n";
        auto unit = meaning.unitAt.value(block.first().address, -1);
        if (unit >= 0)
            text += meaning.units[unit].title + "\n";
        for (auto &i : block)
            text += i.text + "\n";
        auto *ti = new QGraphicsSimpleTextItem(text);
        ti->setFont(mono());
        ti->setBrush(palette().color(QPalette::Text));
        auto bounds = ti->boundingRect();
        qreal w = std::max<qreal>(400, bounds.width() + 24), h = bounds.height() + 18;
        quint64 a = block.first().address;
        auto *box = new AddressItem(QRectF(0, 0, w, h), [window = QPointer<MainWindow>(this), a] {
            if (window)
                window->navigate(a);
        });
        bool selected = work.selected >= block.first().address &&
                        work.selected < block.last().address + block.last().size;
        box->setData(0, QVariant::fromValue(a));
        box->setData(1, selected);
        box->setPen(QPen(selected ? palette().color(QPalette::Link) : QColor("#52738e"), selected ? 3 : 1.4));
        box->setBrush(palette().color(QPalette::Base));
        box->setPos(40, y);
        flowScene->addItem(box);
        ti->setParentItem(box);
        ti->setPos(12, 8);
        items[a] = box;
        y += h + 54;
    }
    for (auto &block : blocks) {
        auto &last = block.last();
        auto *from = items[block.first().address];
        QVector<QPair<quint64, QColor>> targets;
        if (recoveredSuccessors.contains(block.first().address)) {
            for (auto destination : recoveredSuccessors[block.first().address]) {
                // Calls are cross-references, not intraprocedural branch edges.
                if (last.call && destination != last.address + quint64(last.size))
                    continue;
                targets << qMakePair(destination, destination == last.address + quint64(last.size)
                                                      ? QColor("#7aa8d3")
                                                      : QColor("#6dba9b"));
            }
        } else {
            if (last.branch && last.target && !last.text.contains('['))
                targets << qMakePair(last.target, QColor("#6dba9b"));
            if (!last.terminal)
                targets << qMakePair(last.address + last.size, QColor("#7aa8d3"));
        }
        for (auto &edge : targets) {
            if (!owner.contains(edge.first))
                continue;
            auto *to = items[owner[edge.first]];
            QPointF start = from->sceneBoundingRect().bottomLeft() + QPointF(30, 0),
                    end = to->sceneBoundingRect().topLeft() + QPointF(30, 0);
            QPainterPath path(start);
            if (end.y() < start.y()) {
                path.lineTo(12, start.y() + 14);
                path.lineTo(12, end.y() - 14);
            } else
                path.lineTo(start.x(), end.y() - 12);
            path.lineTo(end);
            auto *pathItem = flowScene->addPath(path, QPen(edge.second, 2));
            QString edgeLabel = last.conditional
                                    ? (edge.first == last.target ? "Branch taken" : "Fall-through")
                                    : "Control flow";
            pathItem->setToolTip(edgeLabel + " → " + hex(edge.first));
            QPolygonF arrow{end, end + QPointF(-4, -8), end + QPointF(4, -8)};
            flowScene->addPolygon(arrow, QPen(edge.second), QBrush(edge.second));
        }
    }
    flowScene->setSceneRect(flowScene->itemsBoundingRect().adjusted(-20, -20, 20, 20));
    if (owner.contains(work.selected))
        flowView->ensureVisible(items[owner[work.selected]], 16, 16);
}
void MainWindow::goExpression(QString expr) {
    expr = expr.trimmed();
    bool ok;
    quint64 a = expr.toULongLong(&ok, 16);
    if (ok) {
        navigate(a);
        return;
    }
    if (image) {
        if (decompiler)
            for (const auto &function : decompiler->functions())
                if (function.name.compare(expr, Qt::CaseInsensitive) == 0) {
                    navigate(relocateStatic(function.entry));
                    return;
                }
        for (auto rows : {image->functions, image->imports, image->exports})
            for (auto &r : rows)
                if (r.name.compare(expr, Qt::CaseInsensitive) == 0 ||
                    r.name.section('!', 1).compare(expr, Qt::CaseInsensitive) == 0) {
                    navigate(relocateStatic(r.address));
                    return;
                }
        for (auto it = work.renames.begin(); it != work.renames.end(); ++it)
            if (it.value().compare(expr, Qt::CaseInsensitive) == 0) {
                navigate(relocateStatic(it.key()));
                return;
            }
    }
    if (debugger.state() == Debugger::State::Paused) {
        debugger.command("disassemble", expr);
        center->setCurrentIndex(0);
    } else
        error("Address or symbol was not found. Addresses are hexadecimal; runtime expressions require a "
              "paused session.");
}
quint64 MainWindow::relocateStatic(quint64 address) const {
    if (!image || debugger.state() != Debugger::State::Paused || address < image->base ||
        address - image->base >= image->imageSize)
        return address;
    for (const auto &module : live.modules)
        if (QFileInfo(module.name)
                .fileName()
                .compare(QFileInfo(image->path).fileName(), Qt::CaseInsensitive) == 0)
            return module.address + (address - image->base);
    return address;
}
void MainWindow::follow() {
    auto index = codeView->currentIndex();
    if (index.isValid() && index.row() < codeModel->code.size()) {
        auto &i = codeModel->code[index.row()];
        if (i.target) {
            navigate(i.target);
            return;
        }
    }
    statusBar()->showMessage(
        "No statically resolved relative operand. Use Go to Address for a register or memory value.", 6000);
}
void MainWindow::xrefs() {
    navKind->setCurrentIndex(8);
    refreshNavigation();
    exploreDock->show();
    exploreDock->raise();
}
void MainWindow::annotate(QString kind) {
    if (loading)
        return;
    if (!work.selected)
        return;
    auto *map = kind == "Comment" ? &work.comments : kind == "Rename" ? &work.renames : &work.bookmarks;
    bool ok;
    auto text = QInputDialog::getMultiLineText(this, kind,
                                               hex(work.selected) + " — empty text removes the annotation",
                                               map->value(work.selected), &ok);
    if (!ok)
        return;
    if (text.isEmpty())
        map->remove(work.selected);
    else
        (*map)[work.selected] = text;
    changed();
    refreshNavigation();
    codeView->viewport()->update();
    auto index = codeView->currentIndex();
    if (index.isValid())
        explain(codeModel->code[index.row()]);
}
void MainWindow::search() {
    if (!image) {
        error("Open a binary before searching.");
        return;
    }
    QDialog dialog(this);
    dialog.setWindowTitle("Search binary");
    dialog.resize(860, 540);
    auto *l = new QVBoxLayout(&dialog);
    auto *query = new QLineEdit;
    query->setPlaceholderText("Symbol, string or exact hex bytes; select search mode below");
    auto *type = new QComboBox;
    type->addItems({"Symbols / Strings / Annotations", "Hex bytes"});
    auto *model = new RowModel(&dialog);
    auto *results = table(model);
    auto *find = new QPushButton("Search");
    l->addWidget(query);
    l->addWidget(type);
    l->addWidget(find);
    l->addWidget(results);
    auto *hint = new QLabel("Double-click a result to navigate. Results capped at 2,000.");
    l->addWidget(hint);
    auto searchCanceled = std::make_shared<std::atomic_bool>(false);
    auto *searchWatcher = new QFutureWatcher<QVector<Row>>(&dialog);
    connect(&dialog, &QDialog::finished, &dialog, [searchCanceled] { *searchCanceled = true; });
    connect(searchWatcher, &QFutureWatcher<QVector<Row>>::finished, &dialog, [&] {
        model->reset(searchWatcher->result());
        find->setEnabled(true);
        hint->setText(QString::number(model->rows.size()) + " result(s), maximum 2,000");
    });
    connect(find, &QPushButton::clicked, &dialog, [&, this] {
        QString q = query->text().trimmed();
        if (q.isEmpty())
            return;
        bool hexMode = type->currentIndex() == 1;
        QByteArray pattern;
        if (hexMode) {
            QString compact = q;
            compact.remove(QRegularExpression("\\s"));
            if (compact.isEmpty() || compact.size() % 2 ||
                !QRegularExpression("^[0-9a-fA-F]+$").match(compact).hasMatch()) {
                hint->setText("Enter complete hex byte pairs, e.g. 48 89 E5.");
                return;
            }
            pattern = QByteArray::fromHex(compact.toLatin1());
        }
        find->setEnabled(false);
        hint->setText("Searching in background… Close this dialog to cancel.");
        auto imageSnapshot = image;
        auto workSnapshot = work;
        searchWatcher->setFuture(QtConcurrent::run([image = imageSnapshot, work = workSnapshot,
                                                    searchCanceled, q, hexMode, pattern] {
            QVector<Row> rows;
            if (hexMode) {
                auto bytes = pattern;
                qsizetype from = 0;
                while (rows.size() < 2000 && !*searchCanceled) {
                    auto pos = image->data.indexOf(bytes, from);
                    if (pos < 0)
                        break;
                    for (auto &s : image->sections)
                        if (pos >= s.raw && pos - s.raw < s.rawSize)
                            rows << Row{image->base + s.rva + quint64(pos - s.raw), "Hex match",
                                        "File offset " + hex(pos)};
                    from = pos + 1;
                }
            } else {
                for (auto list : {image->functions, image->imports, image->exports, image->strings})
                    for (auto &row : list)
                        if (!*searchCanceled && rows.size() < 2000 &&
                            row.name.contains(q, Qt::CaseInsensitive))
                            rows << row;
                for (auto it = work.comments.begin(); it != work.comments.end() && rows.size() < 2000; ++it)
                    if (it.value().contains(q, Qt::CaseInsensitive))
                        rows << Row{it.key(), it.value(), "Comment"};
                for (auto it = work.renames.begin(); it != work.renames.end() && rows.size() < 2000; ++it)
                    if (it.value().contains(q, Qt::CaseInsensitive))
                        rows << Row{it.key(), it.value(), "Renamed symbol"};
            }
            return rows;
        }));
    });
    connect(query, &QLineEdit::returnPressed, find, &QPushButton::click);
    connect(results, &QTableView::activated, &dialog, [&, this](auto i) {
        auto a = model->rows[i.row()].address;
        dialog.accept();
        navigate(a);
    });
    dialog.exec();
}
void MainWindow::commandPalette() {
    QDialog d(this);
    d.setWindowTitle("Command Palette");
    d.resize(620, 460);
    auto *l = new QVBoxLayout(&d);
    auto *filter = new QLineEdit;
    filter->setPlaceholderText("Type a command…");
    auto *list = new QListWidget;
    l->addWidget(filter);
    l->addWidget(list);
    QVector<QAction *> actions;
    for (auto *a : findChildren<QAction *>())
        if (!a->text().isEmpty() && !a->isSeparator() && a->isEnabled() && !a->menu()) {
            auto *item = new QListWidgetItem(a->text().remove('&') + "    " + a->shortcut().toString(), list);
            item->setData(Qt::UserRole, actions.size());
            actions << a;
        }
    connect(filter, &QLineEdit::textChanged, &d, [list](auto text) {
        for (int n = 0; n < list->count(); n++)
            list->item(n)->setHidden(!list->item(n)->text().contains(text, Qt::CaseInsensitive));
    });
    connect(list, &QListWidget::itemActivated, &d, [&](auto *i) {
        auto *a = actions[i->data(Qt::UserRole).toInt()];
        d.accept();
        QTimer::singleShot(0, a, &QAction::trigger);
    });
    d.exec();
}
void MainWindow::refreshBreakpoints() {
    bpModel->clear();
    bpModel->setHorizontalHeaderLabels({"State", "Expression / API", "Kind", "Condition", "Hits / after",
                                        "Group", "Action", "Bound address / error"});
    for (auto &b : work.breakpoints) {
        QList<QStandardItem *> row;
        for (auto text : QStringList{
                 b.enabled ? b.status : "Disabled", b.expression,
                 b.kind + (b.kind == "Software" ? "" : " (" + QString::number(b.size) + " bytes)"),
                 b.condition, QString::number(b.hits) + " / " + QString::number(b.after), b.group,
                 QString(b.log ? "Log" : "Break") + (b.once ? " · once" : "") +
                     (b.returns ? " · return" : ""),
                 b.error.isEmpty() ? (b.bound ? hex(b.bound) : "Unresolved / next session") : b.error}) {
            auto *i = new QStandardItem(text);
            i->setToolTip(text);
            row << i;
        }
        bpModel->appendRow(row);
    }
    bpView->setColumnWidth(0, 140);
    bpView->setColumnWidth(1, 240);
}
void MainWindow::syncPolicies() {
    debugger.setBreakpoints(work.breakpoints);
    if (debugger.state() == Debugger::State::Running) {
        debugger.pause();
        statusBar()->showMessage("Pausing to apply breakpoint changes.", 5000);
    }
}
void MainWindow::editBreakpoint(int index) {
    if (loading) {
        statusBar()->showMessage("Wait for analysis or cancel it before changing breakpoints.", 4000);
        return;
    }
    QDialog d(this);
    d.setWindowTitle(index < 0 ? "New breakpoint" : "Edit breakpoint");
    d.resize(620, 460);
    auto *l = new QFormLayout(&d);
    Breakpoint b;
    if (index >= 0 && index < work.breakpoints.size())
        b = work.breakpoints[index];
    auto *expression = new QLineEdit(b.expression);
    expression->setPlaceholderText("module!export, module+0xRVA, or absolute runtime address");
    auto *condition = new QLineEdit(b.condition);
    condition->setPlaceholderText("e.g. @rcx == 0n2 (MASM; default numbers are hex)");
    auto *group = new QLineEdit(b.group);
    auto *kind = new QComboBox;
    kind->addItems({"Software", "Execute", "Write", "Read/write"});
    kind->setCurrentText(b.kind);
    auto *size = new QComboBox;
    size->addItems({"1", "2", "4", "8"});
    size->setCurrentText(QString::number(b.size));
    auto *after = new QSpinBox;
    after->setRange(1, 1000000000);
    after->setValue(int(std::min<quint64>(b.after, 1000000000)));
    auto *enabled = new QCheckBox("Enabled");
    enabled->setChecked(b.enabled);
    auto *once = new QCheckBox("Disable after first qualifying hit");
    once->setChecked(b.once);
    auto *log = new QCheckBox("Log evidence and continue");
    log->setChecked(b.log);
    auto *ret = new QCheckBox("Observe API return (entry breakpoint only)");
    ret->setChecked(b.returns);
    l->addRow("Address / symbol", expression);
    l->addRow("Condition", condition);
    l->addRow("Kind", kind);
    l->addRow("Watch size", size);
    l->addRow("Break on / after hit", after);
    l->addRow("Group", group);
    l->addRow(enabled);
    l->addRow(once);
    l->addRow(log);
    l->addRow(ret);
    auto *limits =
        new QLabel("Hardware: four x64 slots; data watchpoints require natural alignment. Read/write watches "
                   "both accesses. Symbol breakpoints remain pending until their module loads. Static F9 "
                   "uses module+RVA to handle ASLR. Return observations pair thread and stack; tail calls, "
                   "exceptions and stack changes may prevent pairing.");
    limits->setWordWrap(true);
    l->addRow(limits);
    auto *validation = new QLabel;
    validation->setWordWrap(true);
    l->addRow(validation);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    l->addRow(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &d, [&] {
        QString expr = expression->text().trimmed();
        if (expr.isEmpty() || !QRegularExpression("^[a-zA-Z0-9_!+?.`:$@-]+$").match(expr).hasMatch()) {
            validation->setText(
                "Use a single symbol or address expression; spaces/commands are not supported.");
            return;
        }
        if (!conditionSyntax(condition->text())) {
            validation->setText("Use an expression only; assignments and debugger commands are rejected.");
            return;
        }
        d.accept();
    });
    if (d.exec() != QDialog::Accepted)
        return;
    b.expression = expression->text().trimmed();
    b.condition = condition->text().trimmed();
    b.kind = kind->currentText();
    b.size = size->currentText().toInt();
    b.after = after->value();
    b.enabled = enabled->isChecked();
    b.once = once->isChecked();
    b.log = log->isChecked();
    b.returns = ret->isChecked();
    b.group = group->text().isEmpty() ? "Custom" : group->text();
    b.status = "Pending";
    b.error.clear();
    if (index < 0)
        work.breakpoints << b;
    else
        work.breakpoints[index] = b;
    changed();
    refreshBreakpoints();
    syncPolicies();
}
void MainWindow::presets() {
    if (loading) {
        statusBar()->showMessage("Wait for analysis or cancel it before installing presets.", 4000);
        return;
    }
    QDialog d(this);
    d.setObjectName("presetBrowser");
    d.setWindowTitle("Breakpoint Preset Library");
    d.resize(1000, 610);
    auto *l = new QVBoxLayout(&d);
    auto *filter = new QLineEdit;
    filter->setPlaceholderText("Search intent, API, category or observation…");
    auto *category = new QComboBox;
    category->addItems(
        {"All categories", "Process", "Memory", "File", "Registry", "Network", "Module", "Exception"});
    auto *top = new QHBoxLayout;
    top->addWidget(filter, 1);
    top->addWidget(category);
    l->addLayout(top);
    auto *split = new QSplitter;
    auto *list = new QListWidget;
    auto *preview = new QTextBrowser;
    split->addWidget(list);
    split->addWidget(preview);
    split->setStretchFactor(1, 2);
    l->addWidget(split);
    auto *returnOption = new QCheckBox("Capture return value where a normal return occurs");
    returnOption->setChecked(true);
    l->addWidget(returnOption);
    auto *install = new QPushButton("Install Selected Preset");
    install->setEnabled(false);
    l->addWidget(install);
    auto catalog = apiCatalog();
    auto refresh = [&] {
        list->clear();
        for (int n = 0; n < catalog.size(); n++) {
            auto &a = catalog[n];
            if (category->currentIndex() > 0 && category->currentText() != a.category)
                continue;
            if (!(a.category + a.symbol + a.purpose + a.observation)
                     .contains(filter->text(), Qt::CaseInsensitive))
                continue;
            auto *i = new QListWidgetItem(a.purpose + "\n" + a.symbol, list);
            i->setData(Qt::UserRole, n);
            i->setToolTip(a.purpose);
        }
        if (list->count())
            list->setCurrentRow(0);
    };
    connect(list, &QListWidget::currentItemChanged, &d, [&](auto *i, auto *) {
        install->setEnabled(i);
        if (!i) {
            preview->clear();
            return;
        }
        auto &a = catalog[i->data(Qt::UserRole).toInt()];
        QStringList argumentLabels;
        const QMap<QString, QString> typeNames{{"wstr", "UTF-16 string address"},
                                               {"astr", "ANSI string address or ordinal"},
                                               {"ptr", "address"},
                                               {"uint", "unsigned integer"},
                                               {"size", "64-bit byte count (SIZE_T)"},
                                               {"bool", "BOOL"},
                                               {"handle", "handle"},
                                               {"flags", "flags"}};
        for (const auto &argument : a.args) {
            auto parts = argument.split(':');
            argumentLabels << parts[0].toHtmlEscaped() + " — " +
                                  typeNames.value(parts.value(1), parts.value(1)).toHtmlEscaped();
        }
        preview->setHtml(
            "<h2>" + a.purpose.toHtmlEscaped() + "</h2><h3>Exact breakpoint</h3><p><code>" +
            a.symbol.toHtmlEscaped() + "</code></p><h3>What a hit means</h3><p>" +
            a.observation.toHtmlEscaped() + "</p><h3>Arguments at entry</h3><p>" +
            argumentLabels.join("<br>") + "</p><h3>Limits / false positives</h3><p>" +
            a.limits.toHtmlEscaped() +
            "</p><p>Entry captures the request. Optional return capture records RAX at a thread/stack "
            "matched return site. Unresolved exports remain visibly pending; no API call is simulated.</p>");
    });
    connect(filter, &QLineEdit::textChanged, &d, [&] { refresh(); });
    connect(category, &QComboBox::currentIndexChanged, &d, [&] { refresh(); });
    connect(install, &QPushButton::clicked, &d, [&] {
        if (!list->currentItem())
            return;
        auto &api = catalog[list->currentItem()->data(Qt::UserRole).toInt()];
        Breakpoint b;
        b.expression = api.symbol;
        b.group = api.category;
        b.returns = returnOption->isChecked();
        work.breakpoints << b;
        changed();
        refreshBreakpoints();
        syncPolicies();
        d.accept();
        breakpointsDock->show();
        breakpointsDock->raise();
    });
    refresh();
    d.exec();
}
void MainWindow::launch() {
    if (loading)
        return;
    if (!image) {
        chooseBinary();
        return;
    }
    if (image->dll) {
        error("DLLs can be inspected statically. Launch an x64 host executable or attach to an eligible host "
              "process.");
        return;
    }
    QDialog d(this);
    d.setWindowTitle("Start target on this machine");
    auto *l = new QFormLayout(&d);
    auto *warning = new QLabel("This executes the binary on this Windows machine. Only run files you trust "
                               "here. For unknown binaries, use this workstation inside an explicitly chosen "
                               "isolated VM. Opening a PE never executes it.");
    warning->setWordWrap(true);
    l->addRow(warning);
    l->addRow("Target", new QLabel(image->path));
    auto *args = new QLineEdit;
    l->addRow("Arguments", args);
    auto *consent = new QCheckBox("I choose this machine for executing this target");
    l->addRow(consent);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText("Start Debugging");
    buttons->button(QDialogButtonBox::Ok)->setEnabled(false);
    l->addRow(buttons);
    connect(consent, &QCheckBox::toggled, buttons->button(QDialogButtonBox::Ok), &QPushButton::setEnabled);
    connect(buttons, &QDialogButtonBox::accepted, &d, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    d.resize(620, 280);
    if (d.exec() == QDialog::Accepted) {
        syncPolicies();
        debugger.launch(image->path, args->text());
    }
}
void MainWindow::attach() {
    if (loading)
        return;
    QDialog d(this);
    d.setWindowTitle("Attach to an x64 user-mode process on this machine");
    d.resize(720, 500);
    auto *l = new QVBoxLayout(&d);
    auto *warning = new QLabel("Attaching pauses a real process. Protected processes may deny access. "
                               "Detaching leaves the process running. No privilege escalation is attempted.");
    warning->setWordWrap(true);
    l->addWidget(warning);
    auto *filter = new QLineEdit;
    filter->setPlaceholderText("Filter processes…");
    l->addWidget(filter);
    auto *list = new QListWidget;
    l->addWidget(list);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof entry;
        if (Process32FirstW(snap, &entry))
            do {
                if (entry.th32ProcessID == GetCurrentProcessId() || !entry.th32ProcessID)
                    continue;
                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                BOOL wow = FALSE;
                bool eligible = process && IsWow64Process(process, &wow) && !wow;
                if (process)
                    CloseHandle(process);
                if (!eligible)
                    continue;
                auto *i = new QListWidgetItem(QString::number(entry.th32ProcessID) + "   " +
                                                  QString::fromWCharArray(entry.szExeFile),
                                              list);
                i->setData(Qt::UserRole, quint32(entry.th32ProcessID));
            } while (Process32NextW(snap, &entry));
        CloseHandle(snap);
    }
    connect(filter, &QLineEdit::textChanged, &d, [list](auto q) {
        for (int n = 0; n < list->count(); n++)
            list->item(n)->setHidden(!list->item(n)->text().contains(q, Qt::CaseInsensitive));
    });
    auto *b = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    b->button(QDialogButtonBox::Ok)->setText("Attach Selected Process");
    l->addWidget(b);
    connect(b, &QDialogButtonBox::accepted, &d, [&] {
        if (list->currentItem())
            d.accept();
    });
    connect(b, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    if (d.exec() == QDialog::Accepted) {
        syncPolicies();
        debugger.attach(list->currentItem()->data(Qt::UserRole).toUInt());
    }
}
void MainWindow::debuggerState(Debugger::State state, QString detail) {
    if (compactDecompilerLayout && state == Debugger::State::Starting)
        setDebuggerPanesVisible(true);
    if (compactDecompilerLayout &&
        (state == Debugger::State::Disconnected || state == Debugger::State::Exited))
        setDebuggerPanesVisible(false);
    stateLabel->setToolTip(detail);
    bool paused = state == Debugger::State::Paused, running = state == Debugger::State::Running,
         connected = paused || running || state == Debugger::State::Starting;
    launchAction->setEnabled(!connected);
    attachAction->setEnabled(!connected);
    runAction->setEnabled(paused);
    intoAction->setEnabled(paused);
    overAction->setEnabled(paused);
    outAction->setEnabled(paused);
    pauseAction->setEnabled(running);
    detachAction->setEnabled(connected);
    if (!connected) {
        live = Snapshot{};
        codeModel->ip = 0;
        regModel->reset({});
        stackModel->reset({});
        frameModel->reset({});
        threadModel->reset({});
        moduleModel->reset({});
        if (image) {
            liveCode = false;
            evidenceCode = false;
            codeModel->reset(image->code);
            navigate(image->entry);
        } else {
            liveCode = evidenceCode = false;
            displayedEvidence.reset();
            meaningKey.clear();
            codeModel->reset({});
            readable->setHtml("<h2>No live process</h2><p>Open a binary or select a saved Timeline event to "
                              "inspect its captured bytes.</p>");
            flowScene->clear();
            inspector->setHtml(
                "<h3>No live process</h3><p>Recorded evidence remains available in Timeline.</p>");
        }
        hexView->clear();
    } else if (running) {
        liveCode = false;
        evidenceCode = false;
        displayedEvidence.reset();
        codeModel->ip = 0;
        codeModel->reset({});
        flowScene->clear();
        regModel->reset({});
        stackModel->reset({});
        frameModel->reset({});
        threadModel->reset({});
        inspector->setHtml("<h3>Target running</h3><p>Current register and memory values are unavailable "
                           "until the next stop. Historical evidence remains in Timeline.</p>");
        hexView->clear();
        readable->setHtml("<h2>Target running</h2><p>Pause to inspect code and current values. Recorded "
                          "events remain in Timeline.</p>");
        meaningKey.clear();
    }
    updateSessionInfo();
}
void MainWindow::snapshot(Snapshot s) {
    live = s;
    displayedEvidence.reset();
    liveCode = true;
    evidenceCode = false;
    codeModel->ip = s.ip;
    codeModel->reset(s.code);
    pages->setCurrentIndex(1);
    QVector<Row> regs;
    for (auto it = s.registers.begin(); it != s.registers.end(); ++it) {
        QString detail = "Observed while paused";
        if (it.key() == "efl") {
            QStringList flags;
            for (auto bit : QList<QPair<int, QString>>{{0, "CF"},
                                                       {2, "PF"},
                                                       {4, "AF"},
                                                       {6, "ZF"},
                                                       {7, "SF"},
                                                       {8, "TF"},
                                                       {9, "IF"},
                                                       {10, "DF"},
                                                       {11, "OF"}})
                if (it.value() & (quint64(1) << bit.first))
                    flags << bit.second;
            detail = flags.join(" | ");
        }
        regs << Row{it.value(), it.key(), detail};
    }
    regModel->reset(regs);
    stackModel->reset(s.stack);
    frameModel->reset(s.frames);
    threadModel->reset(s.threads);
    moduleModel->reset(s.modules);
    if (!s.code.isEmpty())
        navigate(s.viewAddress ? s.viewAddress : s.ip);
    else {
        work.selected = s.viewAddress ? s.viewAddress : s.ip;
        location->setText(hex(work.selected));
        inspector->setHtml("<h3>Paused — instruction bytes unavailable</h3><p>" + s.reason.toHtmlEscaped() +
                           "</p><p>The target's instruction bytes at " + hex(work.selected) +
                           " could not be read. Registers and captured evidence remain inspectable; no "
                           "instruction semantics are asserted.</p>");
    }
    QString text = "Observed process memory at " + hex(s.memoryAddress) + " · Windows thread " +
                   QString::number(s.thread) + "\n";
    if (s.memory.isEmpty())
        text += "No readable bytes returned. The address may be unmapped or inaccessible.\n";
    for (int n = 0; n < s.memory.size(); n += 16) {
        auto chunk = s.memory.mid(n, 16);
        QString ascii;
        for (auto c : chunk)
            ascii += uchar(c) >= 32 && uchar(c) < 127 ? QChar(uchar(c)) : QChar('.');
        text += hex(s.memoryAddress + n) + "  " +
                QString::fromLatin1(chunk.toHex(' ')).leftJustified(48, ' ') + "  " + ascii + "\n";
    }
    hexView->setPlainText(text);
    fileLabel->setText("Live x64 · thread " + QString::number(s.thread) + " · " + s.reason);
    updateSessionInfo();
}
void MainWindow::refreshTimeline() {
    if (timelineModel->rowCount() > work.events.size() ||
        (timelineModel->rowCount() && !work.events.isEmpty() &&
         timelineModel->item(0, 0)->text() != work.events.first().time))
        timelineModel->removeRows(0, timelineModel->rowCount());
    timelineModel->setHorizontalHeaderLabels(
        {"UTC capture time", "Event", "Thread", "Address", "Observed details"});
    for (int n = timelineModel->rowCount(); n < work.events.size(); n++) {
        auto &e = work.events[n];
        QList<QStandardItem *> row;
        for (auto s : QStringList{e.time, e.type, QString::number(e.thread), hex(e.address),
                                  e.detail.section('\n', 0, 0)}) {
            auto *i = new QStandardItem(s);
            i->setToolTip(e.detail);
            row << i;
        }
        timelineModel->appendRow(row);
    }
    timelineView->setColumnWidth(0, 205);
    timelineView->setColumnWidth(1, 150);
    timelineView->setColumnWidth(2, 65);
    timelineView->setColumnWidth(3, 165);
    eventScene->clear();
    QMap<quint32, QPointF> previous;
    QMap<quint32, int> lanes;
    int begin = std::max(0, int(work.events.size()) - 100);
    qreal y = 10;
    for (int n = begin; n < work.events.size(); n++) {
        auto &e = work.events[n];
        if (!lanes.contains(e.thread))
            lanes[e.thread] = lanes.size();
        qreal x = lanes[e.thread] * 280;
        auto *text = eventScene->addText(
            QString("T%1 · #%2\n%3\n%4").arg(e.thread).arg(n + 1).arg(e.type, hex(e.address)));
        text->setDefaultTextColor(palette().color(QPalette::Text));
        text->setPos(x + 8, y + 6);
        text->setTextWidth(250);
        auto *box = eventScene->addRect(x, y, 270, 88, QPen(QColor("#52738e")));
        box->setZValue(-1);
        if (previous.contains(e.thread))
            eventScene->addLine(QLineF(previous[e.thread], QPointF(x + 130, y)), QPen(QColor("#7aa8d3")));
        previous[e.thread] = QPointF(x + 130, y + 88);
        y += 104;
    }
    auto *hint = eventScene->addText(
        "Links indicate observed event order on the same thread only; not causality. Last 100 events.");
    hint->setDefaultTextColor(palette().color(QPalette::Text));
    hint->setPos(0, y + 10);
}
void MainWindow::eventSelection(const QModelIndex &i) {
    if (!i.isValid() || i.row() >= work.events.size())
        return;
    auto &e = work.events[i.row()];
    QString text = "<h3>Captured evidence · " + e.type.toHtmlEscaped() + "</h3><p>" + e.time +
                   " UTC · thread " + QString::number(e.thread) + " · " + link(e.address) + "</p><pre>" +
                   e.detail.toHtmlEscaped() +
                   "</pre><p>Historical snapshot. These are saved values, not current process state.</p>";
    if (!e.code.isEmpty())
        text += "<p><a href='evidence:code'>Open captured instruction bytes at " + hex(e.ip) + "</a> (" +
                QString::number(e.code.size()) + " bytes preserved at this event)</p>";
    for (auto it = e.registers.begin(); it != e.registers.end(); ++it)
        text += "<span>" + it.key() + " = " + link(it.value()) + " &nbsp; </span>";
    text += "<h4>Captured call stack</h4>";
    for (auto &f : e.frames)
        text += "<p>" + link(f.address, f.name) + " · " + f.detail.toHtmlEscaped() + "</p>";
    text += "<h4>Captured stack bytes</h4><pre>";
    for (int n = 0; n < e.stack.size(); n += 16)
        text += hex(e.registers.value("rsp") + n) + "  " +
                QString::fromLatin1(e.stack.mid(n, 16).toHex(' ')) + "\n";
    eventDetail->setHtml(text + "</pre>");
}
void MainWindow::presetLayout(QString name) {
    if (!baselineLayout.isEmpty())
        restoreState(baselineLayout);
    for (auto *d : docks) {
        d->setFloating(false);
    }
    addDockWidget(Qt::LeftDockWidgetArea, exploreDock);
    addDockWidget(Qt::RightDockWidgetArea, contextDock);
    if (aiDock) {
        addDockWidget(Qt::RightDockWidgetArea, aiDock);
        tabifyDockWidget(contextDock, aiDock);
    }
    for (auto *d : {registerDock, stackDock, framesDock, breakpointsDock, threadsDock, timelineDock,
                    modulesDock, outputDock})
        removeDockWidget(d);
    addDockWidget(Qt::BottomDockWidgetArea, registerDock);
    if (name == "Expert") {
        addDockWidget(Qt::BottomDockWidgetArea, breakpointsDock);
        splitDockWidget(registerDock, breakpointsDock, Qt::Horizontal);
    }
    for (auto *d :
         {stackDock, framesDock, breakpointsDock, threadsDock, timelineDock, modulesDock, outputDock}) {
        if (name == "Expert" && d == breakpointsDock)
            continue;
        addDockWidget(Qt::BottomDockWidgetArea, d);
        tabifyDockWidget(registerDock, d);
    }
    for (auto *d : docks)
        d->show();
    if (aiDock)
        aiDock->hide();
    registerDock->raise();
    resizeDocks({exploreDock, contextDock}, {name == "Beginner" ? 260 : 300, name == "Beginner" ? 400 : 360},
                Qt::Horizontal);
    resizeDocks({registerDock}, {std::clamp(height() / 5, 125, name == "Expert" ? 280 : 220)}, Qt::Vertical);
    if (name == "Beginner") {
        threadsDock->hide();
        modulesDock->hide();
        outputDock->hide();
    }
    if (image)
        changed();
}
void MainWindow::theme(bool light) {
    qApp->setStyle("Fusion");
    QPalette p;
    if (light) {
        p.setColor(QPalette::Window, QColor("#f0f2f5"));
        p.setColor(QPalette::WindowText, QColor("#202730"));
        p.setColor(QPalette::Base, Qt::white);
        p.setColor(QPalette::AlternateBase, QColor("#f5f7fa"));
        p.setColor(QPalette::Text, QColor("#202730"));
        p.setColor(QPalette::Button, QColor("#e4e8ed"));
        p.setColor(QPalette::ButtonText, QColor("#202730"));
        p.setColor(QPalette::Highlight, QColor("#2c6da4"));
        p.setColor(QPalette::HighlightedText, Qt::white);
        p.setColor(QPalette::Light, Qt::white);
        p.setColor(QPalette::Midlight, QColor("#d9dfe6"));
        p.setColor(QPalette::Mid, QColor("#bbc4ce"));
        p.setColor(QPalette::Dark, QColor("#9ba6b3"));
        p.setColor(QPalette::Shadow, QColor("#6b7582"));
        p.setColor(QPalette::Link, QColor("#1c5d91"));
        p.setColor(QPalette::ToolTipBase, QColor("#fffce6"));
        p.setColor(QPalette::ToolTipText, QColor("#202730"));
        p.setColor(QPalette::Disabled, QPalette::Text, QColor("#75808b"));
        p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor("#75808b"));
    } else {
        p.setColor(QPalette::Window, QColor("#25292f"));
        p.setColor(QPalette::WindowText, QColor("#e3e8ee"));
        p.setColor(QPalette::Base, QColor("#191d23"));
        p.setColor(QPalette::AlternateBase, QColor("#20252c"));
        p.setColor(QPalette::Text, QColor("#e3e8ee"));
        p.setColor(QPalette::Button, QColor("#303740"));
        p.setColor(QPalette::ButtonText, QColor("#e3e8ee"));
        p.setColor(QPalette::Highlight, QColor("#315c86"));
        p.setColor(QPalette::HighlightedText, Qt::white);
        p.setColor(QPalette::ToolTipBase, QColor("#303740"));
        p.setColor(QPalette::ToolTipText, Qt::white);
        p.setColor(QPalette::Link, QColor("#7cbbf3"));
        p.setColor(QPalette::Disabled, QPalette::Text, QColor("#8c96a3"));
        p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor("#8c96a3"));
    }
    qApp->setPalette(p);
    qApp->setStyleSheet("QToolBar { spacing: 5px; padding: 4px; } QDockWidget::title { padding: 6px; "
                        "font-weight: 600; } QLineEdit, QComboBox { padding: 5px; } QPushButton { padding: "
                        "6px 12px; } QTableView { gridline-color: " +
                        QString(light ? "#d8dce1" : "#303741") +
                        "; } QTabBar::tab { padding: 7px 12px; } QToolButton:focus, QPushButton:focus, "
                        "QLineEdit:focus { border: 1px solid #6fafe4; }");
    if (flowScene)
        flowScene->setBackgroundBrush(p.color(QPalette::Window));
    if (eventScene)
        eventScene->setBackgroundBrush(p.color(QPalette::Window));
    if (image) {
        graph(selectedFunction());
        refreshTimeline();
    }
}
} // namespace vnr
