#include "mainwindow.h"
#include <algorithm>

namespace vnr {
namespace {
quint64 va(const QJsonValue &v) {
    return v.toString().mid(2).toULongLong(nullptr, 16);
}
} // namespace
void MainWindow::setupDecompiler(QMenu *investigate, QMenu *settings) {
    decompiler = new DecompilerService(this);
    auto *page = new QWidget;
    page->setObjectName("decompiledPage");
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(6, 6, 6, 6);
    auto *bar = new QHBoxLayout;
    functionPicker = new QComboBox;
    functionPicker->setObjectName("recoveredFunctions");
    functionPicker->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    functionPicker->setMinimumContentsLength(14);
    functionPicker->setToolTip(
        "Functions recovered by Ghidra; type to search by name. Addresses use the preferred image base.");
    functionPicker->setEditable(true);
    functionPicker->setInsertPolicy(QComboBox::NoInsert);
    functionPicker->completer()->setFilterMode(Qt::MatchContains);
    auto *decompile = new QPushButton("Decompile");
    decompile->setObjectName("decompileButton");
    auto *cancel = new QPushButton("Cancel");
    cancel->setObjectName("cancelDecompilation");
    cancel->setEnabled(false);
    auto *configure = new QPushButton("Configure…");
    configure->setObjectName("configureGhidra");
    bar->addWidget(functionPicker, 1);
    bar->addWidget(decompile);
    bar->addWidget(cancel);
    bar->addWidget(configure);
    layout->addLayout(bar);
    auto *tools = new QHBoxLayout;
    auto *edits = new QToolButton;
    edits->setText("Names & types");
    edits->setPopupMode(QToolButton::InstantPopup);
    auto *editMenu = new QMenu(edits);
    edits->setMenu(editMenu);
    for (const auto &pair : {qMakePair(QString("Rename function…"), QString("function_name")),
                             qMakePair(QString("Edit C signature…"), QString("signature")),
                             qMakePair(QString("Rename variable…"), QString("variable_name")),
                             qMakePair(QString("Edit variable type…"), QString("variable_type"))})
        connect(editMenu->addAction(pair.first), &QAction::triggered, this,
                [this, pair] { editDecompiled(pair.second); });
    auto *refs = new QPushButton("Cross-references");
    refs->setObjectName("decompilerXrefs");
    auto *split = new QCheckBox("Assembly alongside");
    auto *debugPanes = new QPushButton("Debugger panes");
    debugPanes->setObjectName("toggleDebuggerPanes");
    debugPanes->setToolTip("Show or collapse registers, stack, breakpoints and other debugger panes. They "
                           "open automatically when debugging starts.");
    connect(debugPanes, &QPushButton::clicked, this, [this] {
        bool show = registerDock->isHidden();
        compactDecompilerLayout = !show;
        setDebuggerPanesVisible(show);
    });
    split->setObjectName("splitPseudocode");
    split->setChecked(QSettings().value("decompiler/split", false).toBool());
    tools->addWidget(edits);
    tools->addWidget(refs);
    tools->addWidget(debugPanes);
    tools->addStretch();
    tools->addWidget(split);
    layout->addLayout(tools);
    functionSummary = new QLabel("Real reconstructed C-like code · Ghidra backend · independent of AI");
    functionSummary->setObjectName("decompiledSummary");
    functionSummary->setWordWrap(true);
    functionSummary->setTextFormat(Qt::PlainText);
    layout->addWidget(functionSummary);
    auto *panes = new QSplitter(Qt::Horizontal);
    panes->setObjectName("decompilerSplitter");
    pseudocode = new PseudocodeEditor;
    splitAssembly = table(codeModel);
    splitAssembly->setObjectName("pseudocodeAssembly");
    splitAssembly->setSelectionModel(codeView->selectionModel());
    splitAssembly->setColumnHidden(0, true);
    splitAssembly->setColumnHidden(2, true);
    splitAssembly->setColumnHidden(4, true);
    splitAssembly->setColumnWidth(1, 160);
    splitAssembly->setColumnWidth(3, 270);
    panes->addWidget(pseudocode);
    panes->addWidget(splitAssembly);
    splitAssembly->setVisible(split->isChecked());
    layout->addWidget(panes, 1);
    decompilerStatus =
        new QLabel("Configure a local Ghidra installation and JDK to enable real decompilation.");
    decompilerStatus->setTextFormat(Qt::PlainText);
    decompilerStatus->setObjectName("decompilerStatus");
    decompilerStatus->setWordWrap(true);
    layout->addWidget(decompilerStatus);
    center->addTab(page, "Decompiled Code");
    center->setTabToolTip(
        center->indexOf(page),
        "Ghidra reconstructed C-like pseudocode; source mappings, names, types and cross-references");
    decompilerNavigation.setSingleShot(true);
    decompilerNavigation.setInterval(140);
    connect(&decompilerNavigation, &QTimer::timeout, this, [this] { requestDecompilation(); });
    connect(split, &QCheckBox::toggled, this, [this](bool on) {
        splitAssembly->setVisible(on);
        QSettings().setValue("decompiler/split", on);
        if (on && codeView->currentIndex().isValid())
            splitAssembly->scrollTo(codeView->currentIndex().siblingAtColumn(1),
                                    QAbstractItemView::PositionAtCenter);
    });
    connect(splitAssembly->selectionModel(), &QItemSelectionModel::currentRowChanged, this, [this](auto i) {
        if (i.isValid() && i.row() < codeModel->code.size() &&
            work.selected != codeModel->code[i.row()].address)
            navigate(codeModel->code[i.row()].address);
    });
    connect(functionPicker, &QComboBox::activated, this, [this](int index) {
        auto a = functionPicker->itemData(index).toULongLong();
        if (a)
            navigate(relocateStatic(a));
        requestDecompilation(true);
    });
    connect(decompile, &QPushButton::clicked, this, [this] { requestDecompilation(true); });
    connect(configure, &QPushButton::clicked, this, &MainWindow::configureDecompiler);
    connect(cancel, &QPushButton::clicked, decompiler, &DecompilerService::cancel);
    connect(refs, &QPushButton::clicked, this, &MainWindow::decompilerReferences);
    connect(pseudocode, &PseudocodeEditor::editRequested, this, &MainWindow::editDecompiled);
    auto *renameShortcut = new QAction(pseudocode);
    renameShortcut->setShortcut(QKeySequence("Ctrl+Shift+N"));
    renameShortcut->setShortcutContext(Qt::WidgetShortcut);
    pseudocode->addAction(renameShortcut);
    connect(renameShortcut, &QAction::triggered, this, [this] { editDecompiled("function_name"); });
    connect(pseudocode, &PseudocodeEditor::referencesRequested, this, &MainWindow::decompilerReferences);
    connect(pseudocode, &PseudocodeEditor::sourceRequested, this, [this](quint64 a, bool assembly) {
        navigate(relocateStatic(a));
        if (assembly)
            center->setCurrentIndex(0);
        else
            requestDecompilation();
    });
    auto *configureAction = settings->addAction("Decompiler / Ghidra…");
    configureAction->setObjectName("ghidraSettingsAction");
    connect(configureAction, &QAction::triggered, this, &MainWindow::configureDecompiler);
    auto *show = investigate->addAction("Decompile Current Function");
    show->setShortcut(QKeySequence("Ctrl+Shift+D"));
    show->setObjectName("decompileFunctionAction");
    connect(show, &QAction::triggered, this, [this, page] {
        center->setCurrentWidget(page);
        requestDecompilation(true);
    });
    connect(decompiler, &DecompilerService::status, this, [this](QString message) {
        decompilerStatus->setText(message);
        decompilerStatus->setToolTip(message);
    });
    connect(decompiler, &DecompilerService::busyChanged, cancel, &QPushButton::setEnabled);
    connect(decompiler, &DecompilerService::requestCancelled, this, [this] {
        pendingDecompilerEdit.reset();
        requestedDecompilation.clear();
    });
    connect(decompiler, &DecompilerService::analysisReady, this, [this] {
        functionPicker->clear();
        for (const auto &f : decompiler->functions())
            functionPicker->addItem(work.renames.value(f.entry, f.name) + "  ·  " + hex(f.entry),
                                    QVariant::fromValue(f.entry));
        refreshNavigation();
        requestedDecompilation.clear();
        requestDecompilation();
    });
    connect(decompiler, &DecompilerService::failed, this, [this](QString message) {
        requestedDecompilation.clear();
        pendingDecompilerEdit.reset();
        decompilerStatus->setText(message.section('\n', 0, 0).left(400));
        decompilerStatus->setToolTip(message);
        output->appendPlainText("DECOMPILER: " + message);
    });
    connect(decompiler, &DecompilerService::completed, this, [this](DecompiledFunction result) {
        if (pendingDecompilerEdit) {
            auto edit = *pendingDecompilerEdit;
            pendingDecompilerEdit.reset();
            work.decompilerEdits.append(edit);
            if (edit["kind"].toString() == "function_name" || edit["kind"].toString() == "signature")
                work.renames[result.entry] = result.name;
            changed();
            refreshNavigation();
            result.edits = analysisEdits();
        }
        auto selection = staticSelection();
        auto *f = selection ? decompiler->containing(*selection) : nullptr;
        if (!f || f->entry != result.entry)
            return;
        decompiled = result;
        requestedDecompilation.clear();
        pseudocode->setFunction(result);
        pseudocode->selectAddress(*selection);
        functionSummary->setText(
            result.signature +
            "\nGhidra static reconstruction · inferred types may be wrong · not original source");
        QString status =
            result.cached ? "Cached Ghidra result" : "Reconstructed by the native Ghidra decompiler";
        if (liveCode)
            status += " · captured live bytes match; unobserved function bytes are static assumptions";
        else if (evidenceCode)
            status += " · static file result; historical evidence has no verified module mapping";
        if (!result.data["warning"].toString().isEmpty())
            status += " · " + result.data["warning"].toString();
        if (!result.data["analysis_warning"].toString().isEmpty())
            status += " · " + result.data["analysis_warning"].toString();
        decompilerStatus->setText(status);
        decompilerStatus->setToolTip(status);
        if (codeView->currentIndex().isValid())
            splitAssembly->scrollTo(codeView->currentIndex().siblingAtColumn(1),
                                    QAbstractItemView::PositionAtCenter);
        auto index = functionPicker->findData(QVariant::fromValue(result.entry));
        if (index >= 0) {
            QSignalBlocker block(functionPicker);
            functionPicker->setItemText(index, result.name + "  ·  " + hex(result.entry));
            functionPicker->setCurrentIndex(index);
        }
        if (!liveCode && !evidenceCode) {
            meaningKey.clear();
            auto i = image->instructionIndex(work.selected);
            if (i >= 0)
                explain(image->code[i]);
        }
        if (aiPanel)
            aiPanel->sourceChanged(aiSourceIdentity());
    });
}
void MainWindow::configureDecompiler() {
    auto config = GhidraConfig::load();
    QDialog dialog(this);
    dialog.setWindowTitle("Local decompiler settings");
    dialog.setObjectName("ghidraSettings");
    auto *layout = new QVBoxLayout(&dialog);
    auto *intro =
        new QLabel("Choose an extracted Ghidra installation and a compatible 64-bit JDK.\nTested: Ghidra "
                   "12.1.4 with JDK 21. No binary execution or AI is used for decompilation.");
    intro->setWordWrap(true);
    layout->addWidget(intro);
    auto *form = new QFormLayout;
    auto entry = [&](QString title, QString value, QString name) {
        auto *row = new QWidget;
        auto *bar = new QHBoxLayout(row);
        bar->setContentsMargins(0, 0, 0, 0);
        auto *field = new QLineEdit(value);
        field->setObjectName(name);
        auto *browse = new QPushButton("Browse…");
        bar->addWidget(field, 1);
        bar->addWidget(browse);
        connect(browse, &QPushButton::clicked, &dialog, [&, field] {
            auto dir = QFileDialog::getExistingDirectory(&dialog, "Choose directory", field->text());
            if (!dir.isEmpty())
                field->setText(dir);
        });
        form->addRow(title, row);
        return field;
    };
    auto *home = entry("Ghidra folder", config.home, "ghidraHome");
    auto *java = entry("JDK folder", config.javaHome, "ghidraJavaHome");
    layout->addLayout(form);
    auto *message = new QLabel;
    message->setWordWrap(true);
    layout->addWidget(message);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
        GhidraConfig proposed{QDir::cleanPath(home->text().trimmed()),
                              QDir::cleanPath(java->text().trimmed())};
        auto issue = proposed.error();
        if (!issue.isEmpty()) {
            message->setText(issue);
            return;
        }
        proposed.save();
        dialog.accept();
    });
    dialog.resize(690, dialog.sizeHint().height());
    if (dialog.exec() == QDialog::Accepted && image)
        openDecompiler();
}
void MainWindow::openDecompiler() {
    decompiled.reset();
    requestedDecompilation.clear();
    pendingDecompilerEdit.reset();
    pseudocode->setFunction({});
    functionPicker->clear();
    functionSummary->setText("Reconstructed C-like code · select a recovered function to inspect its logic");
    decompiler->open(image);
}
QJsonArray MainWindow::analysisEdits() const {
    QJsonArray edits = work.decompilerEdits;
    if (decompiler)
        for (auto it = work.renames.begin(); it != work.renames.end(); ++it) {
            const auto *f = decompiler->containing(it.key());
            if (f && f->entry == it.key() &&
                QRegularExpression("^[A-Za-z_][A-Za-z0-9_]{0,127}$").match(it.value()).hasMatch())
                edits.append(QJsonObject{
                    {"kind", "function_name"}, {"function", hex(it.key())}, {"text", it.value()}});
        }
    return edits;
}
void MainWindow::setDebuggerPanesVisible(bool visible) {
    for (auto *pane : {registerDock, stackDock, framesDock, breakpointsDock, threadsDock, timelineDock,
                       modulesDock, outputDock})
        pane->setVisible(visible);
    if (visible) {
        registerDock->raise();
        resizeDocks({registerDock}, {std::clamp(height() / 5, 125, 220)}, Qt::Vertical);
    }
}
std::optional<quint64> MainWindow::staticSelection(QString *reason) const {
    if (!image) {
        if (reason)
            *reason = "Open a Windows x64 PE first.";
        return {};
    }
    if (evidenceCode) {
        if (reason)
            *reason = "Historical snapshots do not contain verified module identity; return to static file "
                      "analysis for decompilation.";
        return {};
    }
    if (liveCode && debugger.state() != Debugger::State::Paused) {
        if (reason)
            *reason = "Pause the process before linking runtime bytes to static pseudocode.";
        return {};
    }
    auto a = preferredAddress(*image, work.selected, liveCode, live.modules);
    if (!a) {
        if (reason)
            *reason = "The selected address cannot be mapped to this PE image. Dynamic or unrelated code has "
                      "no on-disk pseudocode.";
        return {};
    }
    if (liveCode && decompiler) {
        const auto *f = decompiler->containing(*a);
        auto runtimeBase = work.selected - (*a - image->base);
        if (!f || !matchingRuntimeBytes(*image, live.code, runtimeBase, *f, reason))
            return {};
    }
    return a;
}
void MainWindow::updateDecompilerSelection() {
    if (!pseudocode || !decompiler)
        return;
    QString reason;
    auto a = staticSelection(&reason);
    const auto *f = a ? decompiler->containing(*a) : nullptr;
    if (decompiled && f && f->entry == decompiled->entry && decompiled->edits == analysisEdits()) {
        pseudocode->selectAddress(*a);
        if (liveCode)
            decompilerStatus->setText("Static Ghidra reconstruction · captured live bytes match; unobserved "
                                      "function bytes remain static assumptions");
        auto index = codeView->currentIndex();
        if (index.isValid()) {
            QSignalBlocker b(splitAssembly->selectionModel());
            splitAssembly->setCurrentIndex(index);
            splitAssembly->scrollTo(index.siblingAtColumn(1));
        }
        return;
    }
    if (decompiled) {
        decompiled.reset();
        pseudocode->setFunction({});
    }
    if (!reason.isEmpty())
        decompilerStatus->setText(reason);
    decompilerNavigation.start();
}
void MainWindow::requestDecompilation(bool force) {
    if (loading || pendingDecompilerEdit)
        return;
    QString reason;
    auto selection = staticSelection(&reason);
    if (!selection) {
        decompilerStatus->setText(reason);
        return;
    }
    if (!decompiler->ready()) {
        if (!decompiler->busy() && force)
            openDecompiler();
        return;
    }
    const auto *f = decompiler->containing(*selection);
    if (!f) {
        decompilerStatus->setText(
            "Ghidra did not recover a function at this instruction; assembly remains available.");
        return;
    }
    auto edits = analysisEdits();
    if (!force && decompiled && decompiled->entry == f->entry && decompiled->edits == edits) {
        pseudocode->selectAddress(*selection);
        return;
    }
    auto key = QByteArray::number(f->entry) + QJsonDocument(edits).toJson(QJsonDocument::Compact);
    if (!force && key == requestedDecompilation)
        return;
    requestedDecompilation = key;
    decompiler->request(*selection, edits);
}
void MainWindow::editDecompiled(QString kind, QString variable) {
    if (!decompiled || !decompiler->ready() || decompiler->busy() || pendingDecompilerEdit || liveCode ||
        evidenceCode) {
        statusBar()->showMessage("Select a completed static decompilation before editing names or types.",
                                 6000);
        return;
    }
    QJsonObject edit{{"kind", kind}, {"function", hex(decompiled->entry)}};
    QString value = kind == "signature"       ? decompiled->signature
                    : kind == "function_name" ? decompiled->name
                                              : QString();
    if (kind.startsWith("variable_")) {
        QJsonArray vars = decompiled->data["variables"].toArray();
        QStringList names;
        for (auto v : vars)
            names << v.toObject()["name"].toString();
        if (names.isEmpty()) {
            statusBar()->showMessage("Ghidra recovered no editable local variables.", 5000);
            return;
        }
        bool ok = true;
        if (!names.contains(variable))
            variable =
                QInputDialog::getItem(this, "Choose recovered variable", "Variable:", names, 0, false, &ok);
        if (!ok)
            return;
        for (auto v : vars)
            if (v.toObject()["name"].toString() == variable) {
                auto o = v.toObject();
                edit["storage"] = o["storage"];
                edit["previous"] = variable;
                value = kind == "variable_type" ? o["type"].toString() : variable;
                break;
            }
    }
    bool ok = false;
    auto proposed = QInputDialog::getText(this, "Edit recovered analysis",
                                          kind == "signature" ? "C signature (known types and pointers):"
                                          : kind == "variable_type" ? "C type (known types and pointers):"
                                                                    : "New identifier:",
                                          QLineEdit::Normal, value, &ok)
                        .trimmed();
    if (!ok || proposed.isEmpty() || proposed == value)
        return;
    if (proposed.size() > 4096 ||
        (kind.endsWith("_name") &&
         !QRegularExpression("^[A-Za-z_][A-Za-z0-9_]{0,127}$").match(proposed).hasMatch())) {
        error("Use an ASCII identifier up to 128 characters; C declarations are limited to 4096 characters.");
        return;
    }
    edit["text"] = proposed;
    auto edits = analysisEdits();
    edits.append(edit);
    pendingDecompilerEdit = edit;
    requestedDecompilation.clear();
    decompiler->request(decompiled->entry, edits);
}
void MainWindow::decompilerReferences() {
    if (!decompiled)
        return;
    QDialog dialog(this);
    dialog.setWindowTitle("Recovered function cross-references");
    auto *layout = new QVBoxLayout(&dialog);
    auto *list = new QTreeWidget;
    list->setHeaderLabels({"Direction / kind", "Address", "Symbol / string"});
    for (auto c : decompiled->data["callers"].toArray()) {
        auto o = c.toObject();
        auto *row =
            new QTreeWidgetItem(list, {"Incoming · " + o["kind"].toString(), o["from"].toString(), {}});
        row->setData(0, Qt::UserRole, QVariant::fromValue(va(o["from"])));
    }
    for (auto r : decompiled->data["references"].toArray()) {
        auto o = r.toObject();
        auto target = va(o["to"]);
        auto *row =
            new QTreeWidgetItem(list, {"Outgoing · " + o["kind"].toString(),
                                       target ? o["to"].toString() : "External symbol (jump to call site)",
                                       o["name"].toString() + " " + o["string"].toString()});
        row->setData(0, Qt::UserRole, QVariant::fromValue(target ? target : va(o["from"])));
    }
    layout->addWidget(new QLabel("Static references from Ghidra. Double-click an address to navigate; this "
                                 "does not imply execution."));
    layout->addWidget(list);
    auto *close = new QDialogButtonBox(QDialogButtonBox::Close);
    layout->addWidget(close);
    connect(close, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(list, &QTreeWidget::itemActivated, &dialog, [this, &dialog](QTreeWidgetItem *item, int) {
        auto a = item->data(0, Qt::UserRole).toULongLong();
        dialog.accept();
        navigate(relocateStatic(a));
    });
    list->resizeColumnToContents(0);
    list->resizeColumnToContents(1);
    dialog.resize(760, 460);
    dialog.exec();
}
} // namespace vnr
