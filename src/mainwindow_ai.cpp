#include "mainwindow.h"
#include <algorithm>
#include <stdexcept>

namespace vnr {
void MainWindow::setupAi(QMenu *investigate, QMenu *settings) {
    aiPanel = new AiPanel(nullptr, providedAiService);
    aiDock = dock("AI Explanation / Readable Code", "aiExplanationDock", aiPanel, Qt::RightDockWidgetArea);
    tabifyDockWidget(contextDock, aiDock);
    aiDock->hide();
    contextDock->raise();
    aiPanel->contextBuilder = [this](AiScope scope, bool runtime) { return aiContext(scope, runtime); };
    auto *providers = settings->addAction("AI Providers…");
    providers->setObjectName("aiProvidersAction");
    connect(providers, &QAction::triggered, aiPanel, &AiPanel::settings);
    investigate->addSeparator();
    const QList<QPair<QString, AiScope>> actions{{"Explain Instruction…", AiScope::Instruction},
                                                 {"Explain Block…", AiScope::Block},
                                                 {"Explain Function…", AiScope::Function}};
    for (const auto &[title, scope] : actions) {
        auto *action = investigate->addAction(title);
        action->setObjectName(scope == AiScope::Instruction ? "aiExplainInstruction"
                              : scope == AiScope::Block     ? "aiExplainBlock"
                                                            : "aiExplainFunction");
        action->setToolTip("Optional AI interpretation. Review exact context and approve before sending.");
        connect(action, &QAction::triggered, this, [this, scope] {
            aiDock->show();
            aiDock->raise();
            aiPanel->requestExplanation(scope);
        });
    }
    auto *mode = investigate->addAction("Readable Code Mode");
    mode->setObjectName("readableCodeModeAction");
    mode->setCheckable(true);
    connect(mode, &QAction::toggled, this, [this](bool visible) {
        aiDock->setVisible(visible);
        if (visible)
            aiDock->raise();
    });
    connect(aiDock, &QDockWidget::visibilityChanged, mode, [this, mode](bool) {
        QSignalBlocker blocker(mode);
        mode->setChecked(!aiDock->isHidden());
    });
    connect(aiPanel, &AiPanel::sourceRequested, this, [this](quint64 address) { navigate(address); });
    connect(aiPanel, &AiPanel::applyRequested, this, [this](const AiSuggestion &suggestion) {
        if (loading || (!image && !liveCode && !evidenceCode)) {
            error("No matching source is available");
            return;
        }
        bool rename = suggestion.kind == "function_name";
        const auto *recovered = decompiler ? decompiler->containing(suggestion.address) : nullptr;
        bool knownRecovered = recovered && recovered->entry == suggestion.address;
        if (rename && (liveCode || evidenceCode || !image ||
                       (!knownRecovered &&
                        std::none_of(image->functions.begin(), image->functions.end(),
                                     [&](const Row &r) { return r.address == suggestion.address; })))) {
            error("Only known static function candidates can be renamed. Runtime variable/name suggestions "
                  "can be saved as comments.");
            return;
        }
        QString proposed = suggestion.kind == "variable_name"
                               ? "Suggested label for " + suggestion.variable + ": " + suggestion.text
                               : suggestion.text;
        QString current =
            rename ? work.renames.value(suggestion.address) : work.comments.value(suggestion.address);
        auto sourceBeforeReview = aiSourceIdentity();
        QMessageBox review(QMessageBox::Question, "Review AI suggestion", {},
                           QMessageBox::Yes | QMessageBox::Cancel, this);
        review.setObjectName("aiSuggestionReview");
        review.setTextFormat(Qt::PlainText);
        review.setText(
            QString("Apply this %1 to your investigation at %2?\n\nExisting: %3\n\nProposed: %4\n\n"
                    "This is an AI suggestion. It changes only local annotations, never the target process. "
                    "Variable labels are advisory comments.")
                .arg(rename ? "function name" : "comment", hex(suggestion.address),
                     current.isEmpty() ? "(none)" : current, proposed));
        review.setDefaultButton(QMessageBox::Cancel);
        if (review.exec() != QMessageBox::Yes)
            return;
        if (sourceBeforeReview != aiSourceIdentity() || loading) {
            error("The source changed during review. Request and review a fresh suggestion.");
            return;
        }
        if (rename)
            work.renames[suggestion.address] = suggestion.text;
        QString annotation = "[Reviewed AI suggestion] " + proposed;
        auto &comment = work.comments[suggestion.address];
        comment += (comment.isEmpty() ? QString() : "\n") + annotation;
        changed();
        refreshNavigation();
        codeView->viewport()->update();
        navigate(suggestion.address);
    });
    connect(&debugger, &Debugger::stateChanged, this, [this](Debugger::State, QString) {
        if (aiPanel && liveCode)
            aiPanel->sourceChanged(aiSourceIdentity());
    });
}
QByteArray MainWindow::aiSourceIdentity() const {
    QByteArray raw;
    QDataStream stream(&raw, QIODevice::WriteOnly);
    stream << (image ? image->hash : QString()) << liveCode << evidenceCode;
    if (decompiled)
        stream << decompiled->entry << decompiled->code << QJsonDocument(analysisEdits()).toJson();
    if (evidenceCode && displayedEvidence)
        stream << displayedEvidence->time << displayedEvidence->ip << displayedEvidence->thread
               << displayedEvidence->code << displayedEvidence->registers;
    else if (liveCode) {
        stream << int(debugger.state()) << live.ip << live.thread << live.registers;
        for (const auto &i : live.code)
            stream << i.address << i.bytes;
    }
    return QCryptographicHash::hash(raw, QCryptographicHash::Sha256);
}
AiContext MainWindow::aiContext(AiScope scope, bool runtime) const {
    if (loading)
        throw std::runtime_error("Wait for static analysis to finish before requesting an explanation");
    if (liveCode && debugger.state() != Debugger::State::Paused)
        throw std::runtime_error("Pause the process before requesting runtime code explanations");
    const Event *event = runtime && evidenceCode && displayedEvidence ? &*displayedEvidence : nullptr;
    const Snapshot *snapshot = runtime && liveCode ? &live : nullptr;
    if (runtime && liveCode) {
        for (auto it = work.events.crbegin(); it != work.events.crend(); ++it)
            if (it->ip == live.ip && it->thread == live.thread && it->registers == live.registers) {
                event = &*it;
                break;
            }
    }
    QString mappingReason;
    auto preferred = staticSelection(&mappingReason);
    const auto *function = preferred && decompiler ? decompiler->containing(*preferred) : nullptr;
    if (decompiled && function && decompiled->entry == function->entry &&
        decompiled->edits == analysisEdits()) {
        Snapshot mappedSnapshot;
        Event mappedEvent;
        if (snapshot) {
            mappedSnapshot = *snapshot;
            mappedSnapshot.ip = image->base + snapshot->ip - (work.selected - (*preferred - image->base));
            snapshot = &mappedSnapshot;
        }
        if (event && !evidenceCode) {
            mappedEvent = *event;
            mappedEvent.ip = snapshot ? snapshot->ip : event->ip;
            event = &mappedEvent;
        }
        auto context = makeAiContext(image.get(), decompiled->instructions, *preferred, scope,
                                     liveCode ? "Ghidra static reconstruction; only the captured live byte "
                                                "window was compared with the file"
                                              : "Static file and Ghidra reconstruction",
                                     snapshot, event, &*decompiled);
        if (liveCode)
            context.data["runtime_address_mapping"] = QJsonObject{
                {"selected_runtime_va", hex(work.selected)},
                {"preferred_file_va", hex(*preferred)},
                {"binary_sha256", image->hash},
                {"coverage",
                 "Only captured instruction bytes compared. Unobserved code remains a static assumption; "
                 "absolute relocated operands are conservatively rejected if different."}};
        return context;
    }
    return makeAiContext(!liveCode && !evidenceCode ? image.get() : nullptr, selectedFunction(),
                         work.selected, scope,
                         evidenceCode ? "Historical saved process bytes"
                         : liveCode   ? "Current paused process bytes"
                                      : "Static file bytes",
                         snapshot, event);
}
} // namespace vnr
