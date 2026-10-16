#include "ai_panel.h"
#include <stdexcept>

namespace vnr {
class CompactAiLabel : public QLabel {
  public:
    explicit CompactAiLabel(QString value) : QLabel(std::move(value)) {
        setTextFormat(Qt::PlainText);
        setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        setFixedHeight(fontMetrics().height() + 4);
        setFocusPolicy(Qt::StrongFocus);
        setAccessibleDescription("Full text: Control+Enter or context menu.");
        setContextMenuPolicy(Qt::ActionsContextMenu);
        auto *details = new QAction("Show full message…", this);
        details->setShortcut(QKeySequence("Ctrl+Return"));
        details->setShortcutContext(Qt::WidgetShortcut);
        addAction(details);
        connect(details, &QAction::triggered, this, [this] {
            QMessageBox message(QMessageBox::Information, "AI explanation details", {}, QMessageBox::Ok,
                                this);
            message.setTextFormat(Qt::PlainText);
            message.setText(text());
            message.exec();
        });
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        painter.setPen(palette().color(QPalette::WindowText));
        painter.drawText(
            rect(), Qt::AlignVCenter | Qt::AlignLeft,
            fontMetrics().elidedText(QString(text()).replace('\n', ' '), Qt::ElideRight, width()));
    }
    bool event(QEvent *event) override {
        if (event->type() == QEvent::ToolTip) {
            auto *help = static_cast<QHelpEvent *>(event);
            QToolTip::showText(help->globalPos(),
                               "<p>" + text().toHtmlEscaped().replace('\n', "<br>") +
                                   "</p><p>Control+Enter: full message</p>",
                               this);
            return true;
        }
        return QLabel::event(event);
    }
};
static QLabel *plainLabel(QString text = {}) {
    auto *label = new QLabel(text);
    label->setTextFormat(Qt::PlainText);
    label->setWordWrap(true);
    return label;
}
static QString modelSetting(AiService *ai) {
    QString account = ai->kind() == AiProviderKind::ChatGpt ? ai->authentication()->store().activeClient
                                                            : ai->endpointLabel();
    return "ai/model/" + QString::fromLatin1(
                             QCryptographicHash::hash(account.toUtf8(), QCryptographicHash::Sha256).toHex());
}
AiPanel::AiPanel(QWidget *parent, AiService *service)
    : QWidget(parent), ai(service ? service : new AiService(this)) {
    setObjectName("aiPanel");
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(6, 6, 6, 6);
    layout->setSpacing(4);
    auto *header = new QHBoxLayout;
    auto *title = plainLabel("Readable Code · optional AI");
    auto font = title->font();
    font.setBold(true);
    title->setFont(font);
    auto *configure = new QPushButton("Providers…");
    configure->setObjectName("aiProviderSettingsButton");
    header->addWidget(title, 1);
    header->addWidget(configure);
    layout->addLayout(header);
    title->setToolTip("AI interpretations can be wrong. Meaning and all debugger tools remain independent.");
    auto *controls = new QHBoxLayout;
    scopeBox = new QComboBox;
    scopeBox->setObjectName("aiScope");
    scopeBox->addItems({"Instruction", "Basic block", "Function window"});
    scopeBox->setToolTip(
        "Function analysis uses the available bounded window, not a complete decompilation.");
    explainButton = new QPushButton("Explain selection");
    explainButton->setObjectName("aiExplainButton");
    cancelButton = new QPushButton("Cancel");
    cancelButton->setEnabled(false);
    cancelButton->setObjectName("aiCancelButton");
    controls->addWidget(scopeBox);
    controls->addWidget(explainButton, 1);
    controls->addWidget(cancelButton);
    layout->addLayout(controls);
    sourceLabel = new CompactAiLabel("Select code, configure a provider, then request an explanation.");
    sourceLabel->setObjectName("aiSourceLabel");
    layout->addWidget(sourceLabel);
    text = new QTextBrowser;
    text->setMinimumHeight(70);
    text->setObjectName("aiExplanation");
    text->setOpenLinks(false);
    text->setOpenExternalLinks(false);
    layout->addWidget(text, 1);
    suggestions = new QComboBox;
    suggestions->setObjectName("aiSuggestions");
    suggestions->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    suggestions->setMinimumContentsLength(15);
    applyButton = new QPushButton("Review…");
    applyButton->setToolTip("Review the selected AI suggestion before applying it to local annotations.");
    applyButton->setObjectName("aiApplySuggestion");
    applyButton->setEnabled(false);
    auto *annotationRow = new QHBoxLayout;
    annotationRow->setSpacing(4);
    annotationRow->addWidget(suggestions, 1);
    annotationRow->addWidget(applyButton);
    layout->addLayout(annotationRow);
    statusLabel = new CompactAiLabel("AI is optional. No inference runs automatically.");
    statusLabel->setObjectName("aiStatus");
    layout->addWidget(statusLabel);
    connect(configure, &QPushButton::clicked, this, &AiPanel::settings);
    connect(explainButton, &QPushButton::clicked, this,
            [this] { requestExplanation(AiScope(scopeBox->currentIndex())); });
    connect(cancelButton, &QPushButton::clicked, this, [this] {
        ai->cancel();
        result = {};
        suggestions->clear();
        applyButton->setEnabled(false);
        statusLabel->setText("Cancelled. Any partial text is unverified and cannot be applied.");
    });
    connect(ai, &AiService::status, statusLabel, &QLabel::setText);
    connect(ai, &AiService::failed, this, [this](QString error) {
        result = {};
        suggestions->clear();
        applyButton->setEnabled(false);
        statusLabel->setText("Request failed: " + error + "\nPartial text, if any, is unverified.");
    });
    connect(ai, &AiService::busyChanged, this, [this](bool busy) {
        explainButton->setEnabled(!busy);
        cancelButton->setEnabled(busy);
        applyButton->setEnabled(!busy && !result.suggestions.isEmpty());
        scopeBox->setEnabled(!busy);
    });
    connect(ai, &AiService::progress, this, [this](QString value) {
        text->setPlainText("AI-generated draft · streaming · unverified\n\n" + value);
        statusLabel->setText("Receiving explanation… Cancel is available; debugger controls remain usable.");
    });
    connect(ai, &AiService::completed, this, &AiPanel::showResult);
    connect(text, &QTextBrowser::anchorClicked, this, [this](QUrl url) {
        if (url.scheme() != "ai-source")
            return;
        bool ok = false;
        auto address = url.path().toULongLong(&ok, 16);
        if (ok && result.context.addresses.contains(address))
            emit sourceRequested(address);
    });
    connect(applyButton, &QPushButton::clicked, this, [this] {
        auto index = suggestions->currentIndex();
        if (index >= 0 && index < result.suggestions.size() && !ai->busy())
            emit applyRequested(result.suggestions[index]);
    });
    auto *auth = ai->authentication();
    connect(auth, &ChatGptAuth::authorizationReady, this, [auth](QUrl url) {
        if (!QDesktopServices::openUrl(url)) {
            auth->cancel();
            emit auth->failed("Could not open the system browser. Retry sign-in.");
        }
    });
    connect(auth, &ChatGptAuth::failed, statusLabel, &QLabel::setText);
    // Restore configuration without making any network requests.
    auto setting = QSettings();
    int kind = setting.value("ai/provider", 0).toInt();
    try {
        ai->configure(kind >= 0 && kind <= 2 ? AiProviderKind(kind) : AiProviderKind::Disabled,
                      QUrl(setting.value("ai/localEndpoint", "http://127.0.0.1:1234/v1").toString()));
    } catch (const std::exception &e) {
        ai->configure(AiProviderKind::Disabled);
        statusLabel->setText(QString::fromUtf8(e.what()));
    }
}
void AiPanel::resizeEvent(QResizeEvent *event) {
    QWidget::resizeEvent(event);
    if (sourceLabel)
        sourceLabel->setVisible(height() >= 340);
}
void AiPanel::sourceChanged(QByteArray token) {
    if (sourceToken == token)
        return;
    sourceToken = std::move(token);
    ai->cancel();
    result = {};
    suggestions->clear();
    applyButton->setEnabled(false);
    text->clear();
    sourceLabel->setText("Source changed. Request an explanation for this binary or snapshot.");
}
void AiPanel::requestExplanation(AiScope scope) {
    scopeBox->setCurrentIndex(int(scope));
    if (ai->busy()) {
        statusLabel->setText("Cancel the current request before explaining another selection.");
        return;
    }
    if (ai->kind() == AiProviderKind::Disabled || ai->selectedModel().isEmpty()) {
        settings();
        if (ai->selectedModel().isEmpty()) {
            statusLabel->setText("Choose a provider and model, then explain the selection.");
            return;
        }
    }
    try {
        if (!contextBuilder)
            throw std::runtime_error("No analysis context is available");
        AiContext context = contextBuilder(scope, false);
        auto token = sourceToken;
        QDialog dialog(this);
        dialog.setWindowTitle(ai->kind() == AiProviderKind::ChatGpt
                                  ? "Review data before sending to OpenAI"
                                  : "Review data before sending to the local server");
        dialog.setObjectName("aiConsentDialog");
        auto available = screen()->availableGeometry().size();
        dialog.resize(std::min(760, available.width() - 40), std::min(580, available.height() - 60));
        auto *layout = new QVBoxLayout(&dialog);
        layout->addWidget(
            plainLabel("Destination: " + ai->endpointLabel() + "\nModel: " + ai->selectedModel() +
                       "\nOnly the JSON below is submitted as analysis context. No entire binary, original "
                       "binary path, investigation notes or provider credentials are included. Review "
                       "binary-derived values before sending."));
        if (ai->kind() == AiProviderKind::Local)
            layout->addWidget(plainLabel("Use a locally loaded model for offline inference. Venor cannot "
                                         "verify whether your local server relays requests elsewhere."));
        auto *runtime = new QCheckBox("Include available register/API evidence at the labelled snapshot IP");
        runtime->setObjectName("aiIncludeRuntime");
        layout->addWidget(runtime);
        auto *preview = new QPlainTextEdit;
        preview->setObjectName("aiContextPreview");
        preview->setReadOnly(true);
        preview->setPlainText(QString::fromUtf8(context.serialized()));
        layout->addWidget(preview, 1);
        connect(runtime, &QCheckBox::toggled, &dialog, [&](bool include) {
            try {
                context = contextBuilder(scope, include);
                preview->setPlainText(QString::fromUtf8(context.serialized()));
            } catch (const std::exception &e) {
                preview->setPlainText(QString::fromUtf8(e.what()));
                context = {};
            }
        });
        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        buttons->button(QDialogButtonBox::Ok)->setText("Send selected context");
        buttons->button(QDialogButtonBox::Cancel)->setDefault(true);
        buttons->button(QDialogButtonBox::Ok)->setAutoDefault(false);
        layout->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
            return;
        if (token != sourceToken || context.addresses.isEmpty())
            throw std::runtime_error(
                "The selected source changed while reviewing. Review a fresh context before sending.");
        result = {};
        suggestions->clear();
        applyButton->setEnabled(false);
        text->clear();
        sourceLabel->setText(context.data["scope"].toString() + " at " +
                             context.data["selection"].toString() + " · " +
                             context.data["provenance"].toString());
        statusLabel->setText("Requesting an explanation…");
        ai->explain(context);
    } catch (const std::exception &e) {
        statusLabel->setText(QString::fromUtf8(e.what()));
    }
}
void AiPanel::showResult(AiExplanation answer) {
    result = std::move(answer);
    text->setHtml(aiExplanationHtml(result));
    suggestions->clear();
    for (const auto &s : result.suggestions)
        suggestions->addItem(s.kind + " · " + hex(s.address) + " · " + s.text.left(100));
    applyButton->setEnabled(!result.suggestions.isEmpty());
    statusLabel->setText(
        QString(
            "%1. %2 linked model reference(s); %3 unverified reference(s); %4 rejected suggestion(s). Review "
            "claims against assembly.")
            .arg(result.cached ? "Loaded from this session's cache" : "Explanation complete")
            .arg(result.verifiedReferences)
            .arg(result.invalidReferences)
            .arg(result.rejectedSuggestions));
}
void AiPanel::settings() {
    QDialog dialog(this);
    dialog.setObjectName("aiSettingsDialog");
    dialog.setWindowTitle("Settings — AI Providers");
    auto available = screen()->availableGeometry().size();
    dialog.resize(std::min(680, available.width() - 40), std::min(740, available.height() - 60));
    auto *outer = new QVBoxLayout(&dialog);
    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto *content = new QWidget;
    auto *layout = new QVBoxLayout(content);
    scroll->setWidget(content);
    outer->addWidget(scroll, 1);
    layout->addWidget(
        plainLabel("Optional AI explanations. Offline analysis and debugging work with AI disabled. "
                   "Inference only starts after reviewing and approving selected context."));
    auto *form = new QFormLayout;
    auto *provider = new QComboBox;
    provider->setObjectName("aiProviderChoice");
    provider->addItems(
        {"Disabled — offline deterministic tools", "ChatGPT subscription", "Local OpenAI-compatible server"});
    provider->setCurrentIndex(int(ai->kind()));
    form->addRow("Provider", provider);
    auto *endpoint =
        new QLineEdit(QSettings().value("ai/localEndpoint", "http://127.0.0.1:1234/v1").toString());
    endpoint->setObjectName("aiLocalEndpoint");
    form->addRow("Local server URL", endpoint);
    layout->addLayout(form);
    auto *localNote = plainLabel(
        "LM Studio: http://127.0.0.1:1234/v1 · Ollama: http://127.0.0.1:11434/v1. Start the server and load "
        "a local model first. Remote URLs are rejected; server authentication is not currently supported.");
    layout->addWidget(localNote);
    auto *group = new QGroupBox("ChatGPT accounts");
    auto *accountsLayout = new QVBoxLayout(group);
    auto *accounts = new QComboBox;
    accounts->setObjectName("aiAccounts");
    accountsLayout->addWidget(accounts);
    auto *accountStatus = plainLabel();
    accountStatus->setObjectName("aiAccountStatus");
    accountsLayout->addWidget(accountStatus);
    auto *signInButtons = new QHBoxLayout;
    auto *signIn = new QPushButton("Continue with ChatGPT");
    signIn->setObjectName("chatGptSignInButton");
    auto *reconnect = new QPushButton("Reconnect selected");
    auto *signOut = new QPushButton("Sign out");
    signInButtons->addWidget(signIn);
    signInButtons->addWidget(reconnect);
    signInButtons->addWidget(signOut);
    accountsLayout->addLayout(signInButtons);
    auto *cancelSignIn = new QPushButton("Cancel sign-in / renewal");
    accountsLayout->addWidget(cancelSignIn);
    accountsLayout->addWidget(plainLabel(
        "Uses eligible ChatGPT plan usage, subject to account/workspace permissions and limits. No API key "
        "or automatic paid-provider fallback. Reconnect if plan permission was declined. Credentials are "
        "encrypted for your Windows user; logout retains the registration for later sign-in."));
    layout->addWidget(group);
    auto *refresh = new QPushButton("Use provider and load models");
    refresh->setObjectName("aiLoadModels");
    layout->addWidget(refresh);
    auto *models = new QComboBox;
    models->setObjectName("aiModelChoice");
    layout->addWidget(models);
    auto *message = plainLabel(ai->authentication()->storageError());
    message->setObjectName("aiSettingsStatus");
    layout->addWidget(message);
    auto *footer = new QHBoxLayout;
    auto *clear = new QPushButton("Clear explanation cache");
    footer->addWidget(clear);
    auto *docs = new QPushButton("ChatGPT plan usage guide");
    footer->addWidget(docs);
    layout->addLayout(footer);
    layout->addStretch();
    auto *close = new QDialogButtonBox(QDialogButtonBox::Close);
    outer->addWidget(close);
    auto *auth = ai->authentication();
    auto updateAccounts = [=] {
        QSignalBlocker block(accounts);
        accounts->clear();
        int selected = -1;
        for (const auto &a : auth->store().accounts) {
            accounts->addItem(a.label(), a.clientId);
            if (a.clientId == auth->store().activeClient)
                selected = accounts->count() - 1;
        }
        accounts->setCurrentIndex(selected);
        const ChatGptAccount *account = nullptr;
        for (const auto &a : auth->store().accounts)
            if (a.clientId == auth->store().activeClient)
                account = &a;
        accountStatus->setText(
            !account ? "No ChatGPT account connected."
            : account->accessToken.isEmpty() && account->refreshToken.isEmpty() && account->idToken.isEmpty()
                ? "Signed out — reconnect this registration."
            : account->planEnabled()
                ? "Connected · ChatGPT plan permission granted. Model access is confirmed only by a "
                  "completed request."
                : "Signed in · ChatGPT plan usage permission was not granted. Reconnect to enable it.");
        signIn->setEnabled(!auth->busy());
        reconnect->setEnabled(!auth->busy() && account);
        signOut->setEnabled(!auth->busy() && account);
        accounts->setEnabled(!auth->busy());
        cancelSignIn->setEnabled(auth->busy());
    };
    auto updateModels = [=, this] {
        QSignalBlocker block(models);
        models->clear();
        QString desired = QSettings().value(modelSetting(ai)).toString();
        for (const auto &model : ai->availableModels())
            models->addItem(model.name, model.id);
        int selected = models->findData(ai->selectedModel().isEmpty() ? desired : ai->selectedModel());
        models->setCurrentIndex(selected);
        if (selected >= 0 && !ai->busy()) {
            try {
                ai->setModel(models->itemData(selected).toString());
            } catch (const std::exception &e) {
                message->setText(QString::fromUtf8(e.what()));
            }
        }
        models->setEnabled(!ai->busy() && models->count() > 0);
        refresh->setEnabled(!ai->busy() && !auth->busy());
    };
    auto providerChanged = [=](int index) {
        endpoint->setEnabled(index == 2);
        localNote->setVisible(index == 2);
    };
    providerChanged(provider->currentIndex());
    updateAccounts();
    updateModels();
    connect(provider, &QComboBox::currentIndexChanged, &dialog, providerChanged);
    connect(auth, &ChatGptAuth::changed, &dialog, updateAccounts);
    connect(auth, &ChatGptAuth::changed, &dialog, updateModels);
    connect(ai, &AiService::modelsReady, &dialog, updateModels);
    connect(ai, &AiService::busyChanged, &dialog, [=](bool) { updateModels(); });
    connect(auth, &ChatGptAuth::status, message, &QLabel::setText);
    connect(auth, &ChatGptAuth::failed, message, &QLabel::setText);
    connect(ai, &AiService::status, message, &QLabel::setText);
    connect(ai, &AiService::failed, message, &QLabel::setText);
    connect(accounts, &QComboBox::currentIndexChanged, &dialog, [=, this](int index) {
        if (index < 0)
            return;
        ai->cancel();
        ai->clearCache();
        auth->selectAccount(accounts->itemData(index).toString());
    });
    connect(signIn, &QPushButton::clicked, &dialog, [=] { auth->signIn(); });
    connect(reconnect, &QPushButton::clicked, &dialog,
            [=] { auth->signIn(accounts->currentData().toString()); });
    connect(cancelSignIn, &QPushButton::clicked, &dialog, [=] {
        auth->cancel();
        updateAccounts();
        updateModels();
        message->setText("Authentication cancelled.");
    });
    connect(signOut, &QPushButton::clicked, &dialog, [=, this] {
        ai->cancel();
        ai->clearCache();
        auth->signOut();
        result = {};
        text->clear();
        suggestions->clear();
        applyButton->setEnabled(false);
    });
    connect(refresh, &QPushButton::clicked, &dialog, [=, this] {
        try {
            ai->configure(AiProviderKind(provider->currentIndex()), QUrl(endpoint->text().trimmed()));
            QSettings s;
            s.setValue("ai/provider", provider->currentIndex());
            s.setValue("ai/localEndpoint", endpoint->text().trimmed());
            result = {};
            text->clear();
            suggestions->clear();
            applyButton->setEnabled(false);
            if (ai->kind() != AiProviderKind::Disabled)
                ai->fetchModels();
            else
                message->setText("AI is disabled. Offline tools remain available.");
        } catch (const std::exception &e) {
            message->setText(QString::fromUtf8(e.what()));
        }
    });
    connect(models, &QComboBox::currentIndexChanged, &dialog, [=, this](int index) {
        if (index < 0)
            return;
        try {
            ai->setModel(models->itemData(index).toString());
            QSettings().setValue(modelSetting(ai), ai->selectedModel());
        } catch (const std::exception &e) {
            message->setText(QString::fromUtf8(e.what()));
        }
    });
    connect(clear, &QPushButton::clicked, &dialog, [this, message] {
        ai->clearCache();
        message->setText("This session's explanation cache was cleared.");
    });
    connect(docs, &QPushButton::clicked, &dialog, [] {
        QDesktopServices::openUrl(QUrl("https://developers.openai.com/siwc/token-sharing-open-source"));
    });
    connect(close, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.exec();
}
} // namespace vnr
