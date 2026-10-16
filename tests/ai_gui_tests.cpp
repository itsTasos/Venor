#include "ai_test_support.h"
#include "mainwindow.h"
#include <QtTest>
using namespace vnr;
static QString sample, captures;
static void capture(QWidget &widget, QString name) {
    if (captures.isEmpty())
        return;
    QDir().mkpath(captures);
    QTest::qWait(60);
    widget.grab().save(captures + "/" + name + ".png");
}
// A labelled protocol fixture, not a language model. All requests stay on loopback.
class LoopbackAiServer : public QObject {
    QTcpServer server;

  public:
    int modelRequests = 0, inferenceRequests = 0;
    bool hanging = false;
    QJsonObject received;
    LoopbackAiServer() {
        if (!server.listen(QHostAddress::LocalHost, 0))
            throw std::runtime_error("Cannot start local protocol fixture");
        connect(&server, &QTcpServer::newConnection, this, [this] {
            while (auto *socket = server.nextPendingConnection()) {
                auto bytes = std::make_shared<QByteArray>();
                auto handled = std::make_shared<bool>(false);
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, this, [=, this] {
                    if (*handled)
                        return;
                    *bytes += socket->readAll();
                    int end = int(bytes->indexOf("\r\n\r\n"));
                    if (end < 0)
                        return;
                    int contentLength = 0;
                    for (const auto &line : bytes->left(end).split('\n'))
                        if (line.toLower().startsWith("content-length:"))
                            contentLength = line.mid(15).trimmed().toInt();
                    if (bytes->size() < end + 4 + contentLength)
                        return;
                    *handled = true;
                    QByteArray body, type;
                    if (bytes->startsWith("GET /v1/models ")) {
                        ++modelRequests;
                        body = jsonBytes(
                            {{"data", QJsonArray{QJsonObject{{"id", "labelled-protocol-fixture"}}}}});
                        type = "application/json";
                    } else {
                        ++inferenceRequests;
                        received = QJsonDocument::fromJson(bytes->mid(end + 4, contentLength)).object();
                        if (hanging)
                            return;
                        auto messages = received["messages"].toArray();
                        auto context =
                            QJsonDocument::fromJson(messages.at(1).toObject()["content"].toString().toUtf8())
                                .object();
                        auto address = context["selection"].toString();
                        QString text =
                            "PROTOCOL TEST FIXTURE — not a model-generated explanation.\n\n"
                            "Observed facts: submitted bytes include [" +
                            address +
                            "].\nInterpretation: review the deterministic Meaning panel.\n"
                            "Unknowns: no real model is running in this test.\nUnverified reference "
                            "[0xdeadbeef].\n"
                            "<venor-suggestions>{\"suggestions\":[{\"kind\":\"comment\",\"address\":\"" +
                            address +
                            "\",\"text\":\"Protocol fixture annotation requiring explicit "
                            "review\"}]}</venor-suggestions>";
                        body = localStream(text);
                        type = "text/event-stream";
                    }
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: " + type +
                                  "\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n" +
                                  body);
                    socket->disconnectFromHost();
                });
            }
        });
    }
    QUrl endpoint() const {
        return QUrl(QString("http://127.0.0.1:%1/v1").arg(server.serverPort()));
    }
};
class AiGuiTests : public QObject {
    Q_OBJECT
  private slots:
    void settingsConsentAndAnnotations() {
        QTemporaryDir temp(QDir::currentPath() + "/ai-case-XXXXXX");
        QSettings().clear();
        LoopbackAiServer server;
        ChatGptAuth auth(nullptr, temp.filePath("credentials"));
        AiService service(nullptr, &auth);
        MainWindow window(&service);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        window.openBinary(sample);
        QTRY_VERIFY_WITH_TIMEOUT(bool(window.binary()), 20000);
        auto *panel = window.findChild<AiPanel *>("aiPanel");
        QVERIFY(panel);
        QCOMPARE(service.kind(), AiProviderKind::Disabled);
        QCOMPARE(server.modelRequests, 0);
        auto *dock = window.findChild<QDockWidget *>("aiExplanationDock");
        QVERIFY(dock);
        dock->show();
        dock->raise();
        QTimer::singleShot(80, &window, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            QVERIFY(dialog);
            QCOMPARE(dialog->objectName(), QString("aiSettingsDialog"));
            capture(*dialog, "ai-settings-disabled");
            dialog->findChild<QComboBox *>("aiProviderChoice")->setCurrentIndex(2);
            dialog->findChild<QLineEdit *>("aiLocalEndpoint")->setText(server.endpoint().toString());
            QTest::mouseClick(dialog->findChild<QPushButton *>("aiLoadModels"), Qt::LeftButton);
            auto *models = dialog->findChild<QComboBox *>("aiModelChoice");
            QTRY_COMPARE(models->count(), 1);
            models->setCurrentIndex(0);
            capture(*dialog, "ai-settings-local-fixture");
            dialog->reject();
        });
        panel->settings();
        QCOMPARE(server.modelRequests, 1);
        QCOMPARE(service.selectedModel(), QString("labelled-protocol-fixture"));
        QTimer::singleShot(80, &window, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            QVERIFY(dialog);
            QCOMPARE(dialog->objectName(), QString("aiConsentDialog"));
            auto preview = dialog->findChild<QPlainTextEdit *>("aiContextPreview")->toPlainText();
            QVERIFY(preview.contains("deterministic_interpretation"));
            QVERIFY(!preview.contains(QFileInfo(sample).absolutePath()));
            QVERIFY(!dialog->findChild<QCheckBox *>("aiIncludeRuntime")->isChecked());
            capture(*dialog, "ai-context-review");
            dialog->reject();
        });
        panel->requestExplanation(AiScope::Block);
        QCOMPARE(server.inferenceRequests, 0);
        auto approve = [&] {
            QTimer::singleShot(80, &window, [&] {
                auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
                QVERIFY(dialog);
                QCOMPARE(dialog->objectName(), QString("aiConsentDialog"));
                dialog->accept();
            });
        };
        QSignalSpy complete(&service, &AiService::completed);
        approve();
        panel->requestExplanation(AiScope::Block);
        QTRY_COMPARE(complete.size(), 1);
        QCOMPARE(server.inferenceRequests, 1);
        auto *text = panel->findChild<QTextBrowser *>("aiExplanation");
        QVERIFY(text->toPlainText().contains("PROTOCOL TEST FIXTURE"));
        QVERIFY(text->toPlainText().contains("unverified reference"));
        QVERIFY(!text->toHtml().contains("ai-source:deadbeef"));
        auto *suggestionList = panel->findChild<QComboBox *>("aiSuggestions");
        auto *status = panel->findChild<QLabel *>("aiStatus");
        QVERIFY(!text->geometry().intersects(suggestionList->geometry()));
        QVERIFY(status->geometry().bottom() <= panel->height());
        capture(window, "ai-explanation-local-protocol-fixture");
        auto address = window.investigation().selected;
        QVERIFY(!window.investigation().comments.contains(address));
        QSignalSpy links(panel, &AiPanel::sourceRequested);
        auto linkAddress = QString::number(address, 16);
        QMetaObject::invokeMethod(text, "anchorClicked", Qt::DirectConnection,
                                  Q_ARG(QUrl, QUrl("ai-source:" + linkAddress)));
        QCOMPARE(links.size(), 1);
        QMetaObject::invokeMethod(text, "anchorClicked", Qt::DirectConnection,
                                  Q_ARG(QUrl, QUrl("ai-source:deadbeef")));
        QCOMPARE(links.size(), 1);
        auto *apply = panel->findChild<QPushButton *>("aiApplySuggestion");
        QVERIFY(apply->isEnabled());
        QTimer::singleShot(80, &window, [&] {
            auto *review = qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
            QVERIFY(review);
            QCOMPARE(review->objectName(), QString("aiSuggestionReview"));
            capture(*review, "ai-suggestion-review");
            review->done(QMessageBox::Cancel);
        });
        QTest::mouseClick(apply, Qt::LeftButton);
        QVERIFY(!window.investigation().comments.contains(address));
        QTimer::singleShot(80, &window, [&] {
            auto *review = qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
            QVERIFY(review);
            review->done(QMessageBox::Yes);
        });
        QTest::mouseClick(apply, Qt::LeftButton);
        QVERIFY(window.investigation().comments.value(address).contains("[Reviewed AI suggestion]"));
        QVERIFY(window.saveInvestigation(temp.filePath("reviewed.venor")));
        auto saved = loadWorkspace(temp.filePath("reviewed.venor"));
        QCOMPARE(saved.comments, window.investigation().comments);
        approve();
        panel->requestExplanation(AiScope::Block);
        QCOMPARE(complete.size(), 2);
        QCOMPARE(server.inferenceRequests, 1);
        QVERIFY(qvariant_cast<AiExplanation>(complete.last().first()).cached);
        service.clearCache();
        server.hanging = true;
        approve();
        panel->requestExplanation(AiScope::Instruction);
        QTRY_COMPARE(server.inferenceRequests, 2);
        QVERIFY(service.busy());
        QTest::mouseClick(panel->findChild<QPushButton *>("aiCancelButton"), Qt::LeftButton);
        QVERIFY(!service.busy());
        QVERIFY(!apply->isEnabled());
        QVERIFY(window.saveInvestigation(temp.filePath("reviewed.venor")));
        window.close();
    }
    void offlineAndSourceChange() {
        QTemporaryDir temp(QDir::currentPath() + "/ai-case-XXXXXX");
        QSettings().clear();
        FixtureNetwork network;
        ChatGptAuth auth(nullptr, temp.filePath("credentials"), &network);
        AiService service(nullptr, &auth, &network);
        MainWindow window(&service);
        window.show();
        window.openBinary(sample);
        QTRY_VERIFY_WITH_TIMEOUT(bool(window.binary()), 20000);
        auto *meaning = window.findChild<QTextBrowser *>("readableCode");
        if (!meaning)
            meaning = window.findChild<QTextBrowser *>("meaning");
        QVERIFY(window.binary()->code.size() > 0);
        QCOMPARE(network.sent.size(), 0);
        auto *mode = window.findChild<QAction *>("readableCodeModeAction");
        QVERIFY(mode);
        mode->trigger();
        QVERIFY(window.findChild<QDockWidget *>("aiExplanationDock")->isVisible());
        auto *panel = window.findChild<AiPanel *>("aiPanel");
        panel->sourceChanged("new-source");
        QVERIFY(panel->findChild<QTextBrowser *>("aiExplanation")->toPlainText().isEmpty());
        QVERIFY(!panel->findChild<QPushButton *>("aiApplySuggestion")->isEnabled());
        QVERIFY(window.saveInvestigation(temp.filePath("offline.venor")));
        window.close();
    }
    void realLocalModel() {
        QString model = qEnvironmentVariable("VENOR_LIVE_LOCAL_MODEL");
        if (model.isEmpty())
            QSKIP("Opt-in real local model check; set VENOR_LIVE_LOCAL_MODEL and start a local server");
        QApplication::setApplicationDisplayName("Venor — real local model verification");
        QTemporaryDir temp(QDir::currentPath() + "/ai-case-XXXXXX");
        QSettings().clear();
        if (!qEnvironmentVariableIsEmpty("VENOR_LIVE_LOCAL_MAX_TOKENS"))
            QSettings().setValue("ai/localMaxTokens",
                                 qEnvironmentVariableIntValue("VENOR_LIVE_LOCAL_MAX_TOKENS"));
        if (!qEnvironmentVariableIsEmpty("VENOR_LIVE_LOCAL_TIMEOUT_SECONDS"))
            QSettings().setValue("ai/localTimeoutSeconds",
                                 qEnvironmentVariableIntValue("VENOR_LIVE_LOCAL_TIMEOUT_SECONDS"));
        ChatGptAuth auth(nullptr, temp.filePath("credentials"));
        AiService service(nullptr, &auth);
        MainWindow window(&service);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        window.openBinary(sample);
        QTRY_VERIFY_WITH_TIMEOUT(bool(window.binary()), 20000);
        quint64 selected = window.binary()->entry;
        for (const auto &import : window.binary()->imports)
            if (import.name.contains("VirtualAlloc")) {
                for (const auto &instruction : window.binary()->code)
                    if (instruction.call && instruction.target == import.address) {
                        selected = instruction.address;
                        break;
                    }
            }
        window.navigate(selected);
        for (const auto &function : window.binary()->exports)
            if (function.name == "meaning_allocation") {
                selected = function.address;
                window.navigate(selected);
                break;
            }
        bool recovered = !qEnvironmentVariableIsEmpty("VENOR_GHIDRA_HOME");
        if (recovered) {
            auto *backend = window.findChild<DecompilerService *>();
            QTRY_VERIFY_WITH_TIMEOUT(backend->ready() || !backend->lastError().isEmpty(), 300000);
            QVERIFY2(backend->ready(), qPrintable(backend->lastError()));
            auto *editor = window.findChild<PseudocodeEditor *>("pseudocode");
            const auto *function = backend->containing(selected);
            QVERIFY(function);
            QTRY_COMPARE_WITH_TIMEOUT(editor->function().entry, function->entry, 120000);
        }
        auto endpoint = QUrl(qEnvironmentVariable("VENOR_LIVE_LOCAL_ENDPOINT", "http://127.0.0.1:11434/v1"));
        service.configure(AiProviderKind::Local, endpoint);
        QSignalSpy models(&service, &AiService::modelsReady), failures(&service, &AiService::failed);
        service.fetchModels();
        QTRY_COMPARE_WITH_TIMEOUT(models.size(), 1, 15000);
        service.setModel(model);
        auto *panel = window.findChild<AiPanel *>("aiPanel");
        auto *dock = window.findChild<QDockWidget *>("aiExplanationDock");
        dock->show();
        dock->raise();
        QTimer::singleShot(100, &window, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            QVERIFY(dialog);
            QCOMPARE(dialog->objectName(), QString("aiConsentDialog"));
            auto preview = dialog->findChild<QPlainTextEdit *>("aiContextPreview")->toPlainText();
            QVERIFY(!preview.contains(QFileInfo(sample).absolutePath()));
            QVERIFY(!preview.contains("observed_snapshot"));
            capture(*dialog, "ai-real-local-context-review");
            dialog->accept();
        });
        QSignalSpy completed(&service, &AiService::completed);
        panel->requestExplanation(recovered ? AiScope::Function : AiScope::Instruction);
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 660000);
        QVERIFY2(failures.isEmpty(),
                 failures.isEmpty() ? "" : qPrintable(failures.last().first().toString()));
        QCOMPARE(completed.size(), 1);
        auto answer = qvariant_cast<AiExplanation>(completed.first().first());
        QVERIFY(!answer.text.isEmpty());
        if (recovered)
            QVERIFY(answer.context.data["decompilation"].toObject()["pseudocode"].toString().contains(
                "VirtualAlloc"));
        QCOMPARE(answer.provider, QString("Local endpoint"));
        QCOMPARE(answer.model, model);
        capture(window, "ai-real-local-model-explanation");
        if (!captures.isEmpty()) {
            QSaveFile output(captures + "/real-local-explanation.json");
            QVERIFY(output.open(QIODevice::WriteOnly));
            output.write(
                QJsonDocument(QJsonObject{{"provider", answer.provider},
                                          {"model", answer.model},
                                          {"endpoint", endpoint.toString()},
                                          {"text", answer.text},
                                          {"invalid_references", answer.invalidReferences},
                                          {"context", answer.context.data},
                                          {"verification", "Real local inference completed through native "
                                                           "GUI; claims still require manual review"}})
                    .toJson());
            QVERIFY(output.commit());
        }
        QVERIFY(window.saveInvestigation(temp.filePath("real-local.venor")));
        window.close();
    }
};
int main(int argc, char **argv) {
    if (!qEnvironmentVariableIsEmpty("VENOR_LIVE_LOCAL_MODEL"))
        qputenv("QTEST_FUNCTION_TIMEOUT", "900000");
    QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
    QApplication app(argc, argv);
    app.setOrganizationName("VenorTests");
    app.setApplicationName("AiGuiTests");
    app.setApplicationDisplayName("Venor — labelled local protocol test");
    QTemporaryDir settings(QDir::currentPath() + "/ai-case-XXXXXX");
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settings.path());
    sample = QString::fromLocal8Bit(argv[1]);
    captures = qEnvironmentVariable("VENOR_QA_CAPTURES");
    AiGuiTests tests;
    auto arguments = app.arguments();
    arguments.removeAt(1);
    arguments << "-o" << "ai-gui-results.txt,txt";
    return QTest::qExec(&tests, arguments);
}
#include "ai_gui_tests.moc"
