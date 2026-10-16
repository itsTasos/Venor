#include "ai_test_support.h"
#include "mainwindow.h"
#include <QtTest>
using namespace vnr;
static QString sample, captures;
static void capture(QWidget &widget, QString name) {
    if (captures.isEmpty())
        return;
    QDir().mkpath(captures);
    QTest::qWait(100);
    widget.grab().save(captures + '/' + name + ".png");
}
class DecompilerGuiTests : public QObject {
    Q_OBJECT
  private slots:
    void realInvestigationJourney() {
        if (qEnvironmentVariableIsEmpty("VENOR_GHIDRA_HOME"))
            QSKIP("Opt-in real Ghidra/native debugger GUI workflow");
        QTemporaryDir directory(QDir::currentPath() + "/decompiler-case-XXXXXX");
        FixtureNetwork network;
        QJsonObject submitted;
        network.handler = [&](const SentRequest &request) -> HttpFixture {
            if (request.request.url().path().endsWith("/models"))
                return {200,
                        jsonBytes({{"data", QJsonArray{QJsonObject{{"id", "labelled-protocol-fixture"}}}}})};
            auto payload = QJsonDocument::fromJson(request.body).object();
            auto messages = payload["messages"].toArray();
            submitted =
                QJsonDocument::fromJson(messages[1].toObject()["content"].toString().toUtf8()).object();
            auto text = "PROTOCOL FIXTURE: supplied real Ghidra reconstruction at [" +
                        submitted["selection"].toString() + "]. No model interpretation was performed.";
            return {200, localStream(text)};
        };
        ChatGptAuth auth(nullptr, directory.filePath("credentials"));
        AiService ai(nullptr, &auth, &network);
        MainWindow window(&ai);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        ai.configure(AiProviderKind::Local, QUrl("http://127.0.0.1:1234/v1"));
        QSignalSpy models(&ai, &AiService::modelsReady);
        ai.fetchModels();
        QTRY_COMPARE(models.size(), 1);
        ai.setModel("labelled-protocol-fixture");
        QTimer::singleShot(350, &window, [] {
            auto *chooser = qobject_cast<QFileDialog *>(QApplication::activeModalWidget());
            QVERIFY(chooser);
            auto *filename = chooser->findChild<QLineEdit *>("fileNameEdit");
            QVERIFY(filename);
            QVERIFY2(QFileInfo(sample).isFile(), qPrintable(sample));
            filename->setText(QDir::toNativeSeparators(sample));
            QMetaObject::invokeMethod(chooser, "accept", Qt::DirectConnection);
        });
        QTimer::singleShot(5000, &window, [] {
            if (auto *chooser = qobject_cast<QFileDialog *>(QApplication::activeModalWidget())) {
                qWarning() << "File chooser did not accept" << sample << chooser->selectedFiles();
                chooser->reject();
            }
        });
        QTest::keyClick(&window, Qt::Key_O, Qt::ControlModifier);
        QTRY_VERIFY_WITH_TIMEOUT(bool(window.binary()), 20000);
        auto *backend = window.findChild<DecompilerService *>();
        QVERIFY(backend);
        QTRY_VERIFY_WITH_TIMEOUT(backend->ready() || !backend->lastError().isEmpty(), 300000);
        QVERIFY2(backend->ready(), qPrintable(backend->lastError()));
        auto *picker = window.findChild<QComboBox *>("recoveredFunctions");
        auto *editor = window.findChild<PseudocodeEditor *>("pseudocode");
        auto *tabs = window.findChild<QTabWidget *>("codeTabs");
        auto *page = window.findChild<QWidget *>("decompiledPage");
        QVERIFY(picker);
        QVERIFY(editor);
        quint64 function = 0;
        for (const auto &r : window.binary()->exports)
            if (r.name == "inspect_record")
                function = r.address;
        QVERIFY(function);
        int index = picker->findData(QVariant::fromValue(function));
        QVERIFY(index >= 0);
        tabs->setCurrentWidget(page);
        picker->setCurrentIndex(index);
        QMetaObject::invokeMethod(picker, "activated", Q_ARG(int, index));
        QTRY_COMPARE_WITH_TIMEOUT(editor->function().entry, function, 120000);
        QVERIFY(editor->toPlainText().contains("if"));
        QTRY_VERIFY(editor->viewport()->height() > 140);
        auto *debugPanesButton = window.findChild<QPushButton *>("toggleDebuggerPanes");
        QVERIFY(debugPanesButton);
        QTest::mouseClick(debugPanesButton, Qt::LeftButton);
        QVERIFY(!window.findChild<QDockWidget *>("registers")->isHidden());
        QTest::mouseClick(debugPanesButton, Qt::LeftButton);
        QVERIFY(window.findChild<QDockWidget *>("registers")->isHidden());
        auto *split = window.findChild<QCheckBox *>("splitPseudocode");
        QTest::mouseClick(split, Qt::LeftButton);
        QVERIFY(window.findChild<QTableView *>("pseudocodeAssembly")->isVisible());
        auto *sideAssembly = window.findChild<QTableView *>("pseudocodeAssembly");
        QTRY_VERIFY(sideAssembly->viewport()->rect().intersects(
            sideAssembly->visualRect(sideAssembly->currentIndex().siblingAtColumn(1))));
        capture(window, "real-decompiled-function");
        QJsonObject mapped;
        for (auto value : editor->function().data["tokens"].toArray()) {
            auto t = value.toObject();
            if (!t["address"].toString().isEmpty() && t["length"].toInt() > 0) {
                mapped = t;
                break;
            }
        }
        QVERIFY(!mapped.isEmpty());
        auto cursor = editor->textCursor();
        cursor.setPosition(mapped["start"].toInt());
        editor->setTextCursor(cursor);
        editor->ensureCursorVisible();
        auto target = mapped["address"].toString().mid(2).toULongLong(nullptr, 16);
        QTest::mouseClick(editor->viewport(), Qt::LeftButton, Qt::ControlModifier,
                          editor->cursorRect(cursor).center());
        QCOMPARE(window.investigation().selected, target);
        QCOMPARE(tabs->currentIndex(), 0);
        tabs->setCurrentIndex(1);
        capture(window, "recovered-flow-graph");
        QVERIFY(!window.findChild<QGraphicsView *>("flowGraph")->scene()->items().isEmpty());
        tabs->setCurrentWidget(page);
        QTimer::singleShot(80, &window, [] {
            auto *dialog = qobject_cast<QInputDialog *>(QApplication::activeModalWidget());
            QVERIFY(dialog);
            dialog->setTextValue("reviewed_record");
            dialog->accept();
        });
        for (auto *a : window.findChildren<QAction *>())
            if (a->text() == "Rename function…") {
                a->trigger();
                break;
            }
        QTRY_VERIFY_WITH_TIMEOUT(editor->toPlainText().contains("reviewed_record"), 120000);
        QCOMPARE(window.investigation().renames.value(function), QString("reviewed_record"));
        QSignalSpy explanation(&ai, &AiService::completed);
        QTimer::singleShot(80, &window, [] {
            auto *dialog = QApplication::activeModalWidget();
            QVERIFY(dialog);
            QCOMPARE(dialog->objectName(), QString("aiConsentDialog"));
            auto *preview = dialog->findChild<QPlainTextEdit *>("aiContextPreview");
            QVERIFY(preview->toPlainText().contains("Ghidra"));
            auto *buttons = dialog->findChild<QDialogButtonBox *>();
            QTest::mouseClick(buttons->button(QDialogButtonBox::Ok), Qt::LeftButton);
        });
        window.findChild<AiPanel *>()->requestExplanation(AiScope::Function);
        QTRY_COMPARE(explanation.size(), 1);
        QVERIFY(submitted["decompilation"].toObject()["pseudocode"].toString().contains("reviewed_record"));
        QVERIFY(!submitted.contains("observed_snapshot"));
        QVERIFY(qvariant_cast<AiExplanation>(explanation.first().first()).verifiedReferences > 0);
        window.findChild<QDockWidget *>("aiExplanationDock")->show();
        window.findChild<QDockWidget *>("aiExplanationDock")->raise();
        capture(window, "grounded-context-protocol-fixture");
        // Existing execution controls and breakpoint workflow, now linked to the recovered function.
        window.navigate(function);
        tabs->setCurrentIndex(0);
        auto *assembly = window.findChild<QTableView *>("disassembly");
        assembly->setFocus();
        QTest::keyClick(assembly, Qt::Key_F9);
        QCOMPARE(window.investigation().breakpoints.size(), 1);
        QVERIFY(window.investigation().breakpoints.first().expression.endsWith(
            "+0x" + QString::number(function - window.binary()->base, 16)));
        QTimer::singleShot(80, &window, [] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            QVERIFY(dialog);
            auto *consent = dialog->findChild<QCheckBox *>();
            QTest::mouseClick(consent, Qt::LeftButton, Qt::NoModifier, QPoint(8, consent->height() / 2));
            QTest::mouseClick(dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok),
                              Qt::LeftButton);
        });
        QSignalSpy stops(window.engine(), &Debugger::stopped);
        for (auto *a : window.findChildren<QAction *>())
            if (a->text() == "Start Target…") {
                a->trigger();
                break;
            }
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        QAction *continueAction = nullptr;
        for (auto *a : window.findChildren<QAction *>())
            if (a->text() == "Continue")
                continueAction = a;
        QVERIFY(continueAction);
        QTRY_VERIFY_WITH_TIMEOUT(continueAction->isEnabled(), 10000);
        continueAction->trigger();
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 2, 20000);
        auto snapshot = qvariant_cast<Snapshot>(stops.last().first());
        auto preferred = preferredAddress(*window.binary(), snapshot.ip, true, snapshot.modules);
        QVERIFY(preferred);
        QCOMPARE(*preferred, function);
        tabs->setCurrentWidget(page);
        QElapsedTimer waitForRuntime;
        waitForRuntime.start();
        while (
            !window.findChild<QLabel *>("decompilerStatus")->text().contains("captured live bytes match") &&
            waitForRuntime.elapsed() < 20000)
            QTest::qWait(30);
        capture(window, "paused-function-and-pseudocode");
        QVERIFY2(window.findChild<QLabel *>("decompilerStatus")->text().contains("captured live bytes match"),
                 qPrintable(window.findChild<QLabel *>("decompilerStatus")->text()));
        window.engine()->command("detach");
        QTRY_VERIFY_WITH_TIMEOUT(!window.engine()->isRunning(), 10000);
        window.navigate(function);
        QVERIFY(window.saveInvestigation(directory.filePath("recovered.venor")));
        window.close();
        backend->close();
        MainWindow reopened;
        reopened.show();
        reopened.openInvestigation(directory.filePath("recovered.venor"));
        QTRY_VERIFY_WITH_TIMEOUT(bool(reopened.binary()), 20000);
        auto *restored = reopened.findChild<PseudocodeEditor *>("pseudocode");
        QTRY_VERIFY_WITH_TIMEOUT(restored->toPlainText().contains("reviewed_record"), 120000);
        QCOMPARE(reopened.investigation().renames.value(function), QString("reviewed_record"));
        QVERIFY(!reopened.investigation().decompilerEdits.isEmpty());
        auto *restoredAssembly = reopened.findChild<QTableView *>("pseudocodeAssembly");
        QTRY_VERIFY(restoredAssembly->viewport()->rect().intersects(
            restoredAssembly->visualRect(restoredAssembly->currentIndex().siblingAtColumn(1))));
        capture(reopened, "reopened-investigation");
        QVERIFY(reopened.saveInvestigation(directory.filePath("recovered.venor")));
        reopened.close();
    }
};
int main(int argc, char **argv) {
    QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
    QApplication app(argc, argv);
    app.setOrganizationName("VenorTests");
    app.setApplicationName("DecompilerGui");
    app.setApplicationDisplayName("Venor — real Ghidra verification");
    QTemporaryDir settings(QDir::currentPath() + "/decompiler-case-XXXXXX");
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settings.path());
    if (argc < 2)
        return 2;
    sample = argv[1];
    captures = qEnvironmentVariable("VENOR_QA_CAPTURES");
    DecompilerGuiTests tests;
    return QTest::qExec(&tests, QStringList{argv[0], "-o", "decompiler-gui-results.txt,txt"});
}
#include "decompiler_gui_tests.moc"
