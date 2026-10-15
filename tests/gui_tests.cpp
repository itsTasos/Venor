#include "mainwindow.h"
#include <QtTest>
using namespace vnr;
static QString sample;
static QString captures;
static void capture(QWidget &widget, const QString &name) {
    if (captures.isEmpty())
        return;
    QDir().mkpath(captures);
    QTest::qWait(50);
    widget.grab().save(captures + "/" + name + ".png");
}
class GuiTests : public QObject {
    Q_OBJECT
  private slots:
    void investigate() {
        QTemporaryDir temp(QDir::currentPath() + "/gui-case-XXXXXX");
        QSettings().clear();
        MainWindow w;
        w.show();
        QVERIFY(QTest::qWaitForWindowExposed(&w));
        capture(w, "welcome");
        QTimer::singleShot(80, &w, [] {
            auto *chooser = qobject_cast<QFileDialog *>(QApplication::activeModalWidget());
            QVERIFY(chooser);
            chooser->selectFile(sample);
            QMetaObject::invokeMethod(chooser, "accept", Qt::DirectConnection);
        });
        QTest::keyClick(&w, Qt::Key_O, Qt::ControlModifier);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.binary()), 20000);
        auto *code = w.findChild<QTableView *>("disassembly");
        QVERIFY(code);
        w.activateWindow();
        w.raise();
        code->setFocus();
        QTest::qWait(30);
        QVERIFY(code->model()->rowCount() > 0);
        w.navigate(w.binary()->entry);
        QVERIFY(w.findChild<QTextBrowser *>("explanation")->toPlainText().contains("What happens here"));
        QVERIFY(!w.findChild<QTextBrowser *>("explanation")->toPlainText().contains("Observed facts"));
        auto *details = w.findChild<QToolButton *>("instructionDetails");
        QTest::mouseClick(details, Qt::LeftButton);
        QVERIFY(w.findChild<QTextBrowser *>("explanation")->toPlainText().contains("Observed facts"));
        QTest::mouseClick(details, Qt::LeftButton);
        capture(w, "loaded-binary");
        for (auto *action : w.findChildren<QAction *>())
            if (action->text() == "Light theme") {
                action->setChecked(true);
                QVERIFY(qApp->palette().color(QPalette::Base).lightness() > 220);
                capture(w, "light-theme");
                action->setChecked(false);
                break;
            }
        auto *workspace = w.findChild<QComboBox *>("workspacePreset");
        QVERIFY(workspace);
        workspace->setCurrentText("Beginner");
        capture(w, "beginner-workspace");
        workspace->setCurrentText("Expert");
        capture(w, "expert-workspace");
        QVERIFY(w.findChild<QDockWidget *>("breakpointsDock")->isVisible());
        QVERIFY(w.findChild<QDockWidget *>("registers")->isVisible());
        QTRY_VERIFY(w.findChild<QDockWidget *>("breakpointsDock")->geometry().left() >
                    w.findChild<QDockWidget *>("registers")->geometry().left());
        workspace->setCurrentText("Analyst");
        auto *tabs = w.findChild<QTabWidget *>("codeTabs");
        tabs->setCurrentIndex(1);
        capture(w, "flow-graph");
        tabs->setCurrentIndex(2);
        capture(w, "readable-code");
        tabs->setCurrentIndex(0);
        auto normalSize = w.size();
        w.resize(std::min(1100, normalSize.width()), std::min(720, normalSize.height()));
        capture(w, "compact-layout");
        w.resize(normalSize);
        bool searched = false;
        QTimer searchTimer;
        searchTimer.setInterval(30);
        connect(&searchTimer, &QTimer::timeout, &w, [&] {
            auto *d = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (!d || d->windowTitle() != "Search binary")
                return;
            auto *input = d->findChild<QLineEdit *>();
            auto *results = d->findChild<QTableView *>();
            if (input->text().isEmpty()) {
                input->setText("investigation_marker");
                QTest::mouseClick(d->findChild<QPushButton *>(), Qt::LeftButton);
            }
            if (results->model()->rowCount() > 0) {
                searched = true;
                searchTimer.stop();
                d->accept();
            }
        });
        searchTimer.start();
        for (auto *a : w.findChildren<QAction *>())
            if (a->text() == "Search Binary…") {
                a->trigger();
                break;
            }
        QVERIFY(searched);
        w.activateWindow();
        w.raise();
        code->setFocus();
        QTest::qWait(30);
        QTest::keyClick(code, Qt::Key_F9);
        QCOMPARE(w.investigation().breakpoints.size(), 1);
        QVERIFY(w.investigation().breakpoints[0].expression.contains("+0x"));
        w.investigation().comments[w.binary()->entry] = "GUI investigation";
        w.investigation().notes = "Saved GUI note";
        QVERIFY(w.saveInvestigation(temp.filePath("gui.venor")));
        auto saved = loadWorkspace(temp.filePath("gui.venor"));
        QCOMPARE(saved.breakpoints.size(), 1);
        QCOMPARE(saved.comments[w.binary()->entry], QString("GUI investigation"));
        QVERIFY(!saved.layout.isEmpty());
        QTimer::singleShot(50, &w, [] {
            auto *d = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            QVERIFY(d);
            QVERIFY(d->findChild<QListWidget *>()->count() >= 20);
            capture(*d, "preset-browser");
            d->reject();
        });
        w.presets();
        w.close();
        MainWindow reopened;
        reopened.show();
        reopened.openInvestigation(temp.filePath("gui.venor"));
        QTRY_VERIFY_WITH_TIMEOUT(bool(reopened.binary()), 20000);
        QCOMPARE(reopened.investigation().comments[saved.selected], QString("GUI investigation"));
        QCOMPARE(reopened.investigation().breakpoints.size(), 1);
        QVERIFY(reopened.findChild<QPlainTextEdit *>("investigationNotes")
                    ->toPlainText()
                    .contains("Saved GUI note"));
        reopened.close();
    }
    void meaningNavigation() {
        QTemporaryDir temp(QDir::currentPath() + "/gui-case-XXXXXX");
        MainWindow w;
        w.show();
        w.openBinary(sample);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.binary()), 20000);
        auto image = w.binary();
        auto entry = std::find_if(image->exports.begin(), image->exports.end(),
                                  [](const Row &r) { return r.name == "meaning_allocation"; });
        QVERIFY(entry != image->exports.end());
        auto start = image->instructionIndex(entry->address);
        QVERIFY(start >= 0);
        auto document = analyzeMeaning(image->code.mid(start, 45), image.get());
        auto call = std::find_if(document.steps.begin(), document.steps.end(), [](const MeaningStep &s) {
            return s.call && s.title.contains("VirtualAlloc");
        });
        QVERIFY(call != document.steps.end());
        w.navigate(call->address);
        auto *explanation = w.findChild<QTextBrowser *>("explanation");
        auto *meaning = w.findChild<QTextBrowser *>("meaning");
        auto *tabs = w.findChild<QTabWidget *>("codeTabs");
        QCOMPARE(tabs->currentWidget(), meaning);
        QVERIFY(explanation->toPlainText().contains("4096 bytes"));
        QVERIFY(explanation->toPlainText().contains("MEM_RESERVE"));
        QVERIFY(explanation->toPlainText().contains("Execution and success are unobserved",
                                                    Qt::CaseInsensitive) ||
                explanation->toPlainText().contains("execution and success are unobserved"));
        QVERIFY(w.findChild<QLabel *>("sessionContext")->text().contains("static inspection"));
        QVERIFY(w.findChild<QDockWidget *>("registers")->height() < w.height() * 0.32);
        capture(w, "meaning-api-request");
        auto unit = document.units[document.unitAt[call->address]];
        auto selected = document.steps[unit.steps.first()].address;
        QMetaObject::invokeMethod(meaning, "anchorClicked", Qt::DirectConnection,
                                  Q_ARG(QUrl, QUrl("unit:" + QString::number(selected, 16))));
        QCOMPARE(w.investigation().selected, selected);
        auto *assembly = w.findChild<QTableView *>("disassembly");
        QCOMPARE(assembly->currentIndex().data(Qt::UserRole).toULongLong(), selected);
        QVERIFY(meaning->toPlainText().contains("Selected ·"));
        tabs->setCurrentIndex(1);
        auto *flow = w.findChild<QGraphicsView *>("flowGraph");
        bool highlighted = false;
        for (auto *item : flow->scene()->items())
            highlighted |= item->data(1).toBool();
        QVERIFY(highlighted);
        capture(w, "meaning-synchronized-flow");
        for (auto *item : flow->scene()->items())
            if (item->data(1).toBool()) {
                auto blockAddress = item->data(0).toULongLong();
                flow->centerOn(item);
                QTest::mouseDClick(flow->viewport(), Qt::LeftButton, Qt::NoModifier,
                                   flow->mapFromScene(item->sceneBoundingRect().center()));
                QTRY_COMPARE(w.investigation().selected, blockAddress);
                QCOMPARE(tabs->currentWidget(), flow);
                break;
            }
        QMetaObject::invokeMethod(explanation, "anchorClicked", Qt::DirectConnection,
                                  Q_ARG(QUrl, QUrl("assembly:" + QString::number(call->address, 16))));
        QCOMPARE(tabs->currentWidget(), assembly);
        QCOMPARE(w.investigation().selected, call->address);
        w.navigate(image->code[std::min(start + 150, int(image->code.size()) - 1)].address);
        QVERIFY(meaning->toHtml().contains(QString::number(w.investigation().selected, 16)));
        QVERIFY(w.saveInvestigation(temp.filePath("meaning.venor")));
        w.close();
    }
    void realDebugJourney() {
        QTemporaryDir temp(QDir::currentPath() + "/gui-debug-XXXXXX");
        MainWindow w;
        w.show();
        w.openBinary(sample);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.binary()), 20000);
        QTimer::singleShot(60, &w, [] {
            auto *d = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            QVERIFY(d);
            auto *filter = d->findChild<QLineEdit *>();
            filter->setText("VirtualAlloc");
            auto *list = d->findChild<QListWidget *>();
            QVERIFY(list->count() == 1);
            QTest::mouseClick(d->findChild<QPushButton *>(), Qt::LeftButton);
        });
        w.presets();
        QCOMPARE(w.investigation().breakpoints.size(), 1);
        QTimer::singleShot(60, &w, [] {
            auto *d = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            QVERIFY(d);
            auto *consent = d->findChild<QCheckBox *>();
            QTest::mouseClick(consent, Qt::LeftButton, Qt::NoModifier, QPoint(8, consent->height() / 2));
            QVERIFY(consent->isChecked());
            auto *buttons = d->findChild<QDialogButtonBox *>();
            QTest::mouseClick(buttons->button(QDialogButtonBox::Ok), Qt::LeftButton);
        });
        QSignalSpy stops(w.engine(), &Debugger::stopped);
        auto *launchButton = static_cast<QToolButton *>(nullptr);
        for (auto *button : w.findChildren<QToolButton *>())
            if (button->defaultAction() && button->defaultAction()->text() == "Start Target…")
                launchButton = button;
        QVERIFY(launchButton);
        QTest::mouseClick(launchButton, Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        auto *continueButton = static_cast<QToolButton *>(nullptr);
        for (auto *button : w.findChildren<QToolButton *>())
            if (button->defaultAction() && button->defaultAction()->text() == "Continue")
                continueButton = button;
        QVERIFY(continueButton);
        w.activateWindow();
        w.raise();
        QTRY_VERIFY(continueButton->isEnabled());
        QTest::qWait(30);
        QTest::mouseClick(continueButton, Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 2, 15000);
        auto hit = qvariant_cast<Snapshot>(stops.last()[0]);
        QVERIFY(hit.reason.contains("VirtualAlloc"));
        QVERIFY(w.findChild<QLabel *>("sessionContext")->text().contains("Why stopped"));
        QTRY_VERIFY_WITH_TIMEOUT(
            w.findChild<QTextBrowser *>("explanation")->toPlainText().contains("MEM_COMMIT"), 5000);
        QVERIFY(w.findChild<QTextBrowser *>("explanation")->toPlainText().contains("Recorded API entry"));
        capture(w, "paused-api-breakpoint");
        auto *bpDock = w.findChild<QDockWidget *>("breakpointsDock");
        bpDock->raise();
        capture(w, "breakpoints");
        w.engine()->command("detach");
        QTRY_VERIFY_WITH_TIMEOUT(!w.engine()->isRunning(), 10000);
        QVERIFY(w.saveInvestigation(temp.filePath("runtime.venor")));
        auto evidence = loadWorkspace(temp.filePath("runtime.venor"));
        QVERIFY(!evidence.events.isEmpty());
        bool savedBytes = false;
        for (auto &e : evidence.events)
            if (e.type == "Breakpoint hit") {
                QVERIFY(e.ip);
                QVERIFY(!e.code.isEmpty());
                savedBytes = true;
            }
        QVERIFY(savedBytes);
        w.close();
        MainWindow reopened;
        reopened.show();
        reopened.openInvestigation(temp.filePath("runtime.venor"));
        QTRY_VERIFY_WITH_TIMEOUT(bool(reopened.binary()), 20000);
        auto *timeline = reopened.findChild<QTableView *>("timeline");
        int hitRow = -1;
        for (int n = 0; n < reopened.investigation().events.size(); n++)
            if (reopened.investigation().events[n].type == "Breakpoint hit")
                hitRow = n;
        QVERIFY(hitRow >= 0);
        timeline->setCurrentIndex(timeline->model()->index(hitRow, 0));
        auto *detail = reopened.findChild<QTextBrowser *>("eventDetail");
        QVERIFY(detail->toPlainText().contains("Open captured instruction bytes"));
        QMetaObject::invokeMethod(detail, "anchorClicked", Qt::DirectConnection,
                                  Q_ARG(QUrl, QUrl("evidence:code")));
        QVERIFY(
            reopened.findChild<QTextBrowser *>("explanation")->toPlainText().contains("historical snapshot"));
        QVERIFY(reopened.findChild<QLabel *>("sessionState")->text().contains("SAVED EVIDENCE"));
        QVERIFY(reopened.findChild<QTextBrowser *>("explanation")->toPlainText().contains("MEM_COMMIT"));
        capture(reopened, "reopened-evidence");
        QVERIFY(reopened.saveInvestigation(temp.filePath("runtime.venor")));
        auto capturedOnly = loadWorkspace(temp.filePath("runtime.venor"));
        capturedOnly.binary.clear();
        capturedOnly.hash.clear();
        saveWorkspace(temp.filePath("captured-only.venor"), capturedOnly);
        reopened.close();
        MainWindow detachedEvidence;
        detachedEvidence.show();
        detachedEvidence.openInvestigation(temp.filePath("captured-only.venor"));
        QVERIFY(!detachedEvidence.binary());
        QCOMPARE(detachedEvidence.investigation().events.size(), capturedOnly.events.size());
        auto *savedTimeline = detachedEvidence.findChild<QTableView *>("timeline");
        savedTimeline->setCurrentIndex(savedTimeline->model()->index(hitRow, 0));
        QMetaObject::invokeMethod(detachedEvidence.findChild<QTextBrowser *>("eventDetail"), "anchorClicked",
                                  Qt::DirectConnection, Q_ARG(QUrl, QUrl("evidence:code")));
        QVERIFY(detachedEvidence.findChild<QTextBrowser *>("explanation")
                    ->toPlainText()
                    .contains("historical snapshot"));
        QVERIFY(detachedEvidence.saveInvestigation(temp.filePath("captured-only.venor")));
        detachedEvidence.close();
    }
    void recoverFromInvalidFile() {
        QTemporaryDir temp(QDir::currentPath() + "/gui-error-XXXXXX");
        QFile bad(temp.filePath("bad.exe"));
        QVERIFY(bad.open(QIODevice::WriteOnly));
        bad.write("not a PE");
        bad.close();
        MainWindow w;
        w.show();
        w.openBinary(bad.fileName());
        QVERIFY(!w.findChild<QPlainTextEdit *>("investigationNotes")->isEnabled());
        bool seen = false;
        QTimer dismiss;
        dismiss.setInterval(30);
        connect(&dismiss, &QTimer::timeout, &w, [&] {
            if (auto *message = qobject_cast<QMessageBox *>(QApplication::activeModalWidget())) {
                seen = message->text().contains("Truncated");
                capture(*message, "invalid-file-error");
                message->accept();
                dismiss.stop();
            }
        });
        dismiss.start();
        QTRY_VERIFY_WITH_TIMEOUT(seen, 10000);
        QVERIFY(!w.binary());
        w.openBinary(sample);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.binary()), 20000);
        QVERIFY(w.findChild<QPlainTextEdit *>("investigationNotes")->isEnabled());
        QVERIFY(w.saveInvestigation(temp.filePath("recovered.venor")));
        w.close();
    }
};
int main(int argc, char **argv) {
    QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
    QApplication app(argc, argv);
    app.setOrganizationName("VenorTests");
    app.setApplicationName("GuiTests");
    app.setApplicationDisplayName(APP_TITLE);
    sample = QString::fromLocal8Bit(argv[1]);
    captures = qEnvironmentVariable("VENOR_QA_CAPTURES");
    GuiTests t;
    return QTest::qExec(&t, QStringList{"gui_tests", "-o", "gui-results.txt,txt"});
}
#include "gui_tests.moc"
