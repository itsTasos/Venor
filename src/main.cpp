#include "mainwindow.h"
#include <QtSql>
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/icons/venor.ico"));
    app.setOrganizationName("LocalAnalysis");
    app.setApplicationName(APP_TITLE);
    app.setApplicationVersion("0.1.0");
    QCommandLineParser p;
    p.setApplicationDescription("Native local Windows x64 investigation workstation");
    p.addHelpOption();
    p.addVersionOption();
    p.addOption({"check-runtime", "Check native Qt, embedded icon and SQLite runtime availability and exit"});
    p.addOption({"title", "Override the working application title", "title"});
    p.addPositionalArgument("file", "PE binary or .venor investigation");
    p.process(app);
    if (p.isSet("check-runtime")) {
        auto db = QSqlDatabase::addDatabase("QSQLITE", "runtime_check");
        db.setDatabaseName(":memory:");
        return db.open() && !app.windowIcon().isNull() &&
                       !app.windowIcon().pixmap(QSize(32, 32)).isNull()
                   ? 0
                   : 2;
    }
    if (p.isSet("title"))
        app.setApplicationDisplayName(p.value("title"));
    else
        app.setApplicationDisplayName(qEnvironmentVariable("VENOR_APP_TITLE", APP_TITLE));
    vnr::MainWindow window;
    window.show();
    if (!p.positionalArguments().isEmpty()) {
        auto file = p.positionalArguments().first();
        QTimer::singleShot(0, &window, [&window, file] {
            if (file.endsWith(".venor", Qt::CaseInsensitive))
                window.openInvestigation(file);
            else
                window.openBinary(file);
        });
    }
    return app.exec();
}
