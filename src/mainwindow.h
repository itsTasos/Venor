#pragma once
#include "ai_panel.h"
#include "debugger.h"
#include "pseudocode_view.h"
#include "semantics.h"
#include <QtConcurrent>
#include <QtWidgets>
#include <optional>
namespace vnr {
class InstructionModel : public QAbstractTableModel {
  public:
    QVector<Instruction> code;
    Workspace *workspace = nullptr;
    quint64 ip = 0;
    int fontPointSize = 10;
    explicit InstructionModel(QObject *p = nullptr) : QAbstractTableModel(p) {}
    int rowCount(const QModelIndex & = {}) const override {
        return int(code.size());
    }
    int columnCount(const QModelIndex & = {}) const override {
        return 5;
    }
    QVariant headerData(int s, Qt::Orientation o, int role) const override;
    QVariant data(const QModelIndex &, int) const override;
    void reset(QVector<Instruction> data) {
        beginResetModel();
        code = std::move(data);
        endResetModel();
    }
};
class RowModel : public QAbstractTableModel {
  public:
    QVector<Row> rows;
    QStringList headers{"Address", "Name / value", "Details"};
    explicit RowModel(QObject *p = nullptr) : QAbstractTableModel(p) {}
    int rowCount(const QModelIndex & = {}) const override {
        return int(rows.size());
    }
    int columnCount(const QModelIndex & = {}) const override {
        return 3;
    }
    QVariant headerData(int s, Qt::Orientation o, int role) const override {
        return role == Qt::DisplayRole && o == Qt::Horizontal ? headers.value(s) : QVariant();
    }
    QVariant data(const QModelIndex &i, int role) const override;
    void reset(QVector<Row> r) {
        beginResetModel();
        rows = std::move(r);
        endResetModel();
    }
};
class MainWindow : public QMainWindow {
    Q_OBJECT
  public:
    explicit MainWindow(AiService *ai = nullptr);
    void openBinary(const QString &path, bool restoring = false);
    void openInvestigation(const QString &path);
    bool saveInvestigation(QString path = {});
    void navigate(quint64, bool history = true);
    std::shared_ptr<Binary> binary() const {
        return image;
    }
    Workspace &investigation() {
        return work;
    }
    Debugger *engine() {
        return &debugger;
    }
    void presets();
    void editBreakpoint(int index = -1);

  protected:
    void closeEvent(QCloseEvent *) override;
    void dragEnterEvent(QDragEnterEvent *) override;
    void dropEvent(QDropEvent *) override;
    void resizeEvent(QResizeEvent *) override;
    bool eventFilter(QObject *, QEvent *) override;

  private:
    Workspace work;
    QString workspacePath;
    bool dirty = false, loading = false, restoring = false;
    std::optional<Workspace> pendingWorkspace;
    QString pendingWorkspacePath;
    QByteArray baselineLayout;
    std::shared_ptr<Binary> image;
    std::shared_ptr<std::atomic_bool> cancel;
    QFutureWatcher<std::shared_ptr<Binary>> watcher;
    Debugger debugger;
    Snapshot live;
    bool liveCode = false;
    bool evidenceCode = false;
    std::optional<Event> displayedEvidence;
    MeaningDocument meaning;
    QByteArray meaningKey;
    bool technicalExpanded = false;
    QVector<quint64> history;
    int historyIndex = -1;
    QStackedWidget *pages;
    QTabWidget *center = nullptr;
    QTableView *codeView = nullptr, *navView, *bpView, *timelineView;
    InstructionModel *codeModel;
    RowModel *navModel, *regModel, *stackModel, *frameModel, *threadModel, *moduleModel;
    QStandardItemModel *bpModel, *timelineModel;
    QSortFilterProxyModel *navProxy;
    QComboBox *navKind, *workspaceCombo;
    QLineEdit *navFilter, *location;
    QTextBrowser *inspector, *readable, *eventDetail;
    QPlainTextEdit *output, *notes, *hexView;
    QGraphicsScene *flowScene, *eventScene;
    QGraphicsView *flowView, *eventView;
    QLabel *stateLabel, *fileLabel, *sessionInfo;
    QToolButton *technicalToggle;
    QProgressBar *progress;
    QToolButton *cancelButton;
    QAction *launchAction, *attachAction, *runAction, *pauseAction, *intoAction, *overAction, *outAction,
        *detachAction, *cancelAction;
    QList<QDockWidget *> docks;
    QDockWidget *exploreDock, *contextDock, *registerDock, *stackDock, *framesDock, *breakpointsDock,
        *threadsDock, *timelineDock, *modulesDock, *outputDock;
    QMenu *recentMenu;
    AiPanel *aiPanel = nullptr;
    AiService *providedAiService = nullptr;
    QDockWidget *aiDock = nullptr;
    DecompilerService *decompiler = nullptr;
    PseudocodeEditor *pseudocode = nullptr;
    QLabel *decompilerStatus = nullptr, *functionSummary = nullptr;
    QComboBox *functionPicker = nullptr;
    QTableView *splitAssembly = nullptr;
    QTimer decompilerNavigation;
    std::optional<DecompiledFunction> decompiled;
    std::optional<QJsonObject> pendingDecompilerEdit;
    QByteArray requestedDecompilation;
    bool compactDecompilerLayout = false;
    void setDebuggerPanesVisible(bool visible);
    void setupDecompiler(QMenu *investigate, QMenu *settings);
    void openDecompiler();
    void configureDecompiler();
    void requestDecompilation(bool force = false);
    void updateDecompilerSelection();
    void editDecompiled(QString kind, QString variable = {});
    void decompilerReferences();
    QJsonArray analysisEdits() const;
    std::optional<quint64> staticSelection(QString *reason = nullptr) const;
    QListWidget *recents;
    bool confirmDiscard();
    void changed();
    void error(QString);
    void chooseBinary();
    void chooseInvestigation();
    void launch();
    void attach();
    void refreshNavigation();
    void refreshBreakpoints();
    void refreshTimeline();
    void selectInstruction(const QModelIndex &);
    void explain(const Instruction &);
    void contextLink(const QUrl &);
    void updateSessionInfo();
    void graph(const QVector<Instruction> &);
    QVector<Instruction> selectedFunction() const;
    void snapshot(Snapshot);
    void debuggerState(Debugger::State, QString);
    void syncPolicies();
    void search();
    void commandPalette();
    void goExpression(QString);
    quint64 relocateStatic(quint64) const;
    void annotate(QString);
    void follow();
    void xrefs();
    void presetLayout(QString);
    void theme(bool);
    void updateRecents(QString path = {});
    void eventSelection(const QModelIndex &);
    void setupAi(QMenu *investigate, QMenu *settings);
    AiContext aiContext(AiScope scope, bool runtime) const;
    QByteArray aiSourceIdentity() const;
    QDockWidget *dock(QString, QString, QWidget *, Qt::DockWidgetArea);
    QTableView *table(QAbstractItemModel *);
};
} // namespace vnr
