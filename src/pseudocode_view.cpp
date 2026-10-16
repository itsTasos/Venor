#include "pseudocode_view.h"
namespace vnr {
namespace {
class CLikeHighlighter : public QSyntaxHighlighter {
  public:
    explicit CLikeHighlighter(QTextDocument *doc) : QSyntaxHighlighter(doc) {}
    void highlightBlock(const QString &text) override {
        auto apply = [&](QString expression, QColor color, bool bold = false) {
            auto matches = QRegularExpression(expression).globalMatch(text);
            while (matches.hasNext()) {
                auto m = matches.next();
                QTextCharFormat f;
                f.setForeground(color);
                if (bold)
                    f.setFontWeight(QFont::DemiBold);
                setFormat(m.capturedStart(), m.capturedLength(), f);
            }
        };
        bool dark = qApp->palette().color(QPalette::Base).lightness() < 128;
        apply("\\b(if|else|while|do|for|switch|case|default|break|continue|return|goto|sizeof)\\b",
              dark ? QColor("#c69bea") : QColor("#713395"), true);
        apply("\\b(void|char|short|int|long|float|double|bool|const|unsigned|signed|struct|undefined[1248]?|"
              "u?int[0-9]+_t)\\b",
              dark ? QColor("#70c6bb") : QColor("#126758"));
        apply("\\b(0x[0-9a-fA-F]+|[0-9]+)\\b", dark ? QColor("#d8b77d") : QColor("#875a18"));
        apply("\"([^\"\\\\]|\\\\.)*\"", dark ? QColor("#a9c98e") : QColor("#3d6e23"));
        apply("//[^\\n]*|/\\*.*?\\*/", dark ? QColor("#87949e") : QColor("#5a6871"));
        setCurrentBlockState(0);
        int first = previousBlockState() == 1 ? 0 : text.indexOf("/*");
        while (first >= 0) {
            int end = text.indexOf("*/", first + (previousBlockState() == 1 && first == 0 ? 0 : 2));
            QTextCharFormat f;
            f.setForeground(dark ? QColor("#87949e") : QColor("#5a6871"));
            setFormat(first, end < 0 ? text.size() - first : end + 2 - first, f);
            if (end < 0) {
                setCurrentBlockState(1);
                break;
            }
            first = text.indexOf("/*", end + 2);
        }
    }
};
quint64 va(const QJsonValue &v) {
    return v.toString().mid(2).toULongLong(nullptr, 16);
}
} // namespace
PseudocodeEditor::PseudocodeEditor(QWidget *parent) : QPlainTextEdit(parent) {
    setObjectName("pseudocode");
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    QFont font("Cascadia Mono", 11);
    font.setStyleHint(QFont::Monospace);
    setFont(font);
    setTabStopDistance(QFontMetricsF(font).horizontalAdvance(' ') * 4);
    new CLikeHighlighter(document());
    setToolTip("Ghidra reconstructed C-like code, not the original source. Ctrl+click follows a referenced "
               "function or its mapped assembly. Right-click for names, types and references.");
}
void PseudocodeEditor::setFunction(const DecompiledFunction &f) {
    result = f;
    setPlainText(f.code);
    setExtraSelections({});
}
QJsonObject PseudocodeEditor::tokenAt(int position) const {
    for (auto value : result.data["tokens"].toArray()) {
        auto t = value.toObject();
        int start = t["start"].toInt(), length = t["length"].toInt();
        if (position >= start && position < start + length)
            return t;
    }
    return {};
}
void PseudocodeEditor::selectAddress(quint64 address) {
    QList<QTextEdit::ExtraSelection> selections;
    int first = -1;
    for (auto value : result.data["tokens"].toArray()) {
        auto t = value.toObject();
        if (va(t["address"]) != address)
            continue;
        QTextEdit::ExtraSelection s;
        s.cursor = QTextCursor(document());
        s.cursor.setPosition(t["start"].toInt());
        s.cursor.movePosition(QTextCursor::NextCharacter, QTextCursor::KeepAnchor, t["length"].toInt());
        s.format.setBackground(qApp->palette().color(QPalette::Highlight));
        s.format.setForeground(qApp->palette().color(QPalette::HighlightedText));
        selections << s;
        if (first < 0)
            first = t["start"].toInt();
    }
    setExtraSelections(selections);
    if (first >= 0) {
        auto c = textCursor();
        c.setPosition(first);
        setTextCursor(c);
        ensureCursorVisible();
    }
}
void PseudocodeEditor::mouseReleaseEvent(QMouseEvent *event) {
    QPlainTextEdit::mouseReleaseEvent(event);
    if (event->button() != Qt::LeftButton)
        return;
    auto t = tokenAt(cursorForPosition(event->pos()).position());
    bool follow = event->modifiers().testFlag(Qt::ControlModifier);
    quint64 target = follow ? va(t["target"]) : 0;
    if (!target)
        target = va(t["address"]);
    if (target)
        emit sourceRequested(target, follow && !va(t["target"]));
}
void PseudocodeEditor::contextMenuEvent(QContextMenuEvent *event) {
    auto c = cursorForPosition(event->pos());
    c.select(QTextCursor::WordUnderCursor);
    setTextCursor(c);
    auto token = tokenAt(c.selectionStart());
    auto *menu = createStandardContextMenu();
    menu->addSeparator();
    auto *source = menu->addAction("Go to mapped assembly");
    source->setEnabled(va(token["address"]) != 0);
    connect(source, &QAction::triggered, this,
            [=, this] { emit sourceRequested(va(token["address"]), true); });
    auto *target = menu->addAction("Follow referenced function");
    target->setEnabled(va(token["target"]) != 0);
    connect(target, &QAction::triggered, this,
            [=, this] { emit sourceRequested(va(token["target"]), false); });
    for (auto pair : {qMakePair(QString("Rename function…"), QString("function_name")),
                      qMakePair(QString("Edit C signature…"), QString("signature")),
                      qMakePair(QString("Rename variable…"), QString("variable_name")),
                      qMakePair(QString("Edit variable type…"), QString("variable_type"))}) {
        auto *a = menu->addAction(pair.first);
        bool variable = pair.second.startsWith("variable_");
        bool found = !variable;
        for (auto v : result.data["variables"].toArray())
            if (v.toObject()["name"].toString() == c.selectedText())
                found = true;
        a->setEnabled(found && result.entry);
        connect(a, &QAction::triggered, this,
                [=, this] { emit editRequested(pair.second, c.selectedText()); });
    }
    connect(menu->addAction("Function cross-references…"), &QAction::triggered, this,
            &PseudocodeEditor::referencesRequested);
    menu->exec(event->globalPos());
    delete menu;
}
} // namespace vnr
