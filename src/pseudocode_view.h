#pragma once
#include "decompiler.h"
#include <QtWidgets>
namespace vnr {
class PseudocodeEditor : public QPlainTextEdit {
    Q_OBJECT
  public:
    explicit PseudocodeEditor(QWidget *parent = nullptr);
    void setFunction(const DecompiledFunction &);
    void selectAddress(quint64 address);
    QJsonObject tokenAt(int position) const;
    const DecompiledFunction &function() const {
        return result;
    }
  signals:
    void sourceRequested(quint64 address, bool assembly);
    void editRequested(QString kind, QString variable);
    void referencesRequested();

  protected:
    void mouseReleaseEvent(QMouseEvent *) override;
    void contextMenuEvent(QContextMenuEvent *) override;

  private:
    DecompiledFunction result;
};
} // namespace vnr
