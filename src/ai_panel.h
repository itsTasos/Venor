#pragma once
#include "ai.h"
#include <QtWidgets>

namespace vnr {
class AiPanel : public QWidget {
    Q_OBJECT
  public:
    explicit AiPanel(QWidget *parent = nullptr, AiService *service = nullptr);
    AiService *service() const {
        return ai;
    }
    std::function<AiContext(AiScope, bool)> contextBuilder;
    void settings();
    void requestExplanation(AiScope scope);
    void sourceChanged(QByteArray token);
  signals:
    void sourceRequested(quint64 address);
    void applyRequested(vnr::AiSuggestion suggestion);

  protected:
    void resizeEvent(QResizeEvent *event) override;

  private:
    AiService *ai;
    QComboBox *scopeBox, *suggestions;
    QPushButton *explainButton, *cancelButton, *applyButton;
    QLabel *statusLabel = nullptr, *sourceLabel = nullptr;
    QTextBrowser *text;
    AiExplanation result;
    QByteArray sourceToken;
    void showResult(AiExplanation answer);
};
} // namespace vnr
