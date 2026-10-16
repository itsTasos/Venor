#pragma once
#include "ai_auth.h"
#include "types.h"

namespace vnr {
enum class AiProviderKind { Disabled, ChatGpt, Local };
enum class AiScope { Instruction, Block, Function };
struct AiContext {
    QJsonObject data;
    QSet<quint64> addresses, functionStarts;
    QByteArray serialized() const {
        return QJsonDocument(data).toJson(QJsonDocument::Indented);
    }
    QByteArray key() const;
};
AiContext makeAiContext(const Binary *binary, QVector<Instruction> window, quint64 selection, AiScope scope,
                        QString provenance, const Snapshot *snapshot = nullptr, const Event *event = nullptr);
struct AiSuggestion {
    QString kind, text, variable;
    quint64 address = 0;
};
struct AiExplanation {
    QString text, provider, model;
    AiContext context;
    QVector<AiSuggestion> suggestions;
    int verifiedReferences = 0, invalidReferences = 0, rejectedSuggestions = 0;
    bool cached = false;
};
AiExplanation validateAiExplanation(QString text, const AiContext &context);
QString visibleAiText(QString text);
QString aiExplanationHtml(const AiExplanation &answer);

// SSE framing is independent of either provider's JSON dialect.
class SseDecoder {
  public:
    QVector<QByteArray> feed(QByteArray bytes);
    bool cleanEnd() const {
        return buffer.trimmed().isEmpty() && data.isEmpty();
    }

  private:
    QByteArray buffer, data;
    qint64 received = 0;
};
struct AiModel {
    QString id, name;
};
class AiProvider {
  public:
    virtual ~AiProvider() = default;
    virtual QString label() const = 0;
    virtual QUrl baseUrl() const = 0;
    virtual QString inferencePath() const = 0;
    virtual bool responsesProtocol() const = 0;
    virtual QVector<AiModel> models(const QJsonObject &) const = 0;
    QJsonObject payload(const QString &model, const AiContext &) const;
};
class ChatGptProvider final : public AiProvider {
  public:
    QString label() const override {
        return "ChatGPT subscription";
    }
    QUrl baseUrl() const override {
        return QUrl("https://api.openai.com/v1");
    }
    QString inferencePath() const override {
        return "/responses";
    }
    bool responsesProtocol() const override {
        return true;
    }
    QVector<AiModel> models(const QJsonObject &) const override;
};
class LocalAiProvider final : public AiProvider {
  public:
    explicit LocalAiProvider(QUrl endpoint);
    QString label() const override {
        return "Local endpoint";
    }
    QUrl baseUrl() const override {
        return endpoint;
    }
    QString inferencePath() const override {
        return "/chat/completions";
    }
    bool responsesProtocol() const override {
        return false;
    }
    QVector<AiModel> models(const QJsonObject &) const override;

  private:
    QUrl endpoint;
};
class AiService : public QObject {
    Q_OBJECT
  public:
    explicit AiService(QObject *parent = nullptr, ChatGptAuth *auth = nullptr,
                       QNetworkAccessManager *transport = nullptr);
    ~AiService() override;
    ChatGptAuth *authentication() const {
        return auth;
    }
    AiProviderKind kind() const {
        return configuredKind;
    }
    QString providerLabel() const;
    QString endpointLabel() const;
    bool busy() const {
        return running;
    }
    QString selectedModel() const {
        return model;
    }
    QVector<AiModel> availableModels() const {
        return catalog;
    }
    void configure(AiProviderKind kind, QUrl local = QUrl("http://127.0.0.1:1234/v1"));
    void setModel(QString id);
    void fetchModels();
    void explain(AiContext context);
    void cancel();
    void clearCache();
  signals:
    void modelsReady();
    void progress(QString text);
    void completed(vnr::AiExplanation answer);
    void failed(QString error);
    void status(QString text);
    void busyChanged(bool busy);

  private:
    ChatGptAuth *auth;
    QNetworkAccessManager *network;
    std::unique_ptr<AiProvider> provider;
    AiProviderKind configuredKind = AiProviderKind::Disabled;
    QString model, catalogIdentity;
    QVector<AiModel> catalog;
    QPointer<QNetworkReply> active;
    quint64 generation = 0;
    bool running = false;
    QHash<QByteArray, AiExplanation> cache;
    QList<QByteArray> cacheOrder;
    QString identity() const;
    void begin(std::function<void(QByteArray)> next);
    void finish();
    void fail(QString error);
};
} // namespace vnr
Q_DECLARE_METATYPE(vnr::AiExplanation)
