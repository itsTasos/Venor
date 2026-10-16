#pragma once
#include <QtCore>
#include <QtNetwork>
#include <functional>
#include <memory>

namespace vnr {
struct ChatGptAccount {
    QString clientId, subject, email, name, accessToken, refreshToken, idToken;
    QStringList scopes;
    qint64 expiresAt = 0, earliestRefreshAt = 0;
    bool planEnabled() const {
        return scopes.contains("chatgpt.tokens.use.direct");
    }
    QString label() const;
};

// Only this application-owned store is opened; Codex/browser credentials are never read.
class CredentialStore {
  public:
    explicit CredentialStore(QString directory = {});
    void load();
    void save() const;
    QString directory, hostId, activeClient;
    QVector<ChatGptAccount> accounts;
    ChatGptAccount *find(const QString &clientId);
};

QJsonObject verifyOpenAiIdToken(const QString &jwt, const QJsonObject &jwks, const QString &clientId,
                                const QString &nonce, const QString &expectedSubject = {},
                                qint64 now = QDateTime::currentSecsSinceEpoch());
QByteArray secureRandomUrl(int bytes = 32);

class ChatGptAuth : public QObject {
    Q_OBJECT
  public:
    explicit ChatGptAuth(QObject *parent = nullptr, QString directory = {},
                         QNetworkAccessManager *transport = nullptr);
    ~ChatGptAuth() override;
    const CredentialStore &store() const {
        return credentials;
    }
    QString storageError() const {
        return initialError;
    }
    bool busy() const {
        return operation;
    }
    void signIn(QString clientId = {});
    void cancel();
    void selectAccount(const QString &clientId);
    void ensureAccess(std::function<void(QString, QString)> done);
    void signOut();
  signals:
    void authorizationReady(QUrl url);
    void changed();
    void status(QString text);
    void failed(QString text);

  private:
    CredentialStore credentials;
    QNetworkAccessManager *network;
    QTcpServer listener;
    QTimer attemptTimer;
    QSet<QNetworkReply *> requests;
    std::unique_ptr<QLockFile> lock;
    QJsonObject discovery;
    bool operation = false;
    quint64 generation = 0;
    QString initialError, pendingClient, pendingSubject, state, nonce, verifier, redirectUri;
    QString retryClient;
    QVector<std::function<void(QString, QString)>> accessWaiters;
    void acquire();
    void release();
    void discover(std::function<void()> next);
    void request(QUrl url, QByteArray body, bool post, std::function<void(int, QJsonObject, QString)> done);
    void acceptCallback(QTcpSocket *socket, QByteArray request);
    void exchange(QString code);
    void acceptTokens(QJsonObject tokens, bool refresh, std::function<void()> next);
    void fail(QString message);
    void completeAccess(QString token = {}, QString error = {});
};
} // namespace vnr
