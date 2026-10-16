#include "ai_auth.h"
#include <stdexcept>
// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
// clang-format on

namespace vnr {
static const QString issuer = "https://auth.openai.com";
static const QString resource = "https://api.openai.com/v1";
static QByteArray formBody(const QUrlQuery &query) {
    QByteArray body;
    for (const auto &item : query.queryItems()) {
        if (!body.isEmpty())
            body += '&';
        body += QUrl::toPercentEncoding(item.first) + '=' + QUrl::toPercentEncoding(item.second);
    }
    return body;
}
static void require(bool valid, const char *message) {
    if (!valid)
        throw std::runtime_error(message);
}
QByteArray secureRandomUrl(int count) {
    QByteArray bytes(count, '\0');
    require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(bytes.data()), count,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
            "Windows random generator failed");
    return bytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}
QString ChatGptAccount::label() const {
    return (email.isEmpty() ? subject.left(24) : email) + " · " + clientId.right(10);
}
CredentialStore::CredentialStore(QString path) : directory(std::move(path)) {
    if (directory.isEmpty())
        directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/ai";
}
ChatGptAccount *CredentialStore::find(const QString &id) {
    for (auto &account : accounts)
        if (account.clientId == id)
            return &account;
    return nullptr;
}
static QByteArray protect(QByteArray input, bool decrypt) {
    DATA_BLOB source{DWORD(input.size()), reinterpret_cast<BYTE *>(input.data())}, result{};
    BOOL ok = decrypt ? CryptUnprotectData(&source, nullptr, nullptr, nullptr, nullptr,
                                           CRYPTPROTECT_UI_FORBIDDEN, &result)
                      : CryptProtectData(&source, L"Venor optional AI credentials", nullptr, nullptr, nullptr,
                                         CRYPTPROTECT_UI_FORBIDDEN, &result);
    if (!ok)
        throw std::runtime_error(
            QString("Windows credential protection failed (error %1); credentials were not changed")
                .arg(GetLastError())
                .toStdString());
    QByteArray output(reinterpret_cast<char *>(result.pbData), int(result.cbData));
    SecureZeroMemory(result.pbData, result.cbData);
    LocalFree(result.pbData);
    SecureZeroMemory(input.data(), input.size());
    return output;
}
void CredentialStore::load() {
    QDir().mkpath(directory);
    QFile file(directory + "/credentials.dpapi");
    if (!file.exists()) {
        hostId = "urn:uuid:" + QUuid::createUuid().toString(QUuid::WithoutBraces);
        accounts.clear();
        activeClient.clear();
        return;
    }
    require(file.open(QIODevice::ReadOnly) && file.size() <= 1024 * 1024,
            "Cannot read protected credentials");
    auto plain = protect(file.readAll(), true);
    QJsonParseError error;
    auto document = QJsonDocument::fromJson(plain, &error);
    SecureZeroMemory(plain.data(), plain.size());
    require(error.error == QJsonParseError::NoError && document.isObject(), "Invalid protected credentials");
    auto root = document.object();
    require(root["version"].toInt() == 1, "Unsupported protected credential format");
    hostId = root["host"].toString();
    require(hostId.startsWith("urn:uuid:") && !QUuid(hostId.mid(9)).isNull(),
            "Invalid saved host identifier");
    activeClient = root["active"].toString();
    accounts.clear();
    for (auto value : root["accounts"].toArray()) {
        auto o = value.toObject();
        ChatGptAccount a;
        a.clientId = o["client"].toString();
        a.subject = o["subject"].toString();
        a.email = o["email"].toString();
        a.name = o["name"].toString();
        a.accessToken = o["access"].toString();
        a.refreshToken = o["refresh"].toString();
        a.idToken = o["id"].toString();
        a.expiresAt = o["expires"].toInteger();
        a.earliestRefreshAt = o["earliest"].toInteger();
        for (auto scope : o["scopes"].toArray())
            a.scopes << scope.toString();
        require(a.clientId.startsWith("oaiapp_") && !a.subject.isEmpty() && !find(a.clientId),
                "Invalid saved account registration");
        accounts << a;
    }
    require(activeClient.isEmpty() || find(activeClient), "Missing active account registration");
}
void CredentialStore::save() const {
    QJsonArray array;
    for (const auto &a : accounts) {
        QJsonArray scopes;
        for (const auto &scope : a.scopes)
            scopes << scope;
        array << QJsonObject{
            {"client", a.clientId}, {"subject", a.subject},    {"email", a.email},
            {"name", a.name},       {"access", a.accessToken}, {"refresh", a.refreshToken},
            {"id", a.idToken},      {"expires", a.expiresAt},  {"earliest", a.earliestRefreshAt},
            {"scopes", scopes}};
    }
    QByteArray plain =
        QJsonDocument(
            QJsonObject{{"version", 1}, {"host", hostId}, {"active", activeClient}, {"accounts", array}})
            .toJson(QJsonDocument::Compact);
    auto encrypted = protect(plain, false);
    SecureZeroMemory(plain.data(), plain.size());
    QSaveFile file(directory + "/credentials.dpapi");
    require(file.open(QIODevice::WriteOnly), "Cannot save protected credentials");
    require(file.write(encrypted) == encrypted.size() && file.commit(),
            "Cannot commit protected credentials");
}
static QByteArray unbase64(const QString &text) {
    auto data = QByteArray::fromBase64Encoding(text.toLatin1(), QByteArray::Base64UrlEncoding |
                                                                    QByteArray::AbortOnBase64DecodingErrors);
    require(bool(data), "Malformed token/key encoding");
    return data.decoded;
}
QJsonObject verifyOpenAiIdToken(const QString &jwt, const QJsonObject &jwks, const QString &clientId,
                                const QString &nonce, const QString &expectedSubject, qint64 now) {
    require(jwt.size() <= 65536 && clientId.startsWith("oaiapp_"), "Invalid identity token or client");
    auto pieces = jwt.split('.');
    require(pieces.size() == 3, "Malformed identity token");
    auto header = QJsonDocument::fromJson(unbase64(pieces[0])).object();
    auto claims = QJsonDocument::fromJson(unbase64(pieces[1])).object();
    auto signature = unbase64(pieces[2]);
    QString alg = header["alg"].toString(), kid = header["kid"].toString();
    require(!kid.isEmpty() && !header.contains("crit") &&
                (alg == "RS256" || alg == "PS256" || alg == "ES256"),
            "Unsupported ID-token signing algorithm");
    QJsonObject key;
    for (auto item : jwks["keys"].toArray()) {
        auto k = item.toObject();
        if (k["kid"].toString() == kid) {
            require(key.isEmpty(), "Ambiguous identity signing key");
            key = k;
        }
    }
    require(!key.isEmpty() && (!key.contains("use") || key["use"].toString() == "sig") &&
                (!key.contains("alg") || key["alg"].toString() == alg),
            "Identity signing key not found or incompatible");
    QByteArray blob;
    LPCWSTR provider = BCRYPT_RSA_ALGORITHM, blobType = BCRYPT_RSAPUBLIC_BLOB;
    if (alg == "ES256") {
        auto x = unbase64(key["x"].toString()), y = unbase64(key["y"].toString());
        require(key["kty"].toString() == "EC" && key["crv"].toString() == "P-256" && x.size() == 32 &&
                    y.size() == 32 && signature.size() == 64,
                "Invalid elliptic identity key");
        BCRYPT_ECCKEY_BLOB h{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
        blob = QByteArray(reinterpret_cast<const char *>(&h), sizeof(h)) + x + y;
        provider = BCRYPT_ECDSA_P256_ALGORITHM;
        blobType = BCRYPT_ECCPUBLIC_BLOB;
    } else {
        auto n = unbase64(key["n"].toString()), e = unbase64(key["e"].toString());
        require(key["kty"].toString() == "RSA" && n.size() >= 256 && n.size() <= 1024 && e.size() > 0 &&
                    e.size() <= 8 && signature.size() == n.size(),
                "Invalid RSA identity key");
        BCRYPT_RSAKEY_BLOB h{
            BCRYPT_RSAPUBLIC_MAGIC, ULONG(n.size() * 8), ULONG(e.size()), ULONG(n.size()), 0, 0};
        blob = QByteArray(reinterpret_cast<const char *>(&h), sizeof(h)) + e + n;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE publicKey = nullptr;
    require(BCryptOpenAlgorithmProvider(&algorithm, provider, nullptr, 0) >= 0,
            "Cannot open Windows verifier");
    auto imported = BCryptImportKeyPair(algorithm, nullptr, blobType, &publicKey,
                                        reinterpret_cast<PUCHAR>(blob.data()), ULONG(blob.size()), 0);
    if (imported < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("Invalid identity public key");
    }
    auto digest =
        QCryptographicHash::hash((pieces[0] + "." + pieces[1]).toLatin1(), QCryptographicHash::Sha256);
    BCRYPT_PKCS1_PADDING_INFO pkcs{BCRYPT_SHA256_ALGORITHM};
    BCRYPT_PSS_PADDING_INFO pss{BCRYPT_SHA256_ALGORITHM, 32};
    void *padding = alg == "RS256" ? static_cast<void *>(&pkcs) : alg == "PS256" ? &pss : nullptr;
    ULONG flags = alg == "RS256" ? BCRYPT_PAD_PKCS1 : alg == "PS256" ? BCRYPT_PAD_PSS : 0;
    auto verified = BCryptVerifySignature(publicKey, padding, reinterpret_cast<PUCHAR>(digest.data()),
                                          ULONG(digest.size()), reinterpret_cast<PUCHAR>(signature.data()),
                                          ULONG(signature.size()), flags);
    BCryptDestroyKey(publicKey);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    require(verified >= 0, "Invalid ID-token signature");
    QStringList audiences;
    if (claims["aud"].isString())
        audiences << claims["aud"].toString();
    else
        for (auto v : claims["aud"].toArray())
            audiences << v.toString();
    require(claims["iss"].toString() == issuer && audiences.contains(clientId) &&
                (audiences.size() == 1 || claims["azp"].toString() == clientId) &&
                (!claims.contains("azp") || claims["azp"].toString() == clientId),
            "Invalid ID-token issuer or audience");
    require(
        claims["exp"].isDouble() && claims["iat"].isDouble() && claims["exp"].toInteger() > now - 5 &&
            claims["iat"].toInteger() <= now + 5 &&
            (!claims.contains("nbf") || (claims["nbf"].isDouble() && claims["nbf"].toInteger() <= now + 5)),
        "Expired or not-yet-valid ID token");
    require(!claims["sub"].toString().isEmpty() &&
                (expectedSubject.isEmpty() || claims["sub"].toString() == expectedSubject),
            "ChatGPT account identity changed");
    require(nonce.isEmpty() || claims["nonce"].toString() == nonce, "ID-token nonce mismatch");
    return claims;
}

ChatGptAuth::ChatGptAuth(QObject *parent, QString path, QNetworkAccessManager *transport)
    : QObject(parent), credentials(std::move(path)),
      network(transport ? transport : new QNetworkAccessManager(this)) {
    attemptTimer.setSingleShot(true);
    connect(&attemptTimer, &QTimer::timeout, this,
            [this] { fail("ChatGPT sign-in timed out. Please try again."); });
    try {
        QDir().mkpath(credentials.directory);
        QLockFile guard(credentials.directory + "/session.lock");
        require(guard.tryLock(), "Another Venor instance is updating AI credentials");
        credentials.load();
        credentials.save();
    } catch (const std::exception &e) {
        initialError = QString::fromUtf8(e.what());
    }
    connect(&listener, &QTcpServer::newConnection, this, [this] {
        while (auto *socket = listener.nextPendingConnection()) {
            socket->setParent(this);
            auto data = std::make_shared<QByteArray>();
            auto consumed = std::make_shared<bool>(false);
            connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            QTimer::singleShot(5000, socket, [socket] { socket->disconnectFromHost(); });
            connect(socket, &QTcpSocket::readyRead, this, [this, socket, data, consumed] {
                if (*consumed) {
                    socket->readAll();
                    return;
                }
                *data += socket->readAll();
                if (data->size() > 16384) {
                    *consumed = true;
                    socket->disconnectFromHost();
                    return;
                }
                if (data->contains("\r\n\r\n")) {
                    *consumed = true;
                    acceptCallback(socket, *data);
                }
            });
        }
    });
}
ChatGptAuth::~ChatGptAuth() {
    cancel();
}
void ChatGptAuth::acquire() {
    require(!operation, "Another authentication operation is in progress");
    lock = std::make_unique<QLockFile>(credentials.directory + "/session.lock");
    require(lock->tryLock(), "Another Venor instance is updating this session; retry shortly");
    credentials.load();
    if (!QFile::exists(credentials.directory + "/credentials.dpapi"))
        credentials.save();
    initialError.clear();
    operation = true;
    ++generation;
}
void ChatGptAuth::release() {
    operation = false;
    listener.close();
    attemptTimer.stop();
    lock.reset();
    state.clear();
    nonce.clear();
    verifier.clear();
    redirectUri.clear();
    pendingSubject.clear();
}
void ChatGptAuth::cancel() {
    ++generation;
    auto active = requests;
    requests.clear();
    for (auto *reply : active) {
        reply->disconnect(this);
        reply->abort();
        reply->deleteLater();
    }
    release();
    completeAccess({}, "Authentication cancelled");
}
void ChatGptAuth::fail(QString message) {
    auto waiters = std::move(accessWaiters);
    accessWaiters.clear();
    cancel();
    for (auto &done : waiters)
        done({}, message);
    emit failed(message);
    emit changed();
}
void ChatGptAuth::request(QUrl url, QByteArray body, bool post,
                          std::function<void(int, QJsonObject, QString)> done) {
    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setTransferTimeout(30000);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    auto *reply = post ? network->post(request, body) : network->get(request);
    requests.insert(reply);
    auto epoch = generation;
    auto buffer = std::make_shared<QByteArray>();
    connect(reply, &QIODevice::readyRead, this, [reply, buffer] {
        *buffer += reply->readAll();
        if (buffer->size() > 512 * 1024)
            reply->abort();
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, done, epoch, buffer] {
        requests.remove(reply);
        reply->deleteLater();
        if (epoch != generation)
            return;
        *buffer += reply->readAll();
        int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QJsonParseError parse;
        auto object = QJsonDocument::fromJson(*buffer, &parse).object();
        QString error;
        if (buffer->size() > 512 * 1024)
            error = "Authentication response exceeded the size limit";
        else if (reply->error() != QNetworkReply::NoError || statusCode < 200 || statusCode >= 300) {
            // Token responses may contain credentials: never include the raw body in diagnostics.
            QString code = object["error"].isString() ? object["error"].toString()
                                                      : object["error"].toObject()["code"].toString();
            error = QString("ChatGPT authentication request failed (HTTP %1%2). Retry or reconnect.")
                        .arg(statusCode)
                        .arg(code.isEmpty() ? QString() : ", " + code.left(100));
        } else if (!buffer->isEmpty() && parse.error != QJsonParseError::NoError)
            error = "Invalid authentication JSON response";
        try {
            done(statusCode, object, error);
        } catch (const std::exception &e) {
            fail(QString::fromUtf8(e.what()));
        }
    });
}
void ChatGptAuth::discover(std::function<void()> next) {
    request(QUrl(issuer + "/.well-known/openid-configuration"), {}, false,
            [this, next](int, QJsonObject o, QString error) {
                if (!error.isEmpty()) {
                    fail(error);
                    return;
                }
                if (o["issuer"].toString() != issuer ||
                    o["authorization_endpoint"].toString() != issuer + "/api/accounts/authorize" ||
                    o["token_endpoint"].toString() != issuer + "/api/accounts/oauth/token" ||
                    o["jwks_uri"].toString() != issuer + "/.well-known/jwks.json") {
                    fail("OpenAI discovery endpoints did not match the documented production issuer");
                    return;
                }
                discovery = o;
                next();
            });
}
void ChatGptAuth::signIn(QString client) {
    try {
        acquire();
        pendingClient = client;
        pendingSubject.clear();
        if (!client.isEmpty()) {
            auto *a = credentials.find(client);
            require(a, "Selected ChatGPT registration is unavailable");
            pendingSubject = a->subject;
        } else if (!retryClient.isEmpty())
            pendingClient = retryClient;
        discover([this] {
            if (!listener.listen(QHostAddress::LocalHost, 0)) {
                fail("Cannot open the secure loopback callback listener");
                return;
            }
            state = QString::fromLatin1(secureRandomUrl());
            nonce = QString::fromLatin1(secureRandomUrl());
            verifier = QString::fromLatin1(secureRandomUrl(48));
            redirectUri = QString("http://127.0.0.1:%1/auth/callback").arg(listener.serverPort());
            QUrl url(discovery["authorization_endpoint"].toString());
            QUrlQuery q;
            q.addQueryItem("client_id", pendingClient.isEmpty() ? "dynamic_agent_client" : pendingClient);
            if (pendingClient.isEmpty())
                q.addQueryItem("agent_name_hint", APP_TITLE);
            q.addQueryItem("ext_agent_host_id", credentials.hostId);
            if (auto *a = credentials.find(pendingClient)) {
                if (!a->idToken.isEmpty())
                    q.addQueryItem("id_token_hint", a->idToken);
                if (!a->email.isEmpty())
                    q.addQueryItem("login_hint", a->email);
                if (!a->planEnabled())
                    q.addQueryItem("prompt", "consent");
            }
            q.addQueryItem("response_type", "code");
            q.addQueryItem("redirect_uri", redirectUri);
            q.addQueryItem("scope",
                           "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct");
            q.addQueryItem("resource", resource);
            q.addQueryItem("state", state);
            q.addQueryItem("nonce", nonce);
            q.addQueryItem("code_challenge_method", "S256");
            q.addQueryItem(
                "code_challenge",
                QString::fromLatin1(
                    QCryptographicHash::hash(verifier.toLatin1(), QCryptographicHash::Sha256)
                        .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
            url.setQuery(QString::fromLatin1(formBody(q)), QUrl::StrictMode);
            attemptTimer.start(300000);
            emit status("Complete sign-in and permission approval in your system browser.");
            emit authorizationReady(url);
            emit changed();
        });
    } catch (const std::exception &e) {
        fail(QString::fromUtf8(e.what()));
    }
}
void ChatGptAuth::acceptCallback(QTcpSocket *socket, QByteArray bytes) {
    auto lines = bytes.split('\n');
    auto first = lines.value(0).trimmed().split(' ');
    QUrl url = QUrl::fromEncoded(first.value(1), QUrl::StrictMode);
    QUrlQuery q(url);
    QString host;
    for (const auto &line : lines)
        if (line.toLower().startsWith("host:"))
            host = QString::fromLatin1(line.mid(5).trimmed());
    bool valid = operation && !state.isEmpty() && first.value(0) == "GET" && url.isRelative() &&
                 url.path() == "/auth/callback" &&
                 host == QString("127.0.0.1:%1").arg(listener.serverPort()) &&
                 q.allQueryItemValues("state").size() == 1 && q.queryItemValue("state") == state;
    QByteArray body = valid ? "Sign-in response received. You may return to Venor."
                            : "Invalid or expired sign-in callback.";
    socket->write(QByteArray(valid ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 400 Bad Request\r\n") +
                  "Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: "
                  "no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nConnection: "
                  "close\r\nContent-Length: " +
                  QByteArray::number(body.size()) + "\r\n\r\n" + body);
    socket->disconnectFromHost();
    if (!valid)
        return;
    state.clear();
    listener.close();
    attemptTimer.stop();
    if (q.hasQueryItem("error")) {
        fail("ChatGPT authorization was declined or failed. You can reconnect from settings.");
        return;
    }
    auto issued = q.queryItemValue("client_id");
    if (q.allQueryItemValues("code").size() != 1 || q.queryItemValue("code").isEmpty() ||
        q.allQueryItemValues("client_id").size() > 1 ||
        (!issued.isEmpty() && !pendingClient.isEmpty() && issued != pendingClient)) {
        fail("ChatGPT callback registration or authorization code did not match this attempt");
        return;
    }
    if (pendingClient.isEmpty())
        pendingClient = issued;
    if (!pendingClient.startsWith("oaiapp_")) {
        fail("Registration did not return an issued ChatGPT client ID");
        return;
    }
    exchange(q.queryItemValue("code", QUrl::FullyDecoded));
}
void ChatGptAuth::exchange(QString code) {
    QUrlQuery form;
    form.addQueryItem("grant_type", "authorization_code");
    form.addQueryItem("client_id", pendingClient);
    form.addQueryItem("code", code);
    form.addQueryItem("code_verifier", verifier);
    form.addQueryItem("redirect_uri", redirectUri);
    form.addQueryItem("resource", resource);
    request(
        QUrl(discovery["token_endpoint"].toString()), formBody(form), true,
        [this](int, QJsonObject tokens, QString error) {
            if (!error.isEmpty()) {
                retryClient = pendingSubject.isEmpty() ? pendingClient : QString();
                fail(error);
                return;
            }
            acceptTokens(tokens, false, [this] {
                retryClient.clear();
                release();
                emit changed();
                auto *a = credentials.find(credentials.activeClient);
                emit status(
                    a && a->planEnabled()
                        ? "ChatGPT connected. Select a model to explain code."
                        : "Signed in, but ChatGPT plan permission was not granted. Reconnect to enable it.");
            });
        });
}
void ChatGptAuth::acceptTokens(QJsonObject tokens, bool refresh, std::function<void()> next) {
    request(
        QUrl(discovery["jwks_uri"].toString()), {}, false,
        [this, tokens, refresh, next](int, QJsonObject jwks, QString error) {
            if (!error.isEmpty()) {
                fail(error);
                return;
            }
            try {
                auto *old = credentials.find(pendingClient);
                require(!refresh || old, "The refreshed account is unavailable");
                ChatGptAccount account = old ? *old : ChatGptAccount{};
                auto id = tokens["id_token"].toString();
                require(refresh || !id.isEmpty(), "Authorization did not return an ID token");
                if (!id.isEmpty()) {
                    auto claims = verifyOpenAiIdToken(id, jwks, pendingClient, refresh ? QString() : nonce,
                                                      pendingSubject);
                    account.subject = claims["sub"].toString();
                    account.email = claims["email"].toString();
                    account.name = claims["name"].toString();
                    account.idToken = id;
                }
                require(refresh || tokens["scope"].isString(), "Token response omitted granted scopes");
                if (tokens["scope"].isString())
                    account.scopes = tokens["scope"].toString().split(' ', Qt::SkipEmptyParts);
                account.clientId = pendingClient;
                account.accessToken = tokens["access_token"].toString();
                account.refreshToken = tokens["refresh_token"].toString();
                require((!account.planEnabled() && !refresh) || !account.accessToken.isEmpty(),
                        "ChatGPT plan grant did not include an access token");
                if (!account.accessToken.isEmpty()) {
                    require(tokens["token_type"].toString().compare("Bearer", Qt::CaseInsensitive) == 0 &&
                                tokens["expires_in"].isDouble() && tokens["expires_in"].toInteger() > 0 &&
                                tokens["expires_in"].toInteger() <= 86400,
                            "Invalid or incomplete ChatGPT token response");
                    account.expiresAt = QDateTime::currentSecsSinceEpoch() + tokens["expires_in"].toInteger();
                } else
                    account.expiresAt = 0;
                require(!(refresh || (account.planEnabled() && account.scopes.contains("offline_access"))) ||
                            !account.refreshToken.isEmpty(),
                        "Renewable session did not include a refresh token");
                account.earliestRefreshAt = tokens["earliest_refresh_at"].toInteger();
                if (old)
                    *old = account;
                else
                    credentials.accounts << account;
                if (!refresh)
                    credentials.activeClient = account.clientId;
                credentials.save();
                next();
            } catch (const std::exception &e) {
                fail(QString::fromUtf8(e.what()));
            }
        });
}
void ChatGptAuth::selectAccount(const QString &id) {
    if (operation) {
        emit failed("Finish or cancel the current sign-in first");
        return;
    }
    try {
        acquire();
        require(credentials.find(id), "ChatGPT registration is unavailable");
        credentials.activeClient = id;
        credentials.save();
        release();
        emit changed();
    } catch (const std::exception &e) {
        fail(QString::fromUtf8(e.what()));
    }
}
void ChatGptAuth::completeAccess(QString token, QString error) {
    auto waiters = std::move(accessWaiters);
    accessWaiters.clear();
    for (auto &done : waiters)
        done(token, error);
}
void ChatGptAuth::ensureAccess(std::function<void(QString, QString)> done) {
    if (!accessWaiters.isEmpty()) {
        accessWaiters << std::move(done);
        return;
    }
    if (operation) {
        done({}, "Finish or cancel the current authentication operation first");
        return;
    }
    try {
        acquire();
        auto *a = credentials.find(credentials.activeClient);
        require(a && a->planEnabled(), "Connect a ChatGPT account and grant ChatGPT plan usage permission");
        if (!a->accessToken.isEmpty() && a->expiresAt > QDateTime::currentSecsSinceEpoch() + 60) {
            auto token = a->accessToken;
            release();
            done(token, {});
            return;
        }
        require(!a->refreshToken.isEmpty(), "ChatGPT session expired. Reconnect the selected account");
        require(a->earliestRefreshAt <= QDateTime::currentSecsSinceEpoch(),
                "Token renewal is not yet permitted. Retry shortly");
        pendingClient = a->clientId;
        pendingSubject = a->subject;
        accessWaiters << std::move(done);
        discover([this] {
            auto *a = credentials.find(pendingClient);
            QUrlQuery form;
            form.addQueryItem("grant_type", "refresh_token");
            form.addQueryItem("client_id", a->clientId);
            form.addQueryItem("refresh_token", a->refreshToken);
            form.addQueryItem("resource", resource);
            request(QUrl(discovery["token_endpoint"].toString()), formBody(form), true,
                    [this](int statusCode, QJsonObject tokens, QString error) {
                        if (!error.isEmpty()) {
                            auto code = tokens["error"].isString()
                                            ? tokens["error"].toString()
                                            : tokens["error"].toObject()["code"].toString();
                            const QStringList terminal{
                                "invalid_grant",         "invalid_refresh_token",     "token_expired",
                                "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused"};
                            if (terminal.contains(code)) {
                                if (auto *a = credentials.find(pendingClient)) {
                                    a->accessToken.clear();
                                    a->refreshToken.clear();
                                    a->idToken.clear();
                                    try {
                                        credentials.save();
                                    } catch (...) {
                                    }
                                }
                            }
                            auto waiters = std::move(accessWaiters);
                            accessWaiters.clear();
                            release();
                            for (auto &done : waiters)
                                done({}, error);
                            emit failed(error);
                            emit changed();
                            return;
                        }
                        acceptTokens(tokens, true, [this] {
                            auto *a = credentials.find(pendingClient);
                            QString token = a && a->planEnabled() ? a->accessToken : QString();
                            release();
                            completeAccess(token, token.isEmpty() ? "ChatGPT plan permission was removed"
                                                                  : QString());
                            emit changed();
                        });
                    });
        });
    } catch (const std::exception &e) {
        release();
        done({}, QString::fromUtf8(e.what()));
    }
}
void ChatGptAuth::signOut() {
    if (operation) {
        emit failed("Finish or cancel the current authentication operation first");
        return;
    }
    try {
        acquire();
        auto *a = credentials.find(credentials.activeClient);
        require(a, "No ChatGPT account is selected");
        pendingClient = a->clientId;
        emit status("Signing out and revoking the renewable ChatGPT session…");
        auto finish = [this](bool revoked) {
            if (auto *a = credentials.find(pendingClient)) {
                a->accessToken.clear();
                a->refreshToken.clear();
                a->idToken.clear();
                a->expiresAt = 0;
                a->earliestRefreshAt = 0;
            }
            try {
                credentials.save();
            } catch (const std::exception &e) {
                fail(QString::fromUtf8(e.what()));
                return;
            }
            release();
            emit changed();
            emit status(revoked ? "Signed out. Account registration retained for reconnection."
                                : "Signed out locally. Remote revocation was not confirmed; disconnect Venor "
                                  "in ChatGPT Settings.");
        };
        if (a->refreshToken.isEmpty()) {
            finish(true);
            return;
        }
        // Discovery is fetched independently so a failure can still finish a local logout.
        request(QUrl(issuer + "/.well-known/openid-configuration"), {}, false,
                [this, finish](int, QJsonObject o, QString error) {
                    QUrl revoke(o["revocation_endpoint"].toString());
                    if (!error.isEmpty() || o["issuer"].toString() != issuer || revoke.scheme() != "https" ||
                        revoke.host() != "auth.openai.com" || !revoke.userInfo().isEmpty() ||
                        revoke.port(-1) != -1) {
                        finish(false);
                        return;
                    }
                    auto retry = std::make_shared<std::function<void(int)>>();
                    auto weak = std::weak_ptr<std::function<void(int)>>(retry);
                    *retry = [this, revoke, finish, weak](int count) {
                        auto keep = weak.lock();
                        if (!keep)
                            return;
                        auto *a = credentials.find(pendingClient);
                        QUrlQuery f;
                        f.addQueryItem("token", a->refreshToken);
                        f.addQueryItem("token_type_hint", "refresh_token");
                        f.addQueryItem("client_id", a->clientId);
                        request(revoke, formBody(f), true,
                                [this, finish, keep, count](int code, QJsonObject, QString error) {
                                    if (code == 200 && error.isEmpty())
                                        finish(true);
                                    else if ((code == 0 || code >= 500) && count < 2) {
                                        auto epoch = generation;
                                        QTimer::singleShot(500 * (1 << count), this,
                                                           [this, keep, count, epoch] {
                                                               if (epoch == generation)
                                                                   (*keep)(count + 1);
                                                           });
                                    } else
                                        finish(false);
                                });
                    };
                    (*retry)(0);
                });
    } catch (const std::exception &e) {
        fail(QString::fromUtf8(e.what()));
    }
}
} // namespace vnr
