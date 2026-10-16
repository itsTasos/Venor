#include "ai_test_support.h"
#include <stdexcept>
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
using namespace vnr;

class SigningKey {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool ec;

  public:
    QJsonObject jwks;
    explicit SigningKey(bool elliptic = false) : ec(elliptic) {
        if (BCryptOpenAlgorithmProvider(&algorithm, ec ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_RSA_ALGORITHM,
                                        nullptr, 0) < 0 ||
            BCryptGenerateKeyPair(algorithm, &key, ec ? 256 : 2048, 0) < 0 ||
            BCryptFinalizeKeyPair(key, 0) < 0)
            throw std::runtime_error("Cannot generate signing fixture");
        ULONG size = 0;
        BCryptExportKey(key, nullptr, ec ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &size,
                        0);
        QByteArray blob(int(size), '\0');
        BCryptExportKey(key, nullptr, ec ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_RSAPUBLIC_BLOB,
                        reinterpret_cast<PUCHAR>(blob.data()), size, &size, 0);
        auto b64 = [](QByteArray bytes) {
            return QString::fromLatin1(
                bytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
        };
        QJsonObject publicKey{{"kid", "venor-test-key"}, {"use", "sig"}};
        if (ec) {
            publicKey["kty"] = "EC";
            publicKey["crv"] = "P-256";
            publicKey["x"] = b64(blob.mid(sizeof(BCRYPT_ECCKEY_BLOB), 32));
            publicKey["y"] = b64(blob.mid(sizeof(BCRYPT_ECCKEY_BLOB) + 32, 32));
        } else {
            auto *h = reinterpret_cast<const BCRYPT_RSAKEY_BLOB *>(blob.constData());
            publicKey["kty"] = "RSA";
            publicKey["e"] = b64(blob.mid(sizeof(*h), h->cbPublicExp));
            publicKey["n"] = b64(blob.mid(sizeof(*h) + h->cbPublicExp, h->cbModulus));
        }
        jwks = {{"keys", QJsonArray{publicKey}}};
    }
    ~SigningKey() {
        if (key)
            BCryptDestroyKey(key);
        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    QString token(QString client, QString nonce, QJsonObject overrides = {}, bool pss = false) const {
        qint64 now = QDateTime::currentSecsSinceEpoch();
        QJsonObject claims{{"iss", "https://auth.openai.com"},
                           {"aud", client},
                           {"sub", "account-subject"},
                           {"email", "fixture@example.invalid"},
                           {"iat", now},
                           {"exp", now + 3600},
                           {"nonce", nonce}};
        for (auto it = overrides.begin(); it != overrides.end(); ++it)
            claims[it.key()] = it.value();
        auto encode = [](QJsonObject o) {
            return jsonBytes(o).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        };
        QByteArray input = encode({{"alg", ec    ? "ES256"
                                           : pss ? "PS256"
                                                 : "RS256"},
                                   {"kid", "venor-test-key"}}) +
                           "." + encode(claims);
        auto hash = QCryptographicHash::hash(input, QCryptographicHash::Sha256);
        BCRYPT_PKCS1_PADDING_INFO pkcs{BCRYPT_SHA256_ALGORITHM};
        BCRYPT_PSS_PADDING_INFO paddingPss{BCRYPT_SHA256_ALGORITHM, 32};
        void *padding = ec ? nullptr : pss ? static_cast<void *>(&paddingPss) : &pkcs;
        ULONG flags = ec ? 0 : pss ? BCRYPT_PAD_PSS : BCRYPT_PAD_PKCS1, size = 0;
        BCryptSignHash(key, padding, reinterpret_cast<PUCHAR>(hash.data()), ULONG(hash.size()), nullptr, 0,
                       &size, flags);
        QByteArray signature(int(size), '\0');
        if (BCryptSignHash(key, padding, reinterpret_cast<PUCHAR>(hash.data()), ULONG(hash.size()),
                           reinterpret_cast<PUCHAR>(signature.data()), size, &size, flags) < 0)
            throw std::runtime_error("Cannot sign fixture token");
        return QString::fromLatin1(
            input + "." + signature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    }
};
struct AuthFixture {
    SigningKey signer;
    QUrl authorization;
    QString client = "oaiapp_venor_fixture",
            scope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
    QJsonObject claimOverrides;
    bool badSignature = false, identityOnly = false;
    int refreshes = 0, revocations = 0;
    FixtureNetwork network;
    explicit AuthFixture() {
        network.handler = [this](const SentRequest &call) -> HttpFixture {
            QString path = call.request.url().path();
            if (path == "/.well-known/openid-configuration")
                return {200,
                        jsonBytes(
                            {{"issuer", "https://auth.openai.com"},
                             {"authorization_endpoint", "https://auth.openai.com/api/accounts/authorize"},
                             {"token_endpoint", "https://auth.openai.com/api/accounts/oauth/token"},
                             {"jwks_uri", "https://auth.openai.com/.well-known/jwks.json"},
                             {"revocation_endpoint", "https://auth.openai.com/api/accounts/oauth/revoke"}})};
            if (path == "/.well-known/jwks.json")
                return {200, jsonBytes(signer.jwks)};
            if (path == "/api/accounts/oauth/revoke") {
                ++revocations;
                return {200, {}};
            }
            if (path == "/api/accounts/oauth/token") {
                QUrlQuery form(QString::fromUtf8(call.body));
                bool refresh = form.queryItemValue("grant_type") == "refresh_token";
                if (refresh)
                    ++refreshes;
                auto id =
                    signer.token(client, QUrlQuery(authorization).queryItemValue("nonce"), claimOverrides);
                if (badSignature) {
                    auto parts = id.split('.');
                    auto sig = QByteArray::fromBase64(parts[2].toLatin1(), QByteArray::Base64UrlEncoding);
                    sig[0] ^= 1;
                    parts[2] = QString::fromLatin1(
                        sig.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
                    id = parts.join('.');
                }
                if (identityOnly)
                    return {200, jsonBytes({{"id_token", id}, {"scope", "openid profile email"}})};
                return {200, jsonBytes({{"id_token", id},
                                        {"access_token", "fixture-access-token"},
                                        {"refresh_token",
                                         refresh ? "rotated-refresh-token" : "fixture-refresh-token"},
                                        {"token_type", "Bearer"},
                                        {"expires_in", 3600},
                                        {"scope", scope}})};
            }
            return {404, "{}"};
        };
    }
};

class AiTests : public QObject {
    Q_OBJECT
    void authorize(ChatGptAuth &auth, AuthFixture &fixture, QString client = {}) {
        QSignalSpy ready(&auth, &ChatGptAuth::authorizationReady);
        auto connection = connect(&auth, &ChatGptAuth::authorizationReady, this,
                                  [&](QUrl url) { fixture.authorization = url; });
        auth.signIn(client);
        QTRY_COMPARE(ready.size(), 1);
        auto query = QUrlQuery(fixture.authorization);
        QUrl callback(query.queryItemValue("redirect_uri", QUrl::FullyDecoded));
        QUrlQuery result;
        result.addQueryItem("state", query.queryItemValue("state"));
        result.addQueryItem("code", "fixture-code");
        result.addQueryItem("client_id", fixture.client);
        callback.setQuery(result);
        QNetworkAccessManager browser;
        auto *reply = browser.get(QNetworkRequest(callback));
        QSignalSpy received(reply, &QNetworkReply::finished);
        QTRY_COMPARE(received.size(), 1);
        QVERIFY2(reply->error() == QNetworkReply::NoError, qPrintable(reply->errorString()));
        QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), 200);
        QTRY_VERIFY(!auth.busy());
        disconnect(connection);
    }
  private slots:
    void signedIdentityValidation() {
        for (bool ec : {false, true}) {
            SigningKey key(ec);
            auto jwt = key.token("oaiapp_test", "nonce");
            QCOMPARE(verifyOpenAiIdToken(jwt, key.jwks, "oaiapp_test", "nonce")["sub"].toString(),
                     QString("account-subject"));
            QVERIFY_EXCEPTION_THROWN(verifyOpenAiIdToken(jwt, key.jwks, "oaiapp_test", "other"),
                                     std::exception);
            QVERIFY_EXCEPTION_THROWN(verifyOpenAiIdToken(jwt, key.jwks, "oaiapp_wrong", "nonce"),
                                     std::exception);
            QVERIFY_EXCEPTION_THROWN(
                verifyOpenAiIdToken(jwt, key.jwks, "oaiapp_test", "nonce", "another-subject"),
                std::exception);
            for (const auto &overrides :
                 {QJsonObject{{"iss", "https://attacker.invalid"}}, QJsonObject{{"exp", 1}},
                  QJsonObject{{"iat", QDateTime::currentSecsSinceEpoch() + 100}},
                  QJsonObject{{"nbf", QDateTime::currentSecsSinceEpoch() + 100}}, QJsonObject{{"sub", ""}},
                  QJsonObject{{"aud", QJsonArray{"oaiapp_test", "other"}}}}) {
                QVERIFY_EXCEPTION_THROWN(verifyOpenAiIdToken(key.token("oaiapp_test", "nonce", overrides),
                                                             key.jwks, "oaiapp_test", "nonce"),
                                         std::exception);
            }
            if (!ec)
                QCOMPARE(verifyOpenAiIdToken(key.token("oaiapp_test", "nonce", {}, true), key.jwks,
                                             "oaiapp_test", "nonce")["sub"]
                             .toString(),
                         QString("account-subject"));
            auto parts = jwt.split('.');
            parts[2] = QString(parts[2].size(), 'A');
            QVERIFY_EXCEPTION_THROWN(verifyOpenAiIdToken(parts.join('.'), key.jwks, "oaiapp_test", "nonce"),
                                     std::exception);
            QVERIFY_EXCEPTION_THROWN(
                verifyOpenAiIdToken(jwt, {{"keys", QJsonArray()}}, "oaiapp_test", "nonce"), std::exception);
        }
        QVERIFY_EXCEPTION_THROWN(verifyOpenAiIdToken("e30.e30.", {}, "oaiapp_test", "nonce"), std::exception);
    }
    void oauthAndProtectedPersistence() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        AuthFixture fixture;
        ChatGptAuth auth(nullptr, directory.path(), &fixture.network);
        QVERIFY2(auth.storageError().isEmpty(), qPrintable(auth.storageError()));
        auto host = auth.store().hostId;
        QVERIFY(host.startsWith("urn:uuid:"));
        authorize(auth, fixture);
        QCOMPARE(auth.store().accounts.size(), 1);
        QVERIFY(auth.store().accounts.first().planEnabled());
        auto query = QUrlQuery(fixture.authorization);
        QCOMPARE(query.queryItemValue("client_id"), QString("dynamic_agent_client"));
        QCOMPARE(query.queryItemValue("code_challenge_method"), QString("S256"));
        QCOMPARE(query.queryItemValue("ext_agent_host_id", QUrl::FullyDecoded), host);
        QVERIFY(!query.queryItemValue("state").isEmpty());
        QVERIFY(!query.queryItemValue("nonce").isEmpty());
        auto tokenCall =
            std::find_if(fixture.network.sent.begin(), fixture.network.sent.end(),
                         [](const auto &r) { return r.request.url().path().endsWith("/token"); });
        QVERIFY(tokenCall != fixture.network.sent.end());
        QUrlQuery form(QString::fromUtf8(tokenCall->body));
        QCOMPARE(form.queryItemValue("client_id"), fixture.client);
        QCOMPARE(form.queryItemValue("redirect_uri", QUrl::FullyDecoded),
                 query.queryItemValue("redirect_uri", QUrl::FullyDecoded));
        QCOMPARE(QString::fromLatin1(
                     QCryptographicHash::hash(form.queryItemValue("code_verifier").toLatin1(),
                                              QCryptographicHash::Sha256)
                         .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)),
                 query.queryItemValue("code_challenge"));
        QFile encrypted(directory.filePath("credentials.dpapi"));
        QVERIFY(encrypted.open(QIODevice::ReadOnly));
        auto bytes = encrypted.readAll();
        QVERIFY(!bytes.contains("fixture-access-token"));
        QVERIFY(!bytes.contains("fixture@example.invalid"));
        CredentialStore restored(directory.path());
        restored.load();
        QCOMPARE(restored.hostId, host);
        QCOMPARE(restored.activeClient, fixture.client);
        QCOMPARE(restored.accounts.first().refreshToken, QString("fixture-refresh-token"));
        authorize(auth, fixture, fixture.client);
        auto returning = QUrlQuery(fixture.authorization);
        QCOMPARE(returning.queryItemValue("client_id"), fixture.client);
        QVERIFY(!returning.hasQueryItem("agent_name_hint"));
        QVERIFY(returning.hasQueryItem("id_token_hint"));
        QVERIFY(returning.queryItemValue("state") != query.queryItemValue("state"));
    }
    void callbackStateAndAccountIsolation() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        AuthFixture fixture;
        ChatGptAuth auth(nullptr, directory.path(), &fixture.network);
        QSignalSpy ready(&auth, &ChatGptAuth::authorizationReady), failures(&auth, &ChatGptAuth::failed);
        auth.signIn();
        QTRY_COMPARE(ready.size(), 1);
        auto url = ready.first().first().toUrl();
        QUrlQuery q(url);
        QUrl callback(q.queryItemValue("redirect_uri", QUrl::FullyDecoded));
        QUrlQuery wrong;
        wrong.addQueryItem("state", "wrong-state");
        wrong.addQueryItem("code", "bad");
        wrong.addQueryItem("client_id", fixture.client);
        callback.setQuery(wrong);
        QNetworkAccessManager browser;
        auto *reply = browser.get(QNetworkRequest(callback));
        QSignalSpy done(reply, &QNetworkReply::finished);
        QTRY_COMPARE(done.size(), 1);
        QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), 400);
        QVERIFY(auth.store().accounts.isEmpty());
        QVERIFY(auth.busy());
        auth.cancel();
        authorize(auth, fixture);
        QCOMPARE(auth.store().accounts.size(), 1);
        fixture.client = "oaiapp_second_fixture";
        authorize(auth, fixture);
        QCOMPARE(auth.store().accounts.size(), 2);
        QCOMPARE(auth.store().activeClient, fixture.client);
        auth.selectAccount("oaiapp_venor_fixture");
        QCOMPARE(auth.store().activeClient, QString("oaiapp_venor_fixture"));
        fixture.client = "oaiapp_venor_fixture";
        fixture.claimOverrides = {{"sub", "impostor"}};
        authorize(auth, fixture, fixture.client);
        QVERIFY(!failures.isEmpty());
        QCOMPARE(auth.store().accounts.first().subject, QString("account-subject"));
        QCOMPARE(auth.store().accounts.first().accessToken, QString("fixture-access-token"));
    }
    void rejectedSignatureAndMissingPermission() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        AuthFixture fixture;
        fixture.badSignature = true;
        ChatGptAuth auth(nullptr, directory.path(), &fixture.network);
        QSignalSpy failures(&auth, &ChatGptAuth::failed);
        authorize(auth, fixture);
        QVERIFY(!failures.isEmpty());
        QVERIFY(auth.store().accounts.isEmpty());
        fixture.badSignature = false;
        fixture.identityOnly = true;
        authorize(auth, fixture);
        QCOMPARE(auth.store().accounts.size(), 1);
        QVERIFY(!auth.store().accounts.first().planEnabled());
        bool completed = false;
        auth.ensureAccess([&](QString token, QString error) {
            QVERIFY(token.isEmpty());
            QVERIFY(!error.isEmpty());
            completed = true;
        });
        QTRY_VERIFY(completed);
    }
    void refreshFailureAndCrossProcessLock() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        AuthFixture fixture;
        ChatGptAuth auth(nullptr, directory.path(), &fixture.network);
        authorize(auth, fixture);
        QCOMPARE(auth.store().accounts.size(), 1);
        CredentialStore edit(directory.path());
        edit.load();
        edit.accounts.first().expiresAt = 0;
        edit.save();
        QLockFile guard(directory.filePath("session.lock"));
        QVERIFY(guard.tryLock());
        int results = 0;
        QString lastError;
        auto done = [&](QString token, QString error) {
            QVERIFY(token.isEmpty());
            lastError = error;
            ++results;
        };
        auth.ensureAccess(done);
        QCOMPARE(results, 1);
        QVERIFY(lastError.contains("Another Venor instance"));
        QCOMPARE(fixture.refreshes, 0);
        guard.unlock();
        auto original = fixture.network.handler;
        int code = 503;
        QString failureCode = "temporary_failure";
        fixture.network.handler = [&](const SentRequest &call) -> HttpFixture {
            if (call.request.url().path().endsWith("/token"))
                return {code, jsonBytes({{"error", failureCode}})};
            return original(call);
        };
        auth.ensureAccess(done);
        QTRY_COMPARE(results, 2);
        edit.load();
        QCOMPARE(edit.accounts.first().refreshToken, QString("fixture-refresh-token"));
        code = 400;
        failureCode = "invalid_client";
        auth.ensureAccess(done);
        QTRY_COMPARE(results, 3);
        edit.load();
        QCOMPARE(edit.accounts.first().refreshToken, QString("fixture-refresh-token"));
        failureCode = "invalid_grant";
        auth.ensureAccess(done);
        QTRY_COMPARE(results, 4);
        edit.load();
        QVERIFY(edit.accounts.first().refreshToken.isEmpty());
        QCOMPARE(edit.accounts.first().clientId, fixture.client);
    }
    void corruptedProtectedStoreFailsClosed() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        QFile file(directory.filePath("credentials.dpapi"));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("deliberately damaged encrypted fixture");
        file.close();
        FixtureNetwork network;
        ChatGptAuth auth(nullptr, directory.path(), &network);
        QVERIFY(!auth.storageError().isEmpty());
        QSignalSpy failure(&auth, &ChatGptAuth::failed);
        auth.signIn();
        QCOMPARE(failure.size(), 1);
        QCOMPARE(network.sent.size(), 0);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), QByteArray("deliberately damaged encrypted fixture"));
    }
    void tokenRefreshRotationAndLogout() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        AuthFixture fixture;
        ChatGptAuth auth(nullptr, directory.path(), &fixture.network);
        authorize(auth, fixture);
        QCOMPARE(auth.store().accounts.size(), 1);
        CredentialStore edit(directory.path());
        edit.load();
        edit.accounts.first().expiresAt = 0;
        edit.save();
        int calls = 0;
        auto callback = [&](QString token, QString error) {
            QCOMPARE(token, QString("fixture-access-token"));
            QVERIFY(error.isEmpty());
            ++calls;
        };
        auth.ensureAccess(callback);
        auth.ensureAccess(callback);
        QTRY_COMPARE(calls, 2);
        QCOMPARE(fixture.refreshes, 1);
        QCOMPARE(auth.store().accounts.first().refreshToken, QString("rotated-refresh-token"));
        QSignalSpy changes(&auth, &ChatGptAuth::changed);
        auth.signOut();
        QTRY_VERIFY(!auth.busy());
        QCOMPARE(fixture.revocations, 1);
        QVERIFY(!changes.isEmpty());
        QCOMPARE(auth.store().accounts.size(), 1);
        QVERIFY(auth.store().accounts.first().accessToken.isEmpty());
        QVERIFY(auth.store().accounts.first().refreshToken.isEmpty());
        QVERIFY(auth.store().accounts.first().idToken.isEmpty());
        QCOMPARE(auth.store().activeClient, fixture.client);
        CredentialStore saved(directory.path());
        saved.load();
        QVERIFY(saved.accounts.first().refreshToken.isEmpty());
    }
    void contextBoundsAndEvidenceLinking() {
        auto context = smallContext();
        QVERIFY(context.addresses.contains(0x1000));
        QVERIFY(context.functionStarts.contains(0x1000));
        QVERIFY(!context.serialized().contains("fixture@example"));
        QVERIFY(!context.data.contains("observed_snapshot"));
        auto answer =
            validateAiExplanation("Observed [0x1000]. Unknown [0x9999]. <img src='https://invalid/'>\n"
                                  "<venor-suggestions>{\"suggestions\":[{\"kind\":\"function_name\","
                                  "\"address\":\"0x1000\",\"text\":\"entry_candidate\"},"
                                  "{\"kind\":\"comment\",\"address\":\"0x9999\",\"text\":\"bad\"},"
                                  "{\"kind\":\"function_name\",\"address\":\"0x1005\",\"text\":\"not_a_"
                                  "function\"}]}</venor-suggestions>",
                                  context);
        QCOMPARE(answer.invalidReferences, 1);
        QCOMPARE(answer.rejectedSuggestions, 2);
        QCOMPARE(answer.suggestions.size(), 1);
        auto html = aiExplanationHtml(answer);
        QVERIFY(html.contains("ai-source:1000"));
        QVERIFY(!html.contains("ai-source:9999"));
        QVERIFY(!html.contains("<img"));
        QVERIFY(html.contains("&lt;img"));
        auto inlineReference =
            validateAiExplanation("**Facts**: instruction `0x1000`; constant `0x28`.", context);
        QCOMPARE(inlineReference.verifiedReferences, 1);
        QCOMPARE(inlineReference.invalidReferences, 0);
        QVERIFY(aiExplanationHtml(inlineReference).contains("<b>Facts</b>"));
        QVERIFY(aiExplanationHtml(inlineReference).contains("<code><a href='ai-source:1000'>"));
        auto code = decode(QByteArray::fromHex("b80100000083f8027401c3c3"), 0x1000);
        auto block = makeAiContext(nullptr, code, 0x100a, AiScope::Block, "fixture");
        QVERIFY(block.addresses.contains(0x100a));
        QVERIFY(block.addresses.size() >
                1); // Includes block dependencies instead of an isolated instruction.
        QVERIFY(block.data.contains("control_flow"));
        Snapshot snapshot;
        snapshot.ip = 0x1000;
        snapshot.registers["rax"] = 7;
        auto observed = makeAiContext(nullptr, code, 0x1000, AiScope::Instruction, "paused", &snapshot);
        QVERIFY(observed.data.contains("observed_snapshot"));
        QVERIFY(observed.key() != context.key());
        auto other = makeAiContext(nullptr, code, 0x1005, AiScope::Instruction, "paused", &snapshot);
        QVERIFY(!other.data.contains("observed_snapshot"));
        QVERIFY_EXCEPTION_THROWN(makeAiContext(nullptr, code, 0x9999, AiScope::Block, "fixture"),
                                 std::exception);
    }
    void sseFramingAndProviderContracts() {
        SseDecoder decoder;
        QByteArray utf8 = QString::fromUtf8("data: {\"delta\":\"Ελληνικά\"}\r\n\r\n").toUtf8();
        QVector<QByteArray> events;
        for (auto c : utf8)
            events += decoder.feed(QByteArray(1, c));
        QCOMPARE(events.size(), 1);
        QCOMPARE(QJsonDocument::fromJson(events.first()).object()["delta"].toString(),
                 QString::fromUtf8("Ελληνικά"));
        QVERIFY(decoder.cleanEnd());
        SseDecoder incomplete;
        incomplete.feed("data: {}\n");
        QVERIFY(!incomplete.cleanEnd());
        SseDecoder oversized;
        QVERIFY_EXCEPTION_THROWN(oversized.feed(QByteArray(600000, 'x')), std::exception);
        ChatGptProvider provider;
        auto payload = provider.payload("account-model", smallContext());
        QVERIFY(!payload["store"].toBool(true));
        QVERIFY(payload["stream"].toBool());
        QVERIFY(payload["input"].isArray());
        QVERIFY(payload["instructions"].toString().contains("untrusted DATA"));
        for (const auto &field : {"max_output_tokens", "temperature", "previous_response_id", "tools"})
            QVERIFY(!payload.contains(field));
        QVERIFY_EXCEPTION_THROWN(LocalAiProvider(QUrl("http://remote.example:1234/v1")), std::exception);
        QVERIFY_EXCEPTION_THROWN(LocalAiProvider(QUrl("http://localhost:1234/v1")), std::exception);
        QVERIFY_EXCEPTION_THROWN(LocalAiProvider(QUrl("http://127.0.0.1:1234/v1?redirect=1")),
                                 std::exception);
        LocalAiProvider local(QUrl("http://127.0.0.1:11434/v1/"));
        QVERIFY(!local.responsesProtocol());
        QCOMPARE(local.payload("qwen3-local", smallContext())["reasoning_effort"].toString(),
                 QString("none"));
        QCOMPARE(visibleAiText("<think>internal fixture</think>Final explanation"),
                 QString("Final explanation"));
        QVERIFY(visibleAiText("<think>unfinished fixture").isEmpty());
    }
    void localStreamingCacheCancellationAndFailures() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        FixtureNetwork network;
        ChatGptAuth auth(nullptr, directory.path(), &network);
        QByteArray body = localStream("Observed fixture [0x1000].");
        bool hang = false;
        int inferenceCalls = 0, status = 200;
        network.handler = [&](const SentRequest &call) -> HttpFixture {
            if (call.request.url().path().endsWith("/models"))
                return {200, jsonBytes({{"data", QJsonArray{QJsonObject{{"id", "local-fixture"}}}}})};
            ++inferenceCalls;
            return {status, body, hang};
        };
        AiService service(nullptr, &auth, &network);
        service.configure(AiProviderKind::Local);
        QSignalSpy models(&service, &AiService::modelsReady);
        service.fetchModels();
        QTRY_COMPARE(models.size(), 1);
        service.setModel("local-fixture");
        QSignalSpy complete(&service, &AiService::completed), failed(&service, &AiService::failed);
        service.explain(smallContext());
        QTRY_COMPARE(complete.size(), 1);
        QCOMPARE(inferenceCalls, 1);
        QVERIFY(!qvariant_cast<AiExplanation>(complete.first().first()).cached);
        service.explain(smallContext());
        QCOMPARE(complete.size(), 2);
        QCOMPARE(inferenceCalls, 1);
        QVERIFY(qvariant_cast<AiExplanation>(complete.last().first()).cached);
        service.clearCache();
        body = "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n";
        service.explain(smallContext());
        QTRY_COMPARE(failed.size(), 1);
        QCOMPARE(complete.size(), 2);
        service.explain(smallContext());
        QTRY_COMPARE(failed.size(), 2);
        QCOMPARE(inferenceCalls, 3);
        hang = true;
        service.explain(smallContext());
        QVERIFY(service.busy());
        service.cancel();
        QVERIFY(!service.busy());
        hang = false;
        status = 429;
        body = "{\"error\":{\"code\":\"quota_exhausted\",\"message\":\"fixture quota\"}}";
        service.explain(smallContext());
        QTRY_COMPARE(failed.size(), 3);
        QVERIFY(failed.last().first().toString().contains("429"));
        QVERIFY(failed.last().first().toString().contains("fixture-request-id"));
        QCOMPARE(complete.size(), 2);
    }
    void chatGptStreamingRequiresCompletedEvent() {
        QTemporaryDir directory(QDir::currentPath() + "/ai-case-XXXXXX");
        AuthFixture fixture;
        ChatGptAuth auth(nullptr, directory.path(), &fixture.network);
        authorize(auth, fixture);
        FixtureNetwork inference;
        bool completeEvent = true, failAfterDelta = false;
        inference.handler = [&](const SentRequest &call) -> HttpFixture {
            if (call.request.url().path().endsWith("/models"))
                return {200, jsonBytes({{"models", QJsonArray{QJsonObject{{"slug", "account-model"},
                                                                          {"display_name", "Account model"},
                                                                          {"visibility", "list"}},
                                                              QJsonObject{{"slug", "hidden"},
                                                                          {"visibility", "hidden"}}}}})};
            QByteArray body =
                sseEvent({{"type", "response.output_text.delta"}, {"delta", "Explanation [0x1000]."}});
            if (failAfterDelta)
                body += sseEvent(
                    {{"type", "response.failed"},
                     {"response",
                      QJsonObject{
                          {"error", QJsonObject{{"code", "subscription_sharing_usage_limit_exceeded"}}}}}});
            else if (completeEvent)
                body += sseEvent(
                    {{"type", "response.completed"}, {"response", QJsonObject{{"status", "completed"}}}});
            return {200, body};
        };
        AiService service(nullptr, &auth, &inference);
        service.configure(AiProviderKind::ChatGpt);
        QSignalSpy models(&service, &AiService::modelsReady);
        service.fetchModels();
        QTRY_COMPARE(models.size(), 1);
        QCOMPARE(service.availableModels().size(), 1);
        service.setModel("account-model");
        QSignalSpy completed(&service, &AiService::completed), failed(&service, &AiService::failed);
        service.explain(smallContext());
        QTRY_COMPARE(completed.size(), 1);
        auto call = inference.sent.last();
        QCOMPARE(call.request.url(), QUrl("https://api.openai.com/v1/responses"));
        QCOMPARE(call.request.rawHeader("Authorization"), QByteArray("Bearer fixture-access-token"));
        auto payload = QJsonDocument::fromJson(call.body).object();
        QVERIFY(!payload["store"].toBool(true));
        QVERIFY(payload["stream"].toBool());
        service.clearCache();
        completeEvent = false;
        service.explain(smallContext());
        QTRY_COMPARE(failed.size(), 1);
        failAfterDelta = true;
        service.explain(smallContext());
        QTRY_COMPARE(failed.size(), 2);
        QVERIFY(failed.last().first().toString().contains("subscription_sharing_usage_limit_exceeded"));
        QCOMPARE(completed.size(), 1);
    }
};
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    app.setOrganizationName("VenorTests");
    app.setApplicationName("AiTests");
    AiTests tests;
    auto arguments = app.arguments();
    arguments << "-o" << "ai-results.txt,txt";
    return QTest::qExec(&tests, arguments);
}
#include "ai_tests.moc"
