#pragma once
#include "ai.h"
#include <QtTest>
#include <cstring>

struct HttpFixture {
    int status = 200;
    QByteArray body;
    bool hanging = false;
    int delay = 1;
};
struct SentRequest {
    QNetworkAccessManager::Operation method;
    QNetworkRequest request;
    QByteArray body;
};
class FixtureReply : public QNetworkReply {
    QByteArray content;
    qint64 position = 0;
    bool available = false;

  public:
    FixtureReply(QNetworkRequest request, HttpFixture fixture, QObject *parent)
        : QNetworkReply(parent), content(fixture.body) {
        setRequest(request);
        setUrl(request.url());
        open(QIODevice::ReadOnly | QIODevice::Unbuffered);
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, fixture.status);
        setRawHeader("x-request-id", "fixture-request-id");
        if (!fixture.hanging)
            QTimer::singleShot(fixture.delay, this, [this, fixture] {
                if (isFinished())
                    return;
                available = true;
                if (fixture.status >= 400)
                    setError(QNetworkReply::ContentAccessDenied, "fixture HTTP failure");
                emit readyRead();
                if (isFinished())
                    return;
                setFinished(true);
                emit finished();
            });
    }
    void abort() override {
        if (isFinished())
            return;
        setError(QNetworkReply::OperationCanceledError, "fixture cancelled");
        setFinished(true);
        emit finished();
    }
    qint64 bytesAvailable() const override {
        return (available ? content.size() - position : 0) + QNetworkReply::bytesAvailable();
    }
    bool isSequential() const override {
        return true;
    }

  protected:
    qint64 readData(char *destination, qint64 size) override {
        if (!available)
            return 0;
        auto count = std::min(size, qint64(content.size()) - position);
        if (!count)
            return -1;
        std::memcpy(destination, content.constData() + position, size_t(count));
        position += count;
        return count;
    }
};
class FixtureNetwork : public QNetworkAccessManager {
  public:
    QVector<SentRequest> sent;
    std::function<HttpFixture(const SentRequest &)> handler;
    explicit FixtureNetwork(QObject *parent = nullptr) : QNetworkAccessManager(parent) {}

  protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &request, QIODevice *outgoing) override {
        SentRequest call{op, request, outgoing ? outgoing->readAll() : QByteArray()};
        sent << call;
        return new FixtureReply(request, handler ? handler(call) : HttpFixture{500, "{}"}, this);
    }
};
inline QByteArray jsonBytes(QJsonObject object) {
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}
inline QByteArray sseEvent(QJsonObject object) {
    return "data: " + jsonBytes(object) + "\r\n\r\n";
}
inline QByteArray localStream(QString text) {
    return sseEvent({{"choices", QJsonArray{QJsonObject{{"delta", QJsonObject{{"content", text}}},
                                                        {"finish_reason", QJsonValue()}}}}}) +
           sseEvent(
               {{"choices", QJsonArray{QJsonObject{{"delta", QJsonObject()}, {"finish_reason", "stop"}}}}}) +
           "data: [DONE]\n\n";
}
inline vnr::AiContext smallContext() {
    vnr::Binary binary;
    binary.hash = "test-binary-sha256";
    binary.functions = {{0x1000, "entry", "fixture"}};
    auto code = vnr::decode(QByteArray::fromHex("b80100000083f8027401c3c3"), 0x1000);
    return vnr::makeAiContext(&binary, code, 0x1000, vnr::AiScope::Function, "Static fixture bytes");
}
