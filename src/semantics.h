#pragma once
#include "types.h"
#include <optional>

namespace vnr {
struct MeaningArgument {
    QString name, value, source;
    QVector<quint64> evidence;
};
struct MeaningStep {
    quint64 address = 0;
    QString title, summary;
    QVector<MeaningArgument> arguments;
    QVector<quint64> evidence;
    bool call = false, condition = false, preparation = false, boundary = false;
};
struct MeaningUnit {
    QString title, summary;
    QVector<int> steps;
    QVector<MeaningArgument> arguments;
    QVector<quint64> evidence;
};
struct MeaningDocument {
    QVector<MeaningStep> steps;
    QVector<MeaningUnit> units;
    QMap<quint64, int> unitAt;
};
// Bounded, block-local abstract interpretation. No execution, network or inference service.
MeaningDocument analyzeMeaning(const QVector<Instruction> &, const Binary * = nullptr);
std::optional<quint64> observedRegister(QString, const QMap<QString, quint64> &);
QString observedOperands(const Instruction &, const QMap<QString, quint64> &,
                         const std::function<QByteArray(quint64, int)> &);
QVector<MeaningArgument> recordedApiArguments(const Event &);
} // namespace vnr
