#include "ai.h"
#include "semantics.h"
#include <algorithm>
#include <stdexcept>

namespace vnr {
static QRegularExpression sourceReferences() {
    return QRegularExpression(
        "(?<![A-Za-z0-9_])(?:\\[(0[xX][0-9a-fA-F]{1,16})\\]|(0[xX][0-9a-fA-F]{1,16}))(?![A-Za-z0-9_])");
}
QByteArray AiContext::key() const {
    return QCryptographicHash::hash(serialized() + "venor-explanation-v2", QCryptographicHash::Sha256);
}
AiContext makeAiContext(const Binary *binary, QVector<Instruction> code, quint64 selection, AiScope scope,
                        QString provenance, const Snapshot *snapshot, const Event *event,
                        const DecompiledFunction *decompiled) {
    auto found =
        std::find_if(code.begin(), code.end(), [selection](const auto &i) { return i.address == selection; });
    if (found == code.end())
        throw std::runtime_error("Select a decoded instruction before requesting an explanation");
    int selected = int(found - code.begin());
    int originalCount = code.size();
    QVector<Instruction> full = code;
    QSet<int> chosen;
    QJsonArray blockGraph;
    int selectedFirst = selected, selectedLast = selected;
    {
        QSet<quint64> leaders;
        for (int n = 0; n < code.size(); ++n) {
            if (code[n].branch)
                leaders.insert(code[n].target);
            if ((code[n].branch || code[n].terminal) && n + 1 < code.size())
                leaders.insert(code[n + 1].address);
            if (n && code[n - 1].address + quint64(code[n - 1].size) != code[n].address)
                leaders.insert(code[n].address);
        }
        leaders.insert(code.first().address);
        while (selectedFirst > 0 && !leaders.contains(code[selectedFirst].address))
            --selectedFirst;
        while (selectedLast + 1 < code.size() && !code[selectedLast].branch && !code[selectedLast].terminal &&
               !leaders.contains(code[selectedLast + 1].address))
            ++selectedLast;
        for (int n = 0; n < code.size();) {
            int end = n;
            while (end + 1 < code.size() && !code[end].branch && !code[end].terminal &&
                   !leaders.contains(code[end + 1].address))
                ++end;
            QJsonArray successors;
            if (code[end].branch && code[end].target)
                successors << hex(code[end].target);
            if (!code[end].terminal && end + 1 < code.size())
                successors << hex(code[end + 1].address);
            blockGraph << QJsonObject{{"start", hex(code[n].address)},
                                      {"last_instruction", hex(code[end].address)},
                                      {"successors", successors}};
            n = end + 1;
        }
    }
    if (scope == AiScope::Function && code.size() <= 256) {
        for (int n = 0; n < code.size(); ++n)
            chosen.insert(n);
    } else {
        for (int n = std::max(selectedFirst, selected - 96); n <= std::min(selectedLast, selected + 96); ++n)
            chosen.insert(n);
        for (int n = std::max(0, selectedFirst - 12);
             n <= std::min(int(code.size()) - 1, selectedLast + 12) && chosen.size() < 224; ++n)
            chosen.insert(n);
        if (scope == AiScope::Function) {
            for (int n = 0; n < std::min(16, int(code.size())); ++n)
                chosen.insert(n);
            for (int n = 0; n < code.size() && chosen.size() < 256; ++n)
                if (code[n].call || code[n].branch || code[n].terminal)
                    chosen.insert(n);
        }
    }
    code.clear();
    for (int n = 0; n < full.size(); ++n)
        if (chosen.contains(n))
            code << full[n];
    AiContext context;
    QJsonArray instructions, edges, metadata, functions;
    QMultiMap<quint64, quint64> referencedTargets;
    for (const auto &i : code) {
        context.addresses.insert(i.address);
        instructions << QJsonObject{{"address", hex(i.address)},
                                    {"bytes", QString::fromLatin1(i.bytes.toHex(' '))},
                                    {"assembly", i.text},
                                    {"decoded", i.valid},
                                    {"instruction_fact", i.fact},
                                    {"local_deduction", i.derived},
                                    {"unknown", i.unknown},
                                    {"reads", QJsonArray::fromStringList(i.reads)},
                                    {"writes", QJsonArray::fromStringList(i.writes)}};
    }
    for (const auto &i : code) {
        if ((i.branch || i.call) && i.target)
            edges << QJsonObject{{"from", hex(i.address)},
                                 {"to", hex(i.target)},
                                 {"kind", i.call          ? "call"
                                          : i.conditional ? "conditional_branch"
                                                          : "branch"},
                                 {"destination_in_context", context.addresses.contains(i.target)}};
        if (i.target)
            referencedTargets.insert(i.target, i.address);
    }
    if (binary)
        for (const auto *rows : {&binary->imports, &binary->exports, &binary->strings}) {
            for (const auto &r : *rows)
                if (referencedTargets.contains(r.address)) {
                    for (auto source : referencedTargets.values(r.address))
                        metadata << QJsonObject{{"source_instruction", hex(source)},
                                                {"address", hex(r.address)},
                                                {"name", r.name.left(512)},
                                                {"detail", r.detail.left(512)},
                                                {"provenance", "static file metadata; untrusted content"}};
                }
        }
    if (binary)
        for (const auto &f : binary->functions)
            if (context.addresses.contains(f.address)) {
                functions << QJsonObject{
                    {"address", hex(f.address)},
                    {"name", f.name.left(256)},
                    {"provenance", "static function candidate, not proof of complete recovery"}};
                context.functionStarts.insert(f.address);
            }
    context.data = {{"schema", "venor.analysis-context.v2"},
                    {"architecture", "Windows x64"},
                    {"scope", scope == AiScope::Instruction ? "instruction"
                              : scope == AiScope::Block     ? "basic block"
                                                            : "function window"},
                    {"selection", hex(selection)},
                    {"provenance", provenance},
                    {"coverage", decompiled
                                     ? "Recovered function; Ghidra reconstruction and inferred types, not "
                                       "original source. Static flow does not prove execution."
                                     : "Fallback bounded assembly window; complete function recovery and "
                                       "pseudocode are unavailable. Static flow does not prove execution."},
                    {"containing_block", QJsonObject{{"start", hex(full[selectedFirst].address)},
                                                     {"last_instruction", hex(full[selectedLast].address)}}},
                    {"control_flow", blockGraph},
                    {"omitted_instruction_count", originalCount - int(code.size())},
                    {"binary_sha256", binary ? binary->hash : QString()},
                    {"instructions", instructions},
                    {"decoded_edges", edges},
                    {"referenced_static_metadata", metadata},
                    {"function_candidates", functions}};
    QJsonArray derived;
    const auto meaning = analyzeMeaning(code, binary);
    for (const auto &unit : meaning.units) {
        QJsonArray evidence, arguments;
        for (auto address : unit.evidence)
            evidence << hex(address);
        for (const auto &a : unit.arguments) {
            QJsonArray sources;
            for (auto address : a.evidence)
                sources << hex(address);
            arguments << QJsonObject{
                {"name", a.name}, {"value", a.value}, {"source", a.source}, {"evidence", sources}};
        }
        derived << QJsonObject{{"title", unit.title},
                               {"summary", unit.summary},
                               {"arguments", arguments},
                               {"evidence", evidence},
                               {"provenance", "deterministic local interpretation; not runtime observation"}};
    }
    context.data["deterministic_interpretation"] = derived;
    const QMap<QString, quint64> *registers = nullptr;
    quint64 ip = 0;
    if (event) {
        registers = &event->registers;
        ip = event->ip;
    } else if (snapshot) {
        registers = &snapshot->registers;
        ip = snapshot->ip;
    }
    if (registers && selection == ip) {
        QJsonObject values;
        for (auto it = registers->begin(); it != registers->end(); ++it)
            values[it.key()] = hex(it.value());
        QJsonObject observed{{"ip", hex(ip)},
                             {"registers", values},
                             {"provenance", event ? snapshot
                                                        ? "captured event matching current paused snapshot"
                                                        : "saved event; historical"
                                                  : "current paused snapshot"},
                             {"applies_only_at_ip", true}};
        if (event) {
            observed["time"] = event->time;
            observed["thread"] = qint64(event->thread);
            observed["event_type"] = event->type;
            observed["api"] = event->api;
            QJsonArray arguments;
            for (const auto &a : event->arguments)
                arguments << QJsonObject{
                    {"name", a.name}, {"value", a.value.left(1024)}, {"source", a.source}};
            observed["captured_api_arguments"] = arguments;
        } else {
            observed["thread"] = qint64(snapshot->thread);
            observed["reason"] = snapshot->reason.left(1024);
        }
        context.data["observed_snapshot"] = observed;
    }
    if (decompiled) {
        auto allVariables = decompiled->data["variables"].toArray();
        QJsonArray variables, calls, callers, mappings, signatures;
        for (int n = 0; n < std::min(256, int(allVariables.size())); ++n)
            variables << allVariables[n];
        int omittedReferences = 0;
        for (auto value : decompiled->data["references"].toArray()) {
            auto r = value.toObject();
            if (calls.size() >= 128 ||
                (scope != AiScope::Function &&
                 !context.addresses.contains(r["from"].toString().mid(2).toULongLong(nullptr, 16)))) {
                ++omittedReferences;
                continue;
            }
            calls << r;
            for (const auto &api : apiCatalog())
                if (r["name"].toString().endsWith(api.symbol.section('!', -1), Qt::CaseInsensitive))
                    signatures << QJsonObject{
                        {"symbol", api.symbol},
                        {"arguments", QJsonArray::fromStringList(api.args)},
                        {"purpose", api.purpose},
                        {"limitations", api.limits},
                        {"provenance",
                         "curated Windows API catalogue; calls are requests, not confirmed effects"}};
        }
        auto allCallers = decompiled->data["callers"].toArray();
        for (int n = 0; n < std::min(64, int(allCallers.size())); ++n)
            callers << allCallers[n];
        int start = 0, length = std::min(49152, int(decompiled->code.size()));
        if (decompiled->code.size() > length) {
            for (auto value : decompiled->data["tokens"].toArray()) {
                auto t = value.toObject();
                if (t["address"].toString().mid(2).toULongLong(nullptr, 16) == selection) {
                    start = std::clamp(t["start"].toInt() - 16384, 0, int(decompiled->code.size()) - length);
                    break;
                }
            }
        }
        int omittedMappings = 0;
        for (auto value : decompiled->data["tokens"].toArray()) {
            auto t = value.toObject();
            auto a = t["address"].toString().mid(2).toULongLong(nullptr, 16);
            if (!a || t["start"].toInt() < start || t["start"].toInt() >= start + length)
                continue;
            if (mappings.size() >= 512) {
                ++omittedMappings;
                continue;
            }
            mappings << QJsonObject{
                {"start_utf16", t["start"]}, {"length", t["length"]}, {"address", t["address"]}};
            context.addresses.insert(a);
        }
        context.functionStarts.insert(decompiled->entry);
        QJsonArray candidates = context.data["function_candidates"].toArray();
        candidates << QJsonObject{{"address", hex(decompiled->entry)},
                                  {"name", decompiled->name},
                                  {"provenance", "Ghidra recovered function"}};
        context.data["function_candidates"] = candidates;
        context.data["decompilation"] = QJsonObject{
            {"provenance",
             "Ghidra static reconstruction; inferred names/types may be wrong; not original source"},
            {"entry", hex(decompiled->entry)},
            {"signature", decompiled->signature},
            {"return_type", decompiled->data["return_type"]},
            {"variables_and_parameters", variables},
            {"omitted_variables", allVariables.size() - variables.size()},
            {"warning", decompiled->data["warning"]},
            {"analysis_warning", decompiled->data["analysis_warning"]},
            {"pseudocode", decompiled->code.mid(start, length)},
            {"pseudocode_start_utf16", start},
            {"omitted_pseudocode_characters", decompiled->code.size() - length},
            {"source_mappings", mappings},
            {"omitted_source_mappings", omittedMappings},
            {"references", calls},
            {"omitted_references", omittedReferences},
            {"callers", callers},
            {"omitted_callers", allCallers.size() - callers.size()}};
        context.data["known_api_signatures"] = signatures;
        context.data["control_flow"] = decompiled->data["blocks"];
    }
    auto allBlocks = context.data["control_flow"].toArray();
    if (allBlocks.size() > 256) {
        int selectedBlock = 0;
        for (int n = 0; n < allBlocks.size(); ++n) {
            auto b = allBlocks[n].toObject();
            auto start = b["start"].toString().mid(2).toULongLong(nullptr, 16);
            if (start <= selection)
                selectedBlock = n;
        }
        int begin = std::clamp(selectedBlock - 96, 0, int(allBlocks.size()) - 256);
        QJsonArray retained;
        for (int n = begin; n < begin + 256; ++n)
            retained << allBlocks[n];
        context.data["control_flow"] = retained;
        context.data["omitted_block_count"] = allBlocks.size() - retained.size();
    }
    // Prioritize actual code and reconstruction over repeated prose when the byte budget is reached.
    constexpr int budget = 192 * 1024;
    if (context.serialized().size() > budget) {
        context.data.remove("deterministic_interpretation");
        context.data["omitted_deterministic_interpretation"] =
            "Removed to retain instruction and pseudocode evidence within 192 KiB";
        auto rows = context.data["instructions"].toArray();
        for (int n = 0; n < rows.size(); ++n) {
            auto r = rows[n].toObject();
            r.remove("instruction_fact");
            r.remove("local_deduction");
            r.remove("unknown");
            rows[n] = r;
        }
        context.data["instructions"] = rows;
        context.data["omitted_instruction_prose"] = true;
    }
    if (context.serialized().size() > budget && context.data.contains("decompilation")) {
        auto d = context.data["decompilation"].toObject();
        for (const auto &pair :
             {qMakePair(QString("references"), QString("omitted_references")),
              qMakePair(QString("source_mappings"), QString("omitted_source_mappings")),
              qMakePair(QString("variables_and_parameters"), QString("omitted_variables"))}) {
            auto values = d[pair.first].toArray();
            int retain = pair.first == "source_mappings" ? 128 : 32;
            int removed = std::max(0, int(values.size()) - retain);
            while (values.size() > retain)
                values.removeLast();
            d[pair.first] = values;
            d[pair.second] = d[pair.second].toInt() + removed;
        }
        context.data["decompilation"] = d;
        auto blocks = context.data["control_flow"].toArray();
        int removed = std::max(0, int(blocks.size()) - 64);
        while (blocks.size() > 64)
            blocks.removeLast();
        context.data["control_flow"] = blocks;
        context.data["omitted_block_count"] = context.data["omitted_block_count"].toInt() + removed;
    }
    if (context.serialized().size() > budget)
        throw std::runtime_error(
            "Recovered metadata exceeds the 192 KiB consent budget. Explain a smaller block or instruction.");
    return context;
}
QString visibleAiText(QString text) {
    auto trimmed = text.trimmed();
    if (trimmed.startsWith("<think>")) {
        auto end = trimmed.indexOf("</think>");
        return end < 0 ? QString() : trimmed.mid(end + 8).trimmed();
    }
    if (!trimmed.isEmpty() && QString("<think>").startsWith(trimmed))
        return {};
    return text;
}
AiExplanation validateAiExplanation(QString text, const AiContext &context) {
    text = visibleAiText(std::move(text));
    if (text.isEmpty() || text.size() > 256 * 1024)
        throw std::runtime_error("Empty or oversized AI explanation");
    AiExplanation answer;
    answer.context = context;
    int start = text.indexOf("<venor-suggestions>");
    if (start >= 0) {
        int end = text.indexOf("</venor-suggestions>", start);
        if (end > start) {
            auto raw = text.mid(start + 19, end - start - 19).trimmed().toUtf8();
            QJsonParseError error;
            auto root = QJsonDocument::fromJson(raw, &error);
            if (error.error != QJsonParseError::NoError || !root.isObject())
                ++answer.rejectedSuggestions;
            else {
                auto array = root.object()["suggestions"].toArray();
                for (int n = 0; n < array.size(); ++n) {
                    auto s = array[n].toObject();
                    bool ok = false;
                    QString rawAddress = s["address"].toString();
                    quint64 address =
                        rawAddress.startsWith("0x") ? rawAddress.mid(2).toULongLong(&ok, 16) : 0;
                    QString kind = s["kind"].toString(), value = s["text"].toString().trimmed();
                    bool name = kind == "function_name" || kind == "variable_name";
                    bool valid =
                        n < 12 && ok && context.addresses.contains(address) && !value.isEmpty() &&
                        value.size() <= 2000 && (kind == "comment" || name) &&
                        (!name ||
                         QRegularExpression("^[A-Za-z_][A-Za-z0-9_]{0,99}$").match(value).hasMatch()) &&
                        (kind != "function_name" || context.functionStarts.contains(address)) &&
                        (kind != "variable_name" ||
                         (!s["variable"].toString().isEmpty() && s["variable"].toString().size() <= 64));
                    if (valid)
                        answer.suggestions << AiSuggestion{kind, value, s["variable"].toString(), address};
                    else
                        ++answer.rejectedSuggestions;
                }
            }
        } else
            ++answer.rejectedSuggestions;
        text.truncate(start);
    }
    answer.text = text.trimmed();
    if (answer.text.isEmpty())
        throw std::runtime_error("The provider returned no readable explanation");
    auto references = sourceReferences().globalMatch(answer.text);
    while (references.hasNext()) {
        auto reference = references.next();
        auto raw = reference.captured(1).isEmpty() ? reference.captured(2) : reference.captured(1);
        auto at = raw.mid(2).toULongLong(nullptr, 16);
        if (context.addresses.contains(at))
            ++answer.verifiedReferences;
        else if (!reference.captured(1).isEmpty())
            ++answer.invalidReferences;
    }
    return answer;
}
QString aiExplanationHtml(const AiExplanation &answer) {
    QString html = "<p><b>AI-generated interpretation · review against assembly</b><br>" +
                   answer.provider.toHtmlEscaped() + " · " + answer.model.toHtmlEscaped() +
                   (answer.cached ? " · cached" : "") + "</p><p><b>Source:</b> " +
                   answer.context.data["provenance"].toString().toHtmlEscaped() + "</p>";
    const auto selection = answer.context.data["selection"].toString().mid(2).toULongLong(nullptr, 16);
    if (answer.context.addresses.contains(selection))
        html += "<p>Submitted selection: <a href='ai-source:" + QString::number(selection, 16) + "'>" +
                hex(selection) + "</a></p>";
    auto expression = sourceReferences();
    auto matches = expression.globalMatch(answer.text);
    qsizetype position = 0;
    while (matches.hasNext()) {
        auto m = matches.next();
        html += answer.text.mid(position, m.capturedStart() - position).toHtmlEscaped().replace('\n', "<br>");
        auto raw = m.captured(1).isEmpty() ? m.captured(2) : m.captured(1);
        auto address = raw.mid(2).toULongLong(nullptr, 16);
        html += answer.context.addresses.contains(address)
                    ? "<a href='ai-source:" + QString::number(address, 16) + "'>" +
                          m.captured().toHtmlEscaped() + "</a>"
                    : m.captured().toHtmlEscaped() +
                          (m.captured(1).isEmpty() ? QString() : " <b>(unverified reference)</b>");
        position = m.capturedEnd();
    }
    html += answer.text.mid(position).toHtmlEscaped().replace('\n', "<br>");
    // A deliberately small Markdown subset: all model HTML was already escaped.
    html.replace(QRegularExpression("\\*\\*([^*]+)\\*\\*"), "<b>\\1</b>");
    html.replace(QRegularExpression("`([^`]+)`"), "<code>\\1</code>");
    html += "<hr><p>Links validate membership in the submitted context, not the correctness of an AI claim. "
            "No target actions or annotations are applied automatically.</p>";
    if (answer.rejectedSuggestions)
        html += "<p>Invalid or unsupported suggestions were discarded.</p>";
    return html;
}
} // namespace vnr
