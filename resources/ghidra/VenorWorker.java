// Local file-mailbox protocol. Never executes the analyzed program or accepts arbitrary scripts.
// @category Venor
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.block.*;
import ghidra.util.task.TaskMonitorAdapter;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class VenorWorker extends GhidraScript {
    private DecompInterface decompiler;
    private Path folder;
    private TaskMonitorAdapter task;
    private static String address(Address a) { return a == null || !a.isMemoryAddress() ? "" : "0x" + Long.toUnsignedString(a.getOffset(), 16); }
    private Address addr(String text) throws Exception {
        if (!text.matches("0x[0-9a-fA-F]{1,16}")) throw new Exception("Invalid address");
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(text.substring(2), 16));
    }
    private void write(String file, JsonObject data) throws Exception {
        Path temp = folder.resolve(file + ".tmp");
        Files.writeString(temp, new Gson().toJson(data), StandardCharsets.UTF_8);
        Files.move(temp, folder.resolve(file), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
    private DecompileResults decompile(Function f) throws Exception {
        task.checkCancelled();
        DecompileResults result = decompiler.decompileFunction(f, 45, task);
        if (!result.decompileCompleted() || result.getCCodeMarkup() == null)
            throw new Exception("Ghidra: " + result.getErrorMessage());
        return result;
    }
    private void edit(JsonObject edit) throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr(edit.get("function").getAsString()));
        if (f == null) throw new Exception("Edited function no longer exists");
        String kind = edit.get("kind").getAsString(), text = edit.get("text").getAsString();
        if (text.length() > 4096) throw new Exception("Edit exceeds 4096 characters");
        if (kind.equals("function_name")) {
            if (!text.matches("[A-Za-z_][A-Za-z0-9_]{0,127}")) throw new Exception("Invalid function name");
            f.setName(text, SourceType.USER_DEFINED);
        } else if (kind.equals("signature")) {
            var signature = CParserUtils.parseSignature((DataTypeManagerService)null, currentProgram, text, false);
            if (signature == null) throw new Exception("Cannot parse the C function signature");
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), signature, SourceType.USER_DEFINED);
            if (!cmd.applyTo(currentProgram, task)) throw new Exception(cmd.getStatusMsg());
        } else if (kind.equals("variable_name") || kind.equals("variable_type")) {
            DecompileResults result = decompile(f);
            HighSymbol chosen = null;
            Iterator<HighSymbol> symbols = result.getHighFunction().getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                if (symbol.getStorage().toString().equals(edit.get("storage").getAsString()) &&
                    symbol.getName().equals(edit.get("previous").getAsString())) { chosen = symbol; break; }
            }
            if (chosen == null) throw new Exception("Variable identity changed; review the edit against current analysis");
            if (kind.equals("variable_name")) {
                if (!text.matches("[A-Za-z_][A-Za-z0-9_]{0,127}")) throw new Exception("Invalid variable name");
                HighFunctionDBUtil.updateDBVariable(chosen, text, null, SourceType.USER_DEFINED);
            } else {
                var signature = CParserUtils.parseSignature((DataTypeManagerService)null, currentProgram, text + " __venor_type(void)", false);
                if (signature == null) throw new Exception("Unknown C type");
                HighFunctionDBUtil.updateDBVariable(chosen, null, signature.getReturnType(), SourceType.USER_DEFINED);
            }
        } else throw new Exception("Unsupported analysis edit");
        decompiler.flushCache();
    }
    private JsonObject export(Function f) throws Exception {
        DecompileResults result = decompile(f);
        JsonObject out = new JsonObject();
        out.addProperty("entry", address(f.getEntryPoint())); out.addProperty("name", f.getName());
        out.addProperty("signature", result.getDecompiledFunction().getSignature());
        out.addProperty("warning", result.getErrorMessage());
        out.addProperty("return_type", result.getHighFunction().getFunctionPrototype().getReturnType().getDisplayName());
        JsonArray variables = new JsonArray();
        Iterator<HighSymbol> symbols = result.getHighFunction().getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next(); JsonObject v = new JsonObject();
            v.addProperty("name", s.getName()); v.addProperty("storage", s.getStorage().toString());
            v.addProperty("type", s.getDataType().getDisplayName()); v.addProperty("parameter", s.isParameter());
            variables.add(v);
        }
        out.add("variables", variables);
        StringBuilder code = new StringBuilder(); JsonArray tokens = new JsonArray();
        PrettyPrinter printer = new PrettyPrinter(f, result.getCCodeMarkup(), null);
        for (ClangLine line : printer.getLines()) {
            code.append(line.getIndentString());
            for (ClangToken t : line.getAllTokens()) {
                JsonObject token = new JsonObject(); token.addProperty("start", code.length()); token.addProperty("length", t.getText().length());
                token.addProperty("syntax", t.getSyntaxType());
                Address source = t.getMinAddress();
                if (source == null && t.getPcodeOp() != null) source = t.getPcodeOp().getSeqnum().getTarget();
                token.addProperty("address", address(source));
                if (t instanceof ClangFuncNameToken) {
                    Function target = DecompilerUtils.getFunction(currentProgram, (ClangFuncNameToken)t);
                    if (target != null) token.addProperty("target", address(target.getEntryPoint()));
                }
                tokens.add(token); code.append(t.getText());
            }
            code.append('\n');
        }
        if (code.length() > 1024 * 1024 || tokens.size() > 100000) throw new Exception("Function exceeds pseudocode output limit (1 MiB / 100,000 tokens)");
        out.addProperty("code", code.toString()); out.add("tokens", tokens);
        JsonArray assembly = new JsonArray(), refs = new JsonArray(), blocks = new JsonArray();
        InstructionIterator ins = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (ins.hasNext()) {
            task.checkCancelled(); Instruction i = ins.next();
            if (assembly.size() >= 30000) throw new Exception("Function exceeds 30,000 instruction limit");
            JsonObject row = new JsonObject(); row.addProperty("address", address(i.getAddress()));
            row.addProperty("bytes", HexFormat.of().formatHex(i.getBytes())); assembly.add(row);
            for (Reference ref : i.getReferencesFrom()) {
                if (refs.size() >= 30000) break;
                JsonObject r = new JsonObject(); r.addProperty("from", address(ref.getFromAddress())); r.addProperty("to", address(ref.getToAddress()));
                r.addProperty("kind", ref.getReferenceType().toString());
                r.addProperty("address_space", ref.getToAddress().getAddressSpace().getName());
                Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
                if (symbol != null) r.addProperty("name", symbol.getName(true));
                Function target = currentProgram.getFunctionManager().getReferencedFunction(ref.getToAddress());
                if (target != null) {
                    if (target.isThunk()) target = target.getThunkedFunction(true);
                    if (target != null) r.addProperty("signature", target.getPrototypeString(false, false));
                }
                Data d = getDataAt(ref.getToAddress());
                if (d != null && d.hasStringValue()) r.addProperty("string", d.getValue().toString().substring(0, Math.min(1024, d.getValue().toString().length())));
                refs.add(r);
            }
        }
        out.add("assembly", assembly); out.add("references", refs);
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        CodeBlockIterator iter = model.getCodeBlocksContaining(f.getBody(), task);
        while (iter.hasNext()) {
            CodeBlock block = iter.next(); JsonObject b = new JsonObject();
            b.addProperty("start", address(block.getMinAddress())); b.addProperty("end", address(block.getMaxAddress()));
            JsonArray next = new JsonArray(); CodeBlockReferenceIterator dest = block.getDestinations(task);
            while (dest.hasNext()) next.add(address(dest.next().getDestinationAddress()));
            b.add("successors", next); blocks.add(b);
        }
        out.add("blocks", blocks);
        JsonArray callers = new JsonArray();
        ReferenceIterator calls = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while (calls.hasNext() && callers.size() < 512) {
            Reference r = calls.next(); JsonObject c = new JsonObject(); c.addProperty("from", address(r.getFromAddress()));
            c.addProperty("kind", r.getReferenceType().toString()); callers.add(c);
        }
        out.add("callers", callers); return out;
    }
    protected void run() throws Exception {
        // GhidraScript normally wraps run() in one outer transaction. Close it so each
        // request can truly roll back; nested transactions alone would leak prior edits.
        end(true);
        folder = Paths.get(getScriptArgs()[0]);
        decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new Exception(decompiler.getLastMessage());
        JsonObject ready = new JsonObject(); ready.addProperty("schema", 1); write("ready.json", ready);
        try {
            while (!Files.exists(folder.resolve("stop"))) {
                Path request = folder.resolve("request.json");
                if (!Files.exists(request)) { Thread.sleep(30); continue; }
                JsonObject out = new JsonObject();
                int transaction = currentProgram.startTransaction("Transient Venor analysis edits");
                task = new TaskMonitorAdapter(true);
                Timer canceller = new Timer(true);
                canceller.schedule(new TimerTask() { public void run() { if (Files.exists(folder.resolve("cancel"))) task.cancel(); } }, 30, 30);
                try {
                    if (Files.size(request) > 1024 * 1024) throw new Exception("Request exceeds 1 MiB");
                    JsonObject req = JsonParser.parseString(Files.readString(request, StandardCharsets.UTF_8)).getAsJsonObject();
                    out.addProperty("id", req.get("id").getAsString());
                    if (req.get("schema").getAsInt() != 1) throw new Exception("Unsupported protocol");
                    JsonArray edits = req.getAsJsonArray("edits");
                    if (edits.size() > 1000) throw new Exception("Too many analysis edits");
                    for (JsonElement e : edits) edit(e.getAsJsonObject());
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(addr(req.get("address").getAsString()));
                    if (f == null || f.isExternal()) throw new Exception("Ghidra did not recover a local function containing this address");
                    out.add("result", export(f));
                } catch (Exception e) { out.addProperty("error", e.toString()); }
                finally {
                    canceller.cancel(); currentProgram.endTransaction(transaction, false); currentProgram.flushEvents(); decompiler.flushCache();
                    Files.deleteIfExists(request); Files.deleteIfExists(folder.resolve("cancel"));
                }
                write("response.json", out);
            }
        } finally { decompiler.dispose(); }
    }
}
