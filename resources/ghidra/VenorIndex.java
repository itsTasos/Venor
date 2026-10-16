// Export the analyzed program once. analyzeHeadless saves the project after this script exits.
// @category Venor
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class VenorIndex extends HeadlessScript {
    static String address(Address a) { return a == null ? "" : "0x" + Long.toUnsignedString(a.getOffset(), 16); }
    protected void run() throws Exception {
        JsonObject root = new JsonObject();
        root.addProperty("schema", 1);
        root.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        root.addProperty("base", address(currentProgram.getImageBase()));
        root.addProperty("language", currentProgram.getLanguageID().toString());
        JsonArray functions = new JsonArray();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Function f = iter.next();
            if (f.isExternal()) continue;
            if (functions.size() >= 200000) throw new Exception("Function index exceeds 200,000 entries");
            JsonObject item = new JsonObject();
            item.addProperty("entry", address(f.getEntryPoint()));
            item.addProperty("name", f.getName());
            item.addProperty("signature", f.getPrototypeString(false, false));
            JsonArray ranges = new JsonArray();
            for (AddressRange range : f.getBody().getAddressRanges()) {
                JsonArray pair = new JsonArray(); pair.add(address(range.getMinAddress())); pair.add(address(range.getMaxAddress()));
                ranges.add(pair);
            }
            item.add("ranges", ranges); functions.add(item);
        }
        root.add("functions", functions);
        Path output = Paths.get(getScriptArgs()[0]);
        Files.writeString(output, new Gson().toJson(root), StandardCharsets.UTF_8);
    }
}
