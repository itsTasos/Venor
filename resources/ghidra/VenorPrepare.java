// @category Venor
import ghidra.app.script.GhidraScript;
public class VenorPrepare extends GhidraScript {
    protected void run() throws Exception {
        // Keep analysis local: no PDB lookup or user-selected script execution.
        setAnalysisOption(currentProgram, "PDB Universal", "false");
        setAnalysisOption(currentProgram, "PDB", "false");
    }
}
