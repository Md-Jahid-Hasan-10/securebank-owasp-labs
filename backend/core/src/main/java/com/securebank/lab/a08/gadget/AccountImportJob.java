package com.securebank.lab.a08.gadget;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The gadget class for Lab 20's deserialization RCE.
 *
 * <p>Historically this role was played by
 * {@code org.apache.commons.collections.functors.InvokerTransformer} — the classic
 * Jackson + commons-collections gadget chain. Jackson 2.17 added a hard-coded deny
 * list in {@code BeanDeserializerFactory} that refuses to instantiate known-dangerous
 * classes such as {@code InvokerTransformer}, regardless of the
 * {@code PolymorphicTypeValidator} that is configured. The lesson is unchanged: a
 * deserialiser that lets the document choose the class is a code execution
 * primitive. The library just moved the goalposts, so the lab ships its own gadget
 * to demonstrate the same class of bug.</p>
 *
 * <p>The class looks like a harmless domain object — a scheduled "account import
 * job" — but it carries a side effect in its creator constructor. Jackson
 * instantiates the class named by the document's {@code @class} property while
 * reading the document, so the side effect fires during deserialisation, before any
 * business logic runs.</p>
 */
public class AccountImportJob {

    /** The command to run. Supplied by the attacker in the document. */
    private final String command;

    /** The captured output of the command, surfaced back to the attacker. */
    private String output;

    /**
     * The creator constructor is the gadget.
     *
     * <p>VULN: [A08-Lab20] Insecure Deserialization - the creator has a side
     * effect: it runs whatever command the document asked for. Because the
     * deserialiser is allowed to instantiate an arbitrary class named in the
     * document, reaching this constructor IS the code execution primitive.</p>
     *
     * <p>FIX:  this class must not exist in a real application. The fix is at the
     * deserialiser: never let an untrusted document select the class to
     * instantiate. Parse into a concrete type, or use a JsonTypeInfo with a closed
     * allowlist of subtypes.</p>
     */
    @JsonCreator
    public AccountImportJob(@JsonProperty("command") String command) {
        this.command = command;
        if (command != null && !command.isBlank()) {
            this.output = run(command);
        }
    }

    public String getCommand() {
        return command;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    /**
     * Runs a shell command and returns its output.
     *
     * <p>VULN: [A08-Lab20] arbitrary command execution as the service user.</p>
     */
    private static String run(String command) {
        try {
            ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
            builder.redirectErrorStream(true);
            Process process = builder.start();

            String result;
            try (InputStream in = process.getInputStream()) {
                result = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            process.waitFor();
            return result.trim();
        } catch (IOException | InterruptedException e) {
            return "command failed: " + e.getMessage();
        }
    }

    /**
     * A helper used by the walkthrough to confirm that the gadget class is reachable.
     */
    public List<String> knownGadgets() {
        List<String> gadgets = new ArrayList<>();
        gadgets.add("com.securebank.lab.a08.gadget.AccountImportJob");
        return gadgets;
    }
}
