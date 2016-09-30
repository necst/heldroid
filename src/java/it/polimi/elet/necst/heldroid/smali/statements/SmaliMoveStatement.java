package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliMoveStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "move";
    private static final Pattern CALL_PATTERN = Pattern.compile("move([\\/\\-\\w\\d]*)\\s+([pv]\\d+)\\s*,\\s*([pv]\\d+)");

    private static final int QUALIFIER_GROUP = 1;
    private static final int DESTINATION_GROUP = 2;
    private static final int SOURCE_GROUP = 3;

    private String qualifier;
    private String destination;
    private String source;

    private SmaliMoveStatement() { }

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliMoveStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse move statement: " + codeLine);

        SmaliMoveStatement result = new SmaliMoveStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);
        result.destination = matcher.group(DESTINATION_GROUP);
        result.source = matcher.group(SOURCE_GROUP);

        return result;
    }

    public String getQualifier() {
        return qualifier;
    }

    public String getDestination() {
        return destination;
    }

    public String getSource() {
        return source;
    }
}
