package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliMoveResultStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "move-result";
    private static final Pattern CALL_PATTERN = Pattern.compile("move\\-result(\\-\\w+)?\\s+([pv]\\d+)");

    private static final int QUALIFIER_GROUP = 1;
    private static final int DESTINATION_GROUP = 2;

    private String qualifier;
    private String destination;

    private SmaliMoveResultStatement() { }

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliMoveResultStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse move-result statement: " + codeLine);

        SmaliMoveResultStatement result = new SmaliMoveResultStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);
        result.destination = matcher.group(DESTINATION_GROUP);

        return result;
    }

    public String getQualifier() {
        return qualifier;
    }

    public String getDestination() {
        return destination;
    }
}
