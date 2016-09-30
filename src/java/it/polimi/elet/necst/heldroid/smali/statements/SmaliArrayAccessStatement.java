package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliArrayAccessStatement extends SmaliStatement {
    private static final String[] CALL_PREFIXES = {"aget", "aput" };
    private static final String ACTION_GET = "get";
    private static final String ACTION_PUT = "put";

    private static final Pattern CALL_PATTERN = Pattern.compile("a(get|put)(\\-\\w+)?\\s+([pv]\\d+)\\s*,\\s*([pv]\\d+)\\s*,\\s*([pv]\\d+)");

    protected String qualifier;
    protected String targetRegister;
    protected String arrayRegister;
    protected String indexRegister;

    public static boolean isCalledIn(String codeLine) {
        String trimmedLine = codeLine.trim();

        for (String prefix : CALL_PREFIXES)
            if (trimmedLine.startsWith(prefix))
                return true;

        return false;
    }

    public static SmaliArrayAccessStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse aget/aput statement: " + codeLine);

        String action = matcher.group(ACTION_GROUP);
        SmaliArrayAccessStatement result;

        if (action.equals(ACTION_GET))
            result = new SmaliArrayGetStatement();
        else
            result = new SmaliArrayPutStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);
        result.targetRegister = matcher.group(TARGET_GROUP);
        result.arrayRegister = matcher.group(ARRAY_GROUP);
        result.indexRegister = matcher.group(INDEX_GROUP);

        return result;
    }

    public String getQualifier() {
        return qualifier;
    }

    public String getTargetRegister() {
        return targetRegister;
    }

    public String getArrayRegister() {
        return arrayRegister;
    }

    public String getIndexRegister() {
        return indexRegister;
    }

    private static final int ACTION_GROUP = 1;
    private static final int QUALIFIER_GROUP = 2;
    private static final int TARGET_GROUP = 3;
    private static final int ARRAY_GROUP = 4;
    private static final int INDEX_GROUP = 5;
}
