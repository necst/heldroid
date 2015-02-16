package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliGotoStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "goto";
    private static final Pattern CALL_PATTERN = Pattern.compile("goto(\\/(16|32))?\\s+(:[\\w\\_]+)");

    private static final int QUALIFIER_GROUP = 2;
    private static final int LABEL_GROUP = 3;

    private String qualifier;
    private String label;

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliGotoStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse goto statement: " + codeLine);

        SmaliGotoStatement result = new SmaliGotoStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);
        result.label = matcher.group(LABEL_GROUP);

        return result;

    }

    public String getQualifier() {
        return qualifier;
    }

    public String getLabel() {
        return label;
    }
}
