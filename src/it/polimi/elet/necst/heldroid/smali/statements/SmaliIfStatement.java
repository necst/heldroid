package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliIfStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "if-";
    private static final Pattern CALL_PATTERN = Pattern.compile("if\\-([neltzgq]+)\\s+([pv]\\d+)\\s*,\\s*([pv]\\d+|:[\\w\\_]+)(\\s*,\\s*)?(:[\\w\\_]+)?");

    private static final int QUALIFIER_GROUP = 1;
    private static final int ZERO_REGISTER_GROUP = 2;
    private static final int ZERO_LABEL_GROUP = 3;
    private static final int EQUALS_REGISTER1_GROUP = 2;
    private static final int EQUALS_REGISTER2_GROUP = 3;
    private static final int EQUALS_LABEL_GROUP = 5;

    private String qualifier;
    private String register1, register2;
    private String label;

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliIfStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse if statement: " + codeLine);

        SmaliIfStatement result = new SmaliIfStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);

        if (result.qualifier.endsWith("z")) {
            result.register1 = matcher.group(ZERO_REGISTER_GROUP);
            result.label = matcher.group(ZERO_LABEL_GROUP);
        } else {
            result.register1 = matcher.group(EQUALS_REGISTER1_GROUP);
            result.register2 = matcher.group(EQUALS_REGISTER2_GROUP);
            result.label = matcher.group(EQUALS_LABEL_GROUP);
        }
        return result;

    }

    public String getQualifier() {
        return qualifier;
    }

    public String getRegister1() {
        return register1;
    }

    public String getRegister2() {
        return register2;
    }

    public String getRegister() {
        return register1;
    }

    public String getLabel() {
        return label;
    }
}
