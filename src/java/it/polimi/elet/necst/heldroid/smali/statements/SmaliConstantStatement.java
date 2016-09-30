package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliConstantStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "const";
    private static final Pattern CALL_PATTERN = Pattern.compile("const([\\/\\-\\w\\d]*)\\s+([pv]\\d+)\\s*,\\s*(.+)");

    private static final int QUALIFIER_GROUP = 1;
    private static final int REGISTER_GROUP = 2;
    private static final int VALUE_GROUP = 3;

    private String qualifier;
    private String register;
    private String value;

    private SmaliConstantStatement() { }

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliConstantStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse const statement: " + codeLine);

        SmaliConstantStatement result = new SmaliConstantStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);
        result.register = matcher.group(REGISTER_GROUP);
        result.value = matcher.group(VALUE_GROUP);

        return result;
    }

    public String getQualifier() {
        return qualifier;
    }

    public String getRegister() {
        return register;
    }

    public String getValue() {
        return value;
    }
}
