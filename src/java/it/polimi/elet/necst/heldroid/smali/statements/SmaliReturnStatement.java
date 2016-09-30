package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliReturnStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "return";
    private static final Pattern CALL_PATTERN = Pattern.compile("(return\\-void|return(\\-(\\w+))?\\s+([pv]\\d+))");

    private static final int WHOLE_GROUP = 0;
    private static final int QUALIFIER_GROUP = 3;
    private static final int REGISTER_GROUP = 4;

    private String qualifier;
    private String register;

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliReturnStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse return statement: " + codeLine);

        SmaliReturnStatement result = new SmaliReturnStatement();
        String whole = matcher.group(WHOLE_GROUP);

        if (whole.equals("return-void")) {
            result.qualifier = "void";
            result.register = null;
        } else {
            result.qualifier = matcher.group(QUALIFIER_GROUP);
            result.register = matcher.group(REGISTER_GROUP);
        }

        return result;
    }

    public String getQualifier() {
        return qualifier;
    }

    public String getRegister() {
        return register;
    }
}
