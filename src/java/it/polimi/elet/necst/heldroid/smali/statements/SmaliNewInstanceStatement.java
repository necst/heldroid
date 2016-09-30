package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliNewInstanceStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "new-instance";
    private static final Pattern CALL_PATTERN = Pattern.compile("new\\-instance\\s+([v]\\d+)\\s*,\\s*([\\w\\d\\/\\$\\[;]+)");

    private static final int REGISTER_GROUP = 1;
    private static final int TYPE_GROUP = 2;

    private String register;
    private SmaliClassName instanceType;

    private SmaliNewInstanceStatement() { }

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliNewInstanceStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse new-instance statement: " + codeLine);

        SmaliNewInstanceStatement result = new SmaliNewInstanceStatement();

        result.register = matcher.group(REGISTER_GROUP);
        result.instanceType = new SmaliClassName(matcher.group(TYPE_GROUP));

        return result;
    }

    public String getRegister() {
        return register;
    }

    public SmaliClassName getInstanceType() {
        return instanceType;
    }
}
