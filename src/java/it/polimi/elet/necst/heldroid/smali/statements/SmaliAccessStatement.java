package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class SmaliAccessStatement extends SmaliStatement {
    private static final String[] CALL_PREFIXES = {"sget", "iget", "sput", "iput" };
    private static final String ACTION_GET = "get";
    private static final String ACTION_PUT = "put";

    private static final Pattern CALL_PATTERN = Pattern.compile("(s|i)(get|put)([\\/\\-\\w\\d]*)\\s+([pv]\\d+)\\s*,(\\s*[pv]\\d+\\s*,)?\\s*([\\w\\d\\$\\/\\[;_]+)\\-\\>([\\w\\d\\$\\<\\>_]+):([\\w\\d\\$\\/\\[;_]+)");

    protected String qualifier;
    protected String register;
    protected String returnType;
    protected SmaliMemberName fieldName;

    public static boolean isCalledIn(String codeLine) {
        String trimmedLine = codeLine.trim();

        for (String prefix : CALL_PREFIXES)
            if (trimmedLine.startsWith(prefix))
                return true;

        return false;
    }

    public static SmaliAccessStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse get statement: " + codeLine);

        String action = matcher.group(ACTION_GROUP);
        SmaliAccessStatement result;

        if (action.equals(ACTION_GET))
            result = new SmaliGetStatement();
        else
            result = new SmaliPutStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);
        result.register = matcher.group(REGISTER_GROUP);
        result.returnType = matcher.group(RETURN_TYPE_GROUP);

        String completeClassName = matcher.group(CLASS_GROUP);
        String simpleMemberName = matcher.group(FIELD_GROUP);

        result.fieldName = new SmaliMemberName(new SmaliClassName(completeClassName), simpleMemberName);

        return result;
    }


    public String getQualifier() {
        return qualifier;
    }

    public String getRegister() {
        return register;
    }

    public SmaliMemberName getFieldName() {
        return fieldName;
    }

    public String getReturnType() {
        return returnType;
    }

    private static final int SCOPE_GROUP = 1;
    private static final int ACTION_GROUP = 2;
    private static final int QUALIFIER_GROUP = 3;
    private static final int REGISTER_GROUP = 4;
    private static final int CLASS_GROUP = 6;
    private static final int FIELD_GROUP = 7;
    private static final int RETURN_TYPE_GROUP = 8;
}
