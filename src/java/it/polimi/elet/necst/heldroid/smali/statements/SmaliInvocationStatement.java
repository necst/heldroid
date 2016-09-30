package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliHelper;
import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliInvocationStatement extends SmaliStatement {
    private static final String CALL_PREFIX = "invoke";

    private static final Pattern CALL_PATTERN = Pattern.compile("invoke([\\/\\-\\w\\d]*)\\s+\\{([pv\\.\\d\\s,]*)\\}\\s*,\\s*([\\w\\d\\/\\$\\[;]+)\\-\\>([\\w\\d\\<\\>\\$]+)\\(([\\s\\w\\d\\$\\/\\[;]*)\\)([\\w\\d\\$\\/\\[;]+)");
    private static final Pattern SINGLE_PARAMETER_PATTERN = Pattern.compile("(p|v)(\\d+)");
    private static final Pattern RANGE_PARAMETERS_PATTERN = Pattern.compile("(p|v)(\\d+)\\s*\\.\\.\\s*(p|v)(\\d+)");

    private String qualifier;
    private String returnType;
    private List<String> parameters;
    private List<String> parameterTypes;
    private SmaliMemberName methodName;

    private SmaliInvocationStatement() { }

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliInvocationStatement parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse invoke statement: " + codeLine);

        SmaliInvocationStatement result = new SmaliInvocationStatement();

        result.qualifier = matcher.group(QUALIFIER_GROUP);
        result.returnType = matcher.group(RETURN_TYPE_GROUP);

        String completeClassName = matcher.group(CLASS_GROUP);
        String simpleMethodName = matcher.group(METHOD_GROUP);

        result.methodName = new SmaliMemberName(new SmaliClassName(completeClassName), simpleMethodName);

        result.parameterTypes = SmaliHelper.parseParameterTypesList(matcher.group(PARAMETER_TYPES_LIST_GROUP));
        result.parameters = parseParametersList(matcher.group(PARAMETERS_LIST_GROUP));

        return result;
    }

    private static List<String> parseParametersList(String parametersList) {
        String[] chunks = parametersList.split(",");
        List<String> result = new ArrayList<String>();

        for (String chunk : chunks) {
            Matcher rangeMatcher = RANGE_PARAMETERS_PATTERN.matcher(chunk);

            if (rangeMatcher.find()) {
                String kind = rangeMatcher.group(PARAMETER_KIND_GROUP);
                Integer firstRegister = Integer.parseInt(rangeMatcher.group(FIRST_PARAMETER_GROUP));
                Integer lastRegister = Integer.parseInt(rangeMatcher.group(LAST_PARAMETER_GROUP));

                for (Integer reg = firstRegister; reg <= lastRegister; reg++)
                    result.add(kind + reg);
            } else {
                Matcher singleMatcher = SINGLE_PARAMETER_PATTERN.matcher(chunk);

                if (singleMatcher.find())
                    result.add(singleMatcher.group(0)); // all match
            }
        }

        return result;
    }

    public String getQualifier() {
        return qualifier;
    }

    public SmaliMemberName getMethodName() {
        return methodName;
    }

    public String getReturnType() {
        return returnType;
    }

    public List<String> getParameters() {
        return parameters;
    }

    public List<String> getParameterTypes() {
        return parameterTypes;
    }

    private static final int QUALIFIER_GROUP = 1;
    private static final int PARAMETERS_LIST_GROUP = 2;
    private static final int CLASS_GROUP = 3;
    private static final int METHOD_GROUP = 4;
    private static final int PARAMETER_TYPES_LIST_GROUP = 5;
    private static final int RETURN_TYPE_GROUP = 6;

    private static final int PARAMETER_KIND_GROUP = 1;
    private static final int FIRST_PARAMETER_GROUP = 2;
    private static final int LAST_PARAMETER_GROUP = 4;
}
