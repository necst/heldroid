package it.polimi.elet.necst.heldroid.smali.core;

import it.polimi.elet.necst.heldroid.smali.SmaliFormatException;
import it.polimi.elet.necst.heldroid.smali.SmaliHelper;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliLabelDeclaration;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliStatement;
import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliMethod {
    static class Builder {
        List<String> codeLines;

        public Builder() {
            this.codeLines = new ArrayList<String>();
        }

        public void append(String codeLine) {
            codeLines.add(codeLine);
        }

        public SmaliMethod build() throws SmaliFormatException {
            return SmaliMethod.parse(this.codeLines);
        }
    }

    private static final String DECLARATION_START_PREFIX = ".method";
    private static final String DECLARATION_END_PREFIX = ".end method";
    private static final Pattern SIGNATURE_PATTERN = Pattern.compile("\\.method\\s+([\\-\\w]+\\s+)*([\\w\\d\\$\\<\\>]+)\\s*\\(([\\s\\w\\d\\$\\/\\[;]*)\\)([\\w\\d\\$\\/\\[;]+)");

    private static final int NAME_GROUP = 2;
    private static final int PARAMETER_TYPES_LIST_GROUP = 3;
    private static final int RETURN_TYPE_GROUP = 4;

    private String name;
    private String returnType;
    private List<String> parameterTypes;
    private List<String> codeLines;
    private List<SmaliStatement> interestingStatements;
    private Map<String, Integer> labelOffsets;

    private SmaliMethod() {
        this.codeLines = new ArrayList<String>();
        this.parameterTypes = new ArrayList<String>();
        this.labelOffsets = new HashMap<String, Integer>();
    }

    public static boolean startsHere(String codeLine) {
        return codeLine.trim().startsWith(DECLARATION_START_PREFIX);
    }

    public static boolean endsHere(String codeLine) {
        return codeLine.trim().startsWith(DECLARATION_END_PREFIX);
    }

    public static SmaliMethod parse(List<String> codeLines) throws SmaliFormatException {
        String signatureLine = codeLines.get(0);
        Matcher signatureMatcher = SIGNATURE_PATTERN.matcher(signatureLine);

        if (!signatureMatcher.find())
            throw new SmaliFormatException("No valid method header found in: " + signatureLine);

        SmaliMethod result = new SmaliMethod();

        result.name = signatureMatcher.group(NAME_GROUP);
        result.returnType = signatureMatcher.group(RETURN_TYPE_GROUP);
        result.parameterTypes = SmaliHelper.parseParameterTypesList(signatureMatcher.group(PARAMETER_TYPES_LIST_GROUP));

        codeLines.remove(0);                    // removes .method ... (start line)
        codeLines.remove(codeLines.size() - 1); // removes .end method (end line)

        result.codeLines.addAll(codeLines);
        result.parseCodeLines();

        return result;
    }

    private void parseCodeLines() {
        if (interestingStatements == null)
            interestingStatements = new ArrayList<SmaliStatement>();

        for (String codeLine : codeLines) {
            try {
                SmaliStatement statement = SmaliStatement.parse(codeLine);

                if (statement != null) {
                    interestingStatements.add(statement);

                    if (statement.is(SmaliLabelDeclaration.class)) {
                        SmaliLabelDeclaration declaration = (SmaliLabelDeclaration)statement;
                        labelOffsets.put(declaration.getLabel(), interestingStatements.size());
                    }
                }
            } catch (SmaliSyntaxException ssex) {
                // ssex.printStackTrace();
            }
        }
    }


    public String getName() {
        return name;
    }

    public String getReturnType() {
        return returnType;
    }

    public List<String> getParameterTypes() {
        return parameterTypes;
    }

    public List<SmaliStatement> getInterestingStatements() {
        return interestingStatements;
    }

    public Integer getTargetStatementIndex(String label) {
        Integer index = labelOffsets.get(label);

        if ((index == null) || (index >= interestingStatements.size()))
            return -1;

        return index;
    }

    public SmaliStatement getTargetStatement(String label) {
        Integer index = this.getTargetStatementIndex(label);

        if (index >= 0)
            return interestingStatements.get(index);

        return null;
    }

    public String toString() {
        return this.getName();
    }
}
