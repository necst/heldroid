package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliLabelDeclaration extends SmaliStatement {
    private static final String CALL_PREFIX = ":";
    private static final Pattern CALL_PATTERN = Pattern.compile(":[\\w\\_]+");

    private String label;

    public static boolean isCalledIn(String codeLine) {
        return codeLine.trim().startsWith(CALL_PREFIX);
    }

    public static SmaliLabelDeclaration parse(String codeLine) throws SmaliSyntaxException {
        Matcher matcher = CALL_PATTERN.matcher(codeLine);

        if (!matcher.find())
            throw new SmaliSyntaxException("Cannot parse label statement: " + codeLine);

        SmaliLabelDeclaration result = new SmaliLabelDeclaration();

        result.label = matcher.group(0);

        return result;
    }

    public String getLabel() {
        return label;
    }
}
