package it.polimi.elet.necst.heldroid.smali.core;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliField {
    private static final String DECLARATION_PREFIX = ".field";
    private static final Pattern DECLARATION_PATTERN = Pattern.compile("\\.field\\s+([\\-\\w]+\\s+)*?([\\w\\d\\$]+):([\\w\\d\\$\\/\\[]+;?)(\\s+\\=\\s+(.+))?");

    private static final int NAME_GROUP = 2;
    private static final int TYPE_GROUP = 3;
    private static final int LITERAL_VALUE_GROUP = 5;

    private String name;
    private String type;
    private String literalValue;

    private SmaliField() { }

    public static boolean isDeclaredIn(String codeLine) {
        return codeLine.trim().startsWith(DECLARATION_PREFIX);
    }

    public static SmaliField parse(String codeLine) {
        Matcher matcher = DECLARATION_PATTERN.matcher(codeLine);

        if (!matcher.find())
            return null;

        SmaliField result = new SmaliField();

        result.name = matcher.group(NAME_GROUP);
        result.type = matcher.group(TYPE_GROUP);
        result.literalValue = matcher.group(LITERAL_VALUE_GROUP);

        return result;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public String getLiteralValue() {
        return literalValue;
    }
}
