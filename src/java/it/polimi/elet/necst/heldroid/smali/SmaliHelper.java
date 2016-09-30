package it.polimi.elet.necst.heldroid.smali;

import java.util.ArrayList;
import java.util.List;

public class SmaliHelper {
    public static final String SMALI_EXTENSION = ".smali";

    // Type examples: "I", "[S", "Ljava/lang/Object;"
    public static final String TYPE_REGEX = "[\\w\\d\\$\\/\\[;_]+";
    // Access modifier examples: "public", "static", "declared-synchronized"
    public static final String ACCESS_MODIFIER_REGEX = "[\\-\\w]+";
    // Identifier examples: "<init>", "onCreate", "my_method", "open$3"
    public static final String IDENTIFIER_REGEX = "[\\w\\d\\$\\<\\>_]+";
    // Parameters examples: "v0", "p1, p3, v5", "v1 .. v2", ""
    public static final String PARAMETERS_REGEX = "[pv\\.\\d\\s,]*";
    // Qualifier examples: "/16", "-wide", "-static/range", "/high16", ""
    public static final String QUALIFIER_REGEX = "[\\/\\-\\w\\d]*";

    public static List<String> parseParameterTypesList(String parameterTypesList) {
        List<String> result = new ArrayList<String>();
        StringBuilder builder = new StringBuilder();
        boolean complexTypeOpen = false;

        for (Character c : parameterTypesList.toCharArray()) {
            builder.append(c);

            switch (c) {
                case 'L':
                    complexTypeOpen = true;
                    break;

                case 'Z': // boolean
                case 'B': // byte
                case 'S': // string
                case 'C': // char
                case 'I': // int
                case 'J': // long
                case 'F': // float
                case 'D': // double
                    if (!complexTypeOpen) {
                        result.add(builder.toString());
                        builder.setLength(0);
                    }
                    break;

                case ';':
                    result.add(builder.toString());
                    builder.setLength(0);
                    complexTypeOpen = false;
                    break;
            }
        }

        return result;
    }
}
