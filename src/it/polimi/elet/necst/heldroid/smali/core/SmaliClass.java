package it.polimi.elet.necst.heldroid.smali.core;

import it.polimi.elet.necst.heldroid.smali.SmaliFormatException;
import it.polimi.elet.necst.heldroid.smali.SmaliHelper;
import it.polimi.elet.necst.heldroid.smali.collections.QueryableSmaliClassCollection;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliClass {
    private static final Pattern DECLARATION_PATTERN = Pattern.compile("\\.class\\s+([\\-\\w]+\\s+)*L([\\w\\d\\$\\/_]+);");
    private static final Pattern SUPER_PATTERN = Pattern.compile("\\.super\\s+([\\w\\d\\$\\/_]+);");
    private static final Pattern COMMENT_PATTERN = Pattern.compile("\\s*#.*");

    private static final int NAME_GROUP = 2;
    private static final int SUPER_GROUP = 1;

    private long size;
    private SmaliClassName name, superClassName;

    private Map<String, SmaliMethod> quickMethodsMap;
    private Collection<SmaliField> fields;
    private Collection<SmaliMethod> methods;
    private QueryableSmaliClassCollection associatedCollection;


    public void setAssociatedCollection(QueryableSmaliClassCollection collection) {
        this.associatedCollection = collection;
    }

    public long getSize() {
        return size;
    }

    public SmaliClassName getSuperClassName() {
        return superClassName;
    }

    public SmaliClassName getName() {
        return name;
    }


    private SmaliClass() {
        this.fields = new ArrayList<SmaliField>();
        this.methods = new ArrayList<SmaliMethod>();
    }

    public static SmaliClass parse(File file) throws IOException, SmaliFormatException {
        if (!file.getName().toLowerCase().endsWith(SmaliHelper.SMALI_EXTENSION))
            throw new SmaliFormatException("Invalid file type.");

        BufferedReader reader = new BufferedReader(new FileReader(file));
        boolean headerFound = false;
        String line, completeName;

        completeName = null;
        while ((line = reader.readLine()) != null) {
            Matcher classHeaderMatcher = DECLARATION_PATTERN.matcher(line);

            if (classHeaderMatcher.find()) {
                completeName = classHeaderMatcher.group(NAME_GROUP);
                headerFound = true;
                break;
            }
        }

        if (!headerFound) {
            reader.close();
            throw new SmaliFormatException("No class header found.");
        }

        SmaliClass result = new SmaliClass();
        SmaliMethod.Builder methodBuilder = null;

        result.name = new SmaliClassName("L" + completeName + ";");

        while ((line = reader.readLine()) != null) {
            Matcher matcher = SUPER_PATTERN.matcher(line);

            if (matcher.find()) {
                result.superClassName = new SmaliClassName(matcher.group(SUPER_GROUP) + ";"); // same as above
                continue;
            }

            if (SmaliField.isDeclaredIn(line)) {
                SmaliField field = SmaliField.parse(line);

                if (field != null)
                    result.fields.add(field);
            } else {
                if (SmaliMethod.startsHere(line))
                    methodBuilder = new SmaliMethod.Builder();

                if (methodBuilder != null)
                    methodBuilder.append(line);

                if (SmaliMethod.endsHere(line)) {
                    SmaliMethod method = methodBuilder.build();
                    result.methods.add(method);
                    methodBuilder = null;
                }
            }
        }

        reader.close();
        result.size = file.length();

        return result;
    }


    public boolean matchesType(SmaliClassName typeName) {
        return this.getName().equals(typeName) || typeName.equals(this.getSuperClassName());
    }

    public Collection<SmaliField> getFields() {
        return fields;
    }

    public Collection<SmaliMethod> getMethods() {
        return methods;
    }

    public SmaliMethod getMethodByName(SmaliMemberName name) {
        String methodName = name.getMemberName();

        if (quickMethodsMap != null)
            return quickMethodsMap.get(methodName);

        SmaliMethod result = null;

        quickMethodsMap = new HashMap<String, SmaliMethod>();

        for (SmaliMethod method : methods) {
            quickMethodsMap.put(method.getName(), method);

            if (method.getName().equals(methodName))
                result = method;
        }

        return result;
    }

    public SmaliMethod getMethodBySignature(SmaliMemberName name, List<String> parameterTypes) {
        String methodName = name.getMemberName();

        for (SmaliMethod method : methods) {
            if (method.getName().equals(methodName)) {
                if (method.getParameterTypes().size() != parameterTypes.size())
                    continue;

                for (int i = 0; i < parameterTypes.size(); i++)
                    if (!method.getParameterTypes().get(i).equals(parameterTypes.get(i)))
                        continue;

                return method;
            }
        }

        return null;
    }

    public boolean isSubclassOf(SmaliClassName className) {
        return associatedCollection.classExtends(this, className);
    }


    public String toString() {
        return this.getName().toString();
    }
}
