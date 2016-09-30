package it.polimi.elet.necst.heldroid.smali.names;

import java.util.ArrayList;
import java.util.List;

public class SmaliMemberName {
    private SmaliClassName className;
    private String memberName;
    private String completeName;

    public SmaliMemberName(String completeName) {
        String[] parts = completeName.split("\\-\\>");

        if (parts.length != 2)
            throw new IllegalArgumentException("The name must be in the form Lpackage/class;->memberName");

        this.className = new SmaliClassName(parts[0]);
        this.memberName = parts[1];
        this.completeName = completeName;
    }

    public SmaliMemberName(SmaliClassName className, String memberName) {
        this.className = className;
        this.memberName = memberName;
        this.completeName = className.getCompleteName() + "->" + memberName;
    }

    public SmaliMemberName(String className, String memberName) {
        this(new SmaliClassName(className), memberName);
    }

    public SmaliClassName getClassName() {
        return className;
    }

    public String getMemberName() {
        return memberName;
    }

    public String getCompleteName() {
        return completeName;
    }

    public boolean equals(SmaliMemberName other) {
        return this.completeName.equals(other.completeName);
    }

    public String toString() {
        return this.completeName;
    }


    public static List<SmaliMemberName> newList(String... completeNames) {
        List<SmaliMemberName> result = new ArrayList<SmaliMemberName>(completeNames.length);

        for (int i = 0; i < completeNames.length; i++)
            result.add(new SmaliMemberName(completeNames[i]));

        return result;
    }
}
