package it.polimi.elet.necst.heldroid.smali.names;

public class SmaliClassName {
    private String packageName;
    private String simpleName;
    private String completeName;

    public SmaliClassName(String completeName) {
        this.completeName = completeName;

        if (completeName.indexOf('/') >= 0) {
            this.packageName = completeName.substring(0, completeName.lastIndexOf("/"));
            this.simpleName = completeName.substring(this.getPackageName().length() + 1);
        } else {
            this.packageName = "";
            this.simpleName = completeName;
        }

        if (this.packageName.startsWith("L"))
            this.packageName = this.packageName.substring(1);

        if (this.simpleName.endsWith(";"))
            this.simpleName = this.simpleName.substring(0, this.simpleName.length() - 1);
    }

    public String getPackageName() {
        return packageName;
    }

    public String getSimpleName() {
        return simpleName;
    }

    public String getCompleteName() {
        return completeName;
    }

    public boolean equals(SmaliClassName other) {
        return this.completeName.equals(other.completeName);
    }

    public String toString() {
        return this.completeName;
    }
}
