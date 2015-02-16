package it.polimi.elet.necst.heldroid.utils;

public class Options {
    private String args[];

    public Options(String args[]) {
        this.args = args;
    }

    public boolean contains(String option) {
        for (int i = 0; i < args.length; i++)
            if (args[i].equals(option))
                return true;

        return false;
    }

    public String getParameter(String option) {
        for (int i = 0; i < args.length; i++)
            if (args[i].equals(option))
                return args[i + 1];

        return null;
    }

    public String[] getParameters(String option, int count) {
        for (int i = 0; i < args.length; i++)
            if (args[i].equals(option)) {
                String[] params = new String[count];

                for (int j = 0; j < count; j++)
                    params[j] = args[i + 1 + j];

                return params;
            }

        return null;
    }
}
