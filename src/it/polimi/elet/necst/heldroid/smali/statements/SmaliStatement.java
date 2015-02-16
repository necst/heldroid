package it.polimi.elet.necst.heldroid.smali.statements;

import it.polimi.elet.necst.heldroid.smali.SmaliSyntaxException;

public abstract class SmaliStatement {
    private String codeLine;

    public boolean is(Class type) {
        return this.getClass().getName().equals(type.getName());
    }

    public static SmaliStatement parse(String codeLine) throws SmaliSyntaxException {
        SmaliStatement result = null;

        if (SmaliConstantStatement.isCalledIn(codeLine))
            result = SmaliConstantStatement.parse(codeLine);

        else if (SmaliInvocationStatement.isCalledIn(codeLine))
            result = SmaliInvocationStatement.parse(codeLine);

        else if (SmaliAccessStatement.isCalledIn(codeLine))
            result = SmaliAccessStatement.parse(codeLine);

        else if (SmaliMoveResultStatement.isCalledIn(codeLine))
            result = SmaliMoveResultStatement.parse(codeLine);

        else if (SmaliMoveStatement.isCalledIn(codeLine))
            result = SmaliMoveStatement.parse(codeLine);

        else if (SmaliIfStatement.isCalledIn(codeLine))
            result = SmaliIfStatement.parse(codeLine);

        else if (SmaliGotoStatement.isCalledIn(codeLine))
            result = SmaliGotoStatement.parse(codeLine);

        else if (SmaliReturnStatement.isCalledIn(codeLine))
            result = SmaliReturnStatement.parse(codeLine);

        else if (SmaliLabelDeclaration.isCalledIn(codeLine))
            result = SmaliLabelDeclaration.parse(codeLine);

        else if (SmaliArrayAccessStatement.isCalledIn(codeLine))
            result = SmaliArrayAccessStatement.parse(codeLine);

        else if (SmaliNewInstanceStatement.isCalledIn(codeLine))
            result = SmaliNewInstanceStatement.parse(codeLine);

        if (result != null)
            result.codeLine = codeLine;

        return result;
    }

    public String toString() {
        return codeLine;
    }
}
