package it.polimi.elet.necst.heldroid.smali;

import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.core.SmaliField;
import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliConstantStatement;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliInvocationStatement;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliStatement;
import it.polimi.elet.necst.heldroid.utils.Literal;
import it.polimi.elet.necst.heldroid.utils.MultiMap;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

import java.util.Collection;

public class SmaliConstantFinder {
    public interface ConstantHandler {
        /**
         * Callback method invoked when a constant value is found.
         * @param value The constant value as string. Notice that constants that are string-typed in smali code
         *     are enclosed by double quotes.
         * @return Returns true if you want to terminate the search.
         */
        public boolean constantFound(String value);
    }

    private MultiMap<String, String> initializedFieldValues;
    private Collection<SmaliClass> classes;
    private ConstantHandler handler;

    SmaliConstantFinder(Collection<SmaliClass> classes, MultiMap<String, String> initializedFieldValues) {
        this.classes = classes;
        this.initializedFieldValues = initializedFieldValues;
    }

    public void setHandler(ConstantHandler handler) {
        this.handler = handler;
    }

    public void searchAllLiterals() {
        for (SmaliClass klass : classes)
            this.searchAllLiterals(klass);
    }

    public void searchAllLiterals(SmaliClass klass) {
        for (SmaliField field : klass.getFields())
            if (field.getLiteralValue() != null)
                if ((handler != null) && handler.constantFound(field.getLiteralValue()))
                    return;

        for(SmaliMethod method : klass.getMethods()) {
            for (SmaliStatement statement : method.getInterestingStatements())
                if (statement.is(SmaliConstantStatement.class)) {
                    String value = ((SmaliConstantStatement)statement).getValue();
                    if ((handler != null) && handler.constantFound(value))
                        return;
                }
        }
    }

    public void searchParameters(SmaliMemberName methodName, int parameterIndex) {
        for (SmaliClass klass : classes)
            for (SmaliMethod method : klass.getMethods()) {
                boolean aborted = this.searchParameters(methodName, parameterIndex, method);

                if (aborted)
                    return;
            }
    }

    public boolean testInvocationParameter(SmaliMemberName methodName, int paramIndex, final String paramValue) {
        final Wrapper<Boolean> found = new Wrapper<Boolean>(false);

        this.setHandler(new ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                String escaped = Literal.getStringValue(value);

                if (escaped.equals(paramValue)) {
                    found.value = true;
                    return true;
                }

                return false;
            }
        });

        this.searchParameters(methodName, paramIndex);
        return found.value;
    }

    private boolean searchParameters(final SmaliMemberName methodName, final int parameterIndex, SmaliMethod analyzedMethod) {
        final SmaliSimulator simulator = SmaliSimulator.on(analyzedMethod);
        final ConstantHandler constantHandler = this.handler;
        final Wrapper<Boolean> aborted = new Wrapper<Boolean>();

        aborted.value = false;

        simulator.setInitializedFieldValues(initializedFieldValues);
        simulator.addHandler(SmaliInvocationStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliInvocationStatement invocation = (SmaliInvocationStatement)statement;
                SmaliMemberName invokeName = invocation.getMethodName();

                if (!invokeName.equals(methodName))
                    return false;

                if (invocation.getParameterTypes().size() > parameterIndex) {
                    // invoke requires object to invoke on as first parameter, except for invoke-static
                    int paramOffset = (invocation.getParameters().size() > invocation.getParameterTypes().size()) ? 1 : 0;
                    String parameter = invocation.getParameters().get(parameterIndex + paramOffset);
                    Collection<String> possibleValues = simulator.getPossibleValues(parameter);

                    for (String value : possibleValues)
                        if (constantHandler.constantFound(value)) {
                            aborted.value = true;
                            return true;
                        }
                }

                return false;
            }
        });

        simulator.simulate();

        return aborted.value;
    }

}
