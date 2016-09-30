package it.polimi.elet.necst.heldroid.smali;

import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.smali.statements.*;
import it.polimi.elet.necst.heldroid.utils.MultiMap;

import java.util.*;

public class SmaliSimulator {
    public interface StatementHandler {
        /**
         * Callback method invoked when a given statement type is reached.
         * @param statement The reached statement. May need casting to an appropriate subclass.
         * @return Returns true if you want to terminate the method simulation. Except in the case statement is a
         *     SmaliIfStatement: in that case, true means to take the true branch and false to take the false branch.
         */
        boolean statementReached(SmaliStatement statement);
    }

    private SmaliMethod target;
    private int statementIndex;
    private Map<Class, StatementHandler> handlers;

    private MultiMap<String, String> initializedFieldValues;
    private MultiMap<String, String> fieldDerivedRegisterValues;
    private Map<String, String> currentConstants;

    private SmaliSimulator(SmaliMethod target) {
        this.target = target;
        this.handlers = new HashMap<Class, StatementHandler>();
        this.reset();
    }

    public static SmaliSimulator on(SmaliMethod target) {
        return new SmaliSimulator(target);
    }

    public void setInitializedFieldValues(MultiMap<String, String> obj) {
        this.initializedFieldValues = obj;
    }

    public void addHandler(Class statementClass, StatementHandler handler) {
        handlers.put(statementClass, handler);
    }

    public void removeHandler(Class statementClass) {
        handlers.remove(statementClass);
    }

    public Collection<String> getPossibleValues(String registerName) {
        Collection<String> result = new ArrayList<String>();

        if (currentConstants.containsKey(registerName))
            result.add(currentConstants.get(registerName));

        if (fieldDerivedRegisterValues.containsKey(registerName))
            result.addAll(fieldDerivedRegisterValues.get(registerName));

        return result;
    }

    public void reset() {
        this.statementIndex = 0;
        this.fieldDerivedRegisterValues = new MultiMap<String, String>();
        this.currentConstants = new HashMap<String, String>();
    }

    public void simulate() {
        this.reset();

        while (this.step())
            ;
    }

    private boolean step() {
        // A register/parameter can hold only one value at a time. We consider only registers that are assigned literal
        // values. Among those, the value is either a literal constant defined with a const statement or the content
        // of a class field which has been initialized somewhere with a literal value itself. In the second case, more than
        // one value is possible: since this analysis is aimed to be simple and quick, no complex flow mechanism is
        // adopted and as such we do not know which execution path contains the true value used. We can at most obtain a
        // false negative in detection, which is of no importance.
        // At any given time, the set of keys of fieldDerivedRegisterValues and currentConstants are strictly disjoint.

        if (statementIndex >= target.getInterestingStatements().size())
            return false;

        SmaliStatement statement = target.getInterestingStatements().get(statementIndex);

        // A constant is being declared: memorize its value in the constants mapping
        if (statement.is(SmaliConstantStatement.class))
            this.defineConstant((SmaliConstantStatement) statement);

        // A value is being moved: move it also in the current mappings
        else if (statement.is(SmaliMoveStatement.class))
            this.executeMove((SmaliMoveStatement) statement);

        // A field is being read: if it has a constant value, put it in the current mapping
        else if (statement.is(SmaliGetStatement.class))
            this.readField((SmaliGetStatement)statement);

        // An if statement is encountered: the client decides which branch he wants to follow. Otheriwse
        // the flow will simply fall through
        else if (statement.is(SmaliIfStatement.class)) {
            boolean takeBranch = callHandler(statement);

            if (takeBranch) {
                SmaliIfStatement ifStatement = (SmaliIfStatement)statement;
                Integer jumpIndex = target.getTargetStatementIndex(ifStatement.getLabel());

                if (jumpIndex >= 0)
                    statementIndex = jumpIndex - 1;
            }

            statementIndex++;
            return true;
        }

        statementIndex++;

        // Then, call an appropriate handler, if it exists
        // callHandler returns true iif the called handler returns true as well, which means that it is
        // no longer needed to proceed in the simulation; therefore, in that case, step returns false, which
        // halts the simulation cycle in simulate()
        if (callHandler(statement))
            return false;

        return true;
    }

    private boolean callHandler(SmaliStatement statement) {
        StatementHandler handler = handlers.get(statement.getClass());

        if (handler != null)
            return handler.statementReached(statement);

        return false;
    }

    private void defineConstant(SmaliConstantStatement konst) {
        currentConstants.put(konst.getRegister(), konst.getValue());
        fieldDerivedRegisterValues.empty(konst.getRegister());
    }

    private void executeMove(SmaliMoveStatement move) {
        String source = move.getSource();
        String destination = move.getDestination();

        // Moves value from source to destination in currentConstants mapping
        if (currentConstants.containsKey(source)) {
            String value = currentConstants.get(source);
            currentConstants.remove(source);
            currentConstants.put(destination, value);
            fieldDerivedRegisterValues.empty(destination);
        }

        // Does the same for fieldDerivedRegisterValues mapping, only considering more potential values at once
        else if (fieldDerivedRegisterValues.containsKey(source)) {
            Collection<String> values = fieldDerivedRegisterValues.get(source);
            fieldDerivedRegisterValues.empty(source);
            fieldDerivedRegisterValues.putAll(destination, values);
            currentConstants.remove(destination);
        }
    }

    private void readField(SmaliGetStatement getter) {
        if (initializedFieldValues == null)
            return;

        SmaliMemberName fieldName = getter.getFieldName();
        String fieldCompleteName = fieldName.getCompleteName();

        if (initializedFieldValues.containsKey(fieldCompleteName)) {
            fieldDerivedRegisterValues.replaceAll(getter.getRegister(), initializedFieldValues.get(fieldCompleteName));
            currentConstants.remove(getter.getRegister());
        }
    }
}
