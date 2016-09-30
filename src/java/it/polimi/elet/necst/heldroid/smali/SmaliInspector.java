package it.polimi.elet.necst.heldroid.smali;

import it.polimi.elet.necst.heldroid.smali.collections.QueryableSmaliClassCollection;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliInvocationStatement;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliStatement;

import java.util.*;

public class SmaliInspector {
    private static final int INVOCATION_FLOW_STACK_LIMIT = 3;

    private QueryableSmaliClassCollection classCollection;

    SmaliInspector(QueryableSmaliClassCollection classes) {
        this.classCollection = classes;
    }

    public boolean[] invocationsExist(List<SmaliMemberName> methodNames) {
        boolean[] methodsFound = new boolean[methodNames.size()];

        for (SmaliClass klass : classCollection)
            for (SmaliMethod method : klass.getMethods())
                for (SmaliStatement statement : method.getInterestingStatements())
                    if (statement.is(SmaliInvocationStatement.class)) {
                        SmaliInvocationStatement invoke = (SmaliInvocationStatement) statement;
                        SmaliMemberName invokeName = invoke.getMethodName();

                        for (int i = 0; i < methodNames.size(); i++)
                            if (invokeName.equals(methodNames.get(i)))
                                methodsFound[i] = true;
                    }

        return methodsFound;
    }

    public class Inspection {
        private Collection<String> exitPoints;
        private boolean onlyCheckClass;

        private Inspection(boolean onlyCheckClass) {
            this.exitPoints = new ArrayList<String>();
            this.onlyCheckClass = onlyCheckClass;
        }

        void addMethodNames(Collection<SmaliMemberName> exitPoints) {
            for (SmaliMemberName memberName : exitPoints)
                this.exitPoints.add(memberName.getCompleteName());
        }

        void addMethodName(SmaliMemberName exitPoint) {
            this.exitPoints.add(exitPoint.getCompleteName());
        }

        void addClasseNames(Collection<SmaliClassName> exitPoints) {
            for (SmaliClassName className : exitPoints)
                this.exitPoints.add(className.getCompleteName());
        }

        void addClassName(SmaliClassName exitPoint) {
            this.exitPoints.add(exitPoint.getCompleteName());
        }

        public boolean reachableFrom(SmaliMethod entryPoint) {
            return SmaliInspector.this.flowExists(entryPoint, exitPoints, entryPoint, 0, onlyCheckClass);
        }

        public boolean reachableFromAny(SmaliMemberName virtualMethodName) {
            return reachableFromAny(classCollection, virtualMethodName);
        }

        public boolean reachableFromAny(Collection<SmaliClass> providedClasses, SmaliMemberName virtualMethodName) {
            SmaliClassName baseClassName = virtualMethodName.getClassName();

            for (SmaliClass klass : providedClasses) {
                if (!klass.isSubclassOf(baseClassName))
                    continue;

                SmaliMethod method = klass.getMethodByName(virtualMethodName);

                if (method == null)
                    continue;

                if (this.reachableFrom(method))
                    return true;
            }

            return false;
        }
    }

    public Inspection is(SmaliMemberName methodName) {
        Inspection methodInspection = new Inspection(false);
        methodInspection.addMethodName(methodName);
        return methodInspection;
    }

    public Inspection isAny(Collection<SmaliMemberName> methodNames) {
        Inspection methodInspection = new Inspection(false);
        methodInspection.addMethodNames(methodNames);
        return methodInspection;
    }

    public Inspection isClass(SmaliClassName className) {
        Inspection classInspection = new Inspection(true);
        classInspection.addClassName(className);
        return classInspection;
    }

    public Inspection isAnyClass(Collection<SmaliClassName> classNames) {
        Inspection classInspection = new Inspection(true);
        classInspection.addClasseNames(classNames);
        return classInspection;
    }

    private boolean flowExists(SmaliMethod entryPoint, Collection<String> methodOrClassExitPoints, SmaliMethod originalEntryPoint, int stackLimit, boolean onlyCheckClass) {
        // Avoid circular references
        if (stackLimit > 0 && entryPoint.equals(originalEntryPoint))
            return false;

        // We have to go deeper! Or not...
        if (stackLimit > INVOCATION_FLOW_STACK_LIMIT)
            return false;

        // Contains a collection of methods for further inspections
        Collection<SmaliMethod> invokedMethods = new ArrayList<SmaliMethod>();
        // Contains a mapping from a register name to its class type (only for classes defined in smali files)
        Map<String, SmaliClass> registerLocalTypes = new HashMap<String, SmaliClass>();

        for (SmaliStatement statement : entryPoint.getInterestingStatements()) {
            if (!statement.is(SmaliInvocationStatement.class))
                continue;

            SmaliInvocationStatement invocationStatement = (SmaliInvocationStatement) statement;
            SmaliMemberName invokedMethodName = invocationStatement.getMethodName();
            String searchTarget;

            // If we only care about which class a method is invoked from
            if (onlyCheckClass)
                searchTarget = invokedMethodName.getClassName().getCompleteName();
            else
                searchTarget = invokedMethodName.getCompleteName();

            // If this method invocation is within our blacklist, the search ends in success
            if (methodOrClassExitPoints.contains(searchTarget))
                return true;

            // A new thread has been created. We can look into its Runnable target for further inspections
            if (invokedMethodName.equals(THREAD_CONSTRUCTOR) && invocationStatement.getParameters().size() > 1) {
                List<String> parameterTypes = invocationStatement.getParameterTypes();
                String registerArgument = null;

                // Since Thread has multiple overloaded constructors, check for the parameter index associated to
                // the correct parameter (i.e. a Runnable instance). Luckily, smali invocations report exact signatures
                for (int i = 0; i < parameterTypes.size(); i++)
                    if (parameterTypes.get(i).equals(RUNNABLE))
                        registerArgument = invocationStatement.getParameters().get(i + 1);

                // If a runnable is passed to the constructor and we have previously seen that register associated
                // with a specific class, then the run method of that class is reachable through this code
                if ((registerArgument != null) && registerLocalTypes.containsKey(registerArgument)) {
                    SmaliClass runnableClass = registerLocalTypes.get(registerArgument);
                    SmaliMethod runMethod = runnableClass.getMethodByName(RUNNABLE_RUN);

                    if (runMethod != null)
                        invokedMethods.add(runMethod);
                }
            }

            // Otherwise, if the invoked method is coded within another smali file, keep looking at its
            // content recursively
            SmaliClass targetClass = classCollection.getClassByName(invokedMethodName.getClassName());

            if (targetClass != null) {
                // A constructor method is being called
                if (invokedMethodName.getMemberName().equals(CONSTRUCTOR)) {
                    // This register contains an instance of the class type on which the constructor is being invoked
                    String register = invocationStatement.getParameters().get(0);
                    registerLocalTypes.put(register, targetClass);
                }

                SmaliMethod invokedMethod = targetClass.getMethodByName(invokedMethodName);

                if ((invokedMethod == null) || (stackLimit == INVOCATION_FLOW_STACK_LIMIT))
                    continue;

                // Add the method for later inspection. This is a semi-breadth-first semi-depth-first analysis
                invokedMethods.add(invokedMethod);
            }
        }

        registerLocalTypes.clear();
        registerLocalTypes = null;

        // Checks if any of our callees is reachable through a further method invocation
        for (SmaliMethod invokedMethod : invokedMethods) {
            if (flowExists(invokedMethod, methodOrClassExitPoints, originalEntryPoint, stackLimit + 1, onlyCheckClass))
                return true;
        }

        // If anything else fails, return false
        return false;
    }

    private static final String CONSTRUCTOR = "<init>";
    private static final String RUNNABLE = "Ljava/lang/Runnable;";

    private static final SmaliMemberName RUNNABLE_RUN = new SmaliMemberName("Ljava/lang/Runnable;->run");
    private static final SmaliMemberName THREAD_CONSTRUCTOR = new SmaliMemberName("Ljava/lang/Thread;-><init>");
}
