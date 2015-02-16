package it.polimi.elet.necst.heldroid.ransomware.encryption;

import it.polimi.elet.necst.heldroid.pipeline.FileTree;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.SmaliSimulator;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.smali.statements.*;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.apk.DecodedPackage;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class GlobalEncryptionDetector {
    private static final SmaliMemberName GET_EXTERNAL_STORAGE = new SmaliMemberName("Landroid/os/Environment;->getExternalStorageDirectory");
    private static final SmaliMemberName NEW_CIPHER_OUTPUT_STREAM = new SmaliMemberName("Ljavax/crypto/CipherOutputStream;-><init>");

    private DecodedPackage target;
    private SmaliLoader loader;

    private final Wrapper<Boolean> encryptionFlowFound = new Wrapper<Boolean>();
    private int maxAnalysisNesting = 7;


    public void setTarget(DecodedPackage target) {
        this.target = target;
    }

    public void setMaxAnalysisNesting(int maxAnalysisNesting) {
        this.maxAnalysisNesting = maxAnalysisNesting;
    }


    public boolean detect() {
        if (target == null)
            throw new NullPointerException("target not set!");

        FileTree smaliTree = new FileTree(target.getSmaliDirectory());

        this.encryptionFlowFound.value = false;
        this.loader = SmaliLoader.onSources(smaliTree.getAllFiles());

        List<SmaliMethod> entryPoints = this.findDetectionEntryPoints();

        if (entryPoints.size() == 0)
            return false;

        for (SmaliMethod entryPoint : entryPoints)
            if (reachesEncryption(entryPoint))
                return true;

        return false;
    }

    private List<SmaliMethod> findDetectionEntryPoints() {
        List<SmaliMethod> result = new ArrayList<SmaliMethod>();

        for (SmaliClass klass : loader.getClasses())
            for (SmaliMethod method : klass.getMethods())
                for (SmaliStatement statement : method.getInterestingStatements())
                    if (statement.is(SmaliInvocationStatement.class)) {
                        SmaliInvocationStatement invocation = (SmaliInvocationStatement)statement;
                        if (invocation.getMethodName().equals(GET_EXTERNAL_STORAGE))
                            result.add(method);
                    }

        return result;
    }

    private boolean reachesEncryption(SmaliMethod method) {
        final SmaliSimulator simulator = SmaliSimulator.on(method);
        final Set<String> taintedLocations = new HashSet<String>();

        // Looks among invocations to find a call to getExternalStorageDirectory
        simulator.addHandler(SmaliInvocationStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliInvocationStatement invocation = (SmaliInvocationStatement)statement;

                if (invocation.getMethodName().equals(GET_EXTERNAL_STORAGE)) {
                    // When getExternalStorageDirectory is invoked, its result must be tainted
                    // and it constitutes the source of tainting for this analysis
                    simulator.addHandler(SmaliMoveResultStatement.class, new SmaliSimulator.StatementHandler() {
                        @Override
                        public boolean statementReached(SmaliStatement statement) {
                            SmaliMoveResultStatement moveResult = (SmaliMoveResultStatement)statement;
                            taintedLocations.add(moveResult.getDestination());
                            simulator.removeHandler(SmaliMoveResultStatement.class);
                            return encryptionFlowFound.value;
                        }
                    });

                    // Removes this handler to avoid conflicts with other handlers
                    simulator.removeHandler(SmaliInvocationStatement.class);

                    // Adds a series of instrumentation handlers to keep track of the taint
                    instrument(simulator, taintedLocations, 1);
                }

                return encryptionFlowFound.value;
            }
        });

        simulator.simulate();

        return encryptionFlowFound.value;
    }

    private void instrument(final SmaliSimulator simulator, final Set<String> taintedLocations, final int level) {
        if (level > maxAnalysisNesting)
            return;

        this.instrumentMove(simulator, taintedLocations);
        this.instrumentFieldAccess(simulator, taintedLocations);
        this.instrumentArrayAccess(simulator, taintedLocations);
        this.instrumentInvocation(simulator, taintedLocations, level);
    }

    private void instrumentMove(final SmaliSimulator simulator, final Set<String> taintedLocations) {
        simulator.addHandler(SmaliMoveStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliMoveStatement move = (SmaliMoveStatement)statement;
                propagateTaint(taintedLocations, move.getSource(), move.getDestination());
                return encryptionFlowFound.value;
            }
        });
    }

    private void instrumentFieldAccess(final SmaliSimulator simulator, final Set<String> taintedLocations) {
        // PUT
        simulator.addHandler(SmaliPutStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliPutStatement put = (SmaliPutStatement)statement;
                propagateTaint(taintedLocations, put.getRegister(), put.getFieldName().getCompleteName());
                return encryptionFlowFound.value;
            }
        });

        // GET
        simulator.addHandler(SmaliGetStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliGetStatement get = (SmaliGetStatement)statement;
                propagateTaint(taintedLocations, get.getFieldName().getCompleteName(), get.getRegister());
                return encryptionFlowFound.value;
            }
        });
    }

    private void instrumentArrayAccess(final SmaliSimulator simulator, final Set<String> taintedLocations) {
        // ARRAY PUT
        simulator.addHandler(SmaliArrayPutStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliArrayPutStatement put = (SmaliArrayPutStatement)statement;
                propagateTaint(taintedLocations, put.getTargetRegister(), put.getArrayRegister());
                return encryptionFlowFound.value;
            }
        });

        // ARRAY GET
        simulator.addHandler(SmaliArrayGetStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliArrayGetStatement get = (SmaliArrayGetStatement)statement;
                propagateTaint(taintedLocations, get.getArrayRegister(), get.getTargetRegister());
                return encryptionFlowFound.value;
            }
        });
    }

    private void instrumentInvocation(final SmaliSimulator simulator, final Set<String> taintedLocations, final int level) {
        simulator.addHandler(SmaliInvocationStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliInvocationStatement invocation = (SmaliInvocationStatement)statement;
                SmaliClassName className = invocation.getMethodName().getClassName();
                SmaliClass klass = loader.getClassByName(className);
                List<String> parameters = invocation.getParameters();

                simulator.removeHandler(SmaliMoveResultStatement.class);

                // Invocation to an external method
                if (klass == null) {
                    boolean taintResult = false;

                    for (String param : parameters)
                        if (taintedLocations.contains(param)) {
                            taintResult = true;
                            break;
                        }

                    if (taintResult) {
                        // A flow has been found that leas from getExternalStorage to encryption: return with success
                        if (invocation.getMethodName().equals(NEW_CIPHER_OUTPUT_STREAM))
                            return (encryptionFlowFound.value = true);

                        // If any parameter is tainted, the invocation result is tainted too, so add an handler
                        // for the next move-result. Notice that move-result handlers are reset at the beginning of this handler
                        instrumentNextMoveResult(simulator, taintedLocations);

                        // Also the object on which the method is invoked becomes tainted
                        if (!invocation.getQualifier().contains("static"))
                            taintedLocations.add(parameters.get(0));
                    }
                } else {
                    final SmaliMethod target = klass.getMethodBySignature(invocation.getMethodName(), invocation.getParameterTypes());

                    if (target == null)
                        return encryptionFlowFound.value;

                    final SmaliSimulator innerSimulator = SmaliSimulator.on(target);
                    final Set<String> innerTaintedLocations = new HashSet<String>();

                    for (int i = 0; i < parameters.size(); i++)
                        if (taintedLocations.contains(parameters.get(i)))
                            innerTaintedLocations.add(String.format("p%d", i));

                    instrument(innerSimulator, innerTaintedLocations, level + 1);

                    // If target method returns something tainted, the next move-result will propagate the taint
                    innerSimulator.addHandler(SmaliReturnStatement.class, new SmaliSimulator.StatementHandler() {
                        @Override
                        public boolean statementReached(SmaliStatement statement) {
                            if (innerTaintedLocations.contains(((SmaliReturnStatement)statement).getRegister()))
                                instrumentNextMoveResult(simulator, taintedLocations);
                            return encryptionFlowFound.value;
                        }
                    });

                    innerSimulator.simulate();

                    for (String taint : innerTaintedLocations)
                        if (taint.startsWith("L"))
                            taintedLocations.add(taint);
                }

                return encryptionFlowFound.value;
            }
        });
    }

    private void instrumentNextMoveResult(final SmaliSimulator simulator, final Set<String> taintedLocations) {
        simulator.addHandler(SmaliMoveResultStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                taintedLocations.add(((SmaliMoveResultStatement)statement).getDestination());
                simulator.removeHandler(SmaliMoveResultStatement.class);
                return encryptionFlowFound.value;
            }
        });
    }

    private static void propagateTaint(final Set<String> taintedLocation, String source, String destination) {
        if (taintedLocation.contains(source))
            taintedLocation.add(destination);
        else
            taintedLocation.remove(destination);
    }
}
