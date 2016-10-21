package it.polimi.elet.necst.heldroid.smali;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import it.polimi.elet.necst.heldroid.pipeline.ThreadedCollectionExecutor;
import it.polimi.elet.necst.heldroid.smali.collections.QueryableSmaliClassCollection;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.core.SmaliField;
import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliPutStatement;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliStatement;
import it.polimi.elet.necst.heldroid.utils.MultiMap;

public class SmaliLoader {
    private static final int FILES_PER_THREAD = 10;
    private static final int MAX_THREADS_COUNT = 4;
    private static final int INVOCATION_FLOW_STACK_LIMIT = 10;

    private Map<String, SmaliClass> quickClassesMap;
    private QueryableSmaliClassCollection classes;
    private MultiMap<String, String> initializedFieldValues;

    private SmaliInspector inspector;

    public int getClassesCount() {
        return classes.size();
    }

    public long getTotalClassesSize() {
        long sum = 0;

        for (SmaliClass klass : classes)
            sum += klass.getSize();

        return sum;
    }

    public Collection<SmaliClass> getClasses() {
        return classes;
    }

    public Collection<SmaliClass> getSubclassesOf(SmaliClassName baseClassName) {
        Collection<SmaliClass> result = new ArrayList<SmaliClass>();

        for (SmaliClass klass : classes)
            if (klass.isSubclassOf(baseClassName))
                result.add(klass);

        return result;
    }

    public SmaliClass getClassByName(SmaliClassName className) {
        return classes.getClassByName(className);
    }


    public SmaliLoader(Collection<SmaliClass> classes) {
        this.classes = new QueryableSmaliClassCollection(classes);

        for (SmaliClass klass : this.classes)
            klass.setAssociatedCollection(this.classes);

        this.selectInitializedFields();
    }

    private SmaliLoader() {
        this.classes = new QueryableSmaliClassCollection();
    }


    public static SmaliLoader onSources(Collection<File> classFiles) {
        final SmaliLoader result = new SmaliLoader();
        ThreadedCollectionExecutor<File> texecutor = new ThreadedCollectionExecutor<File>(MAX_THREADS_COUNT, FILES_PER_THREAD);

        texecutor.setTimeout(10, TimeUnit.SECONDS);
        texecutor.execute(classFiles, new ThreadedCollectionExecutor.ParameterizedRunnable<File>() {
            @Override
            public void run(File file) {
                SmaliClass klass = null;

                try {
                    klass = SmaliClass.parse(file);
                } catch (Exception e) { }

                if (klass == null)
                    return;

                if (Thread.currentThread().isInterrupted())
                    return;

                synchronized (result.classes) {
                    klass.setAssociatedCollection(result.classes);
                    result.classes.add(klass);
                }
            }
        });

        result.selectInitializedFields();
        return result;
    }

    public static SmaliLoader onSource(File smaliSource) throws IOException, SmaliFormatException {
        SmaliLoader result = new SmaliLoader();
        SmaliClass klass = SmaliClass.parse(smaliSource);

        if (klass == null)
            throw new IllegalArgumentException("Not a valid smali source.");

        klass.setAssociatedCollection(result.classes);
        result.classes.add(klass);
        result.selectInitializedFields();

        return result;
    }


    /**
     * Scans all the smali classes collected into this inspector and finds all the values that fields have been assigned
     * either in their declaration (in-line initialization) or in other methods' body (typically in the constructor).
     */
    private void selectInitializedFields() {
        if (initializedFieldValues == null)
            initializedFieldValues = new MultiMap<String, String>();

        synchronized (classes) {
            for (SmaliClass klass : classes) {
                for (SmaliField field : klass.getFields())
                    if (field.getLiteralValue() != null) {
                        SmaliMemberName fieldName = new SmaliMemberName(klass.getName(), field.getName());
                        initializedFieldValues.put(fieldName.getCompleteName(), field.getLiteralValue());
                    }

                for (SmaliMethod method : klass.getMethods()) {
                    final SmaliSimulator simulator = SmaliSimulator.on(method);

                    simulator.addHandler(SmaliPutStatement.class, new SmaliSimulator.StatementHandler() {
                        @Override
                        public boolean statementReached(SmaliStatement statement) {
                            SmaliPutStatement putter = (SmaliPutStatement) statement;
                            SmaliMemberName fieldName = putter.getFieldName();

                            initializedFieldValues.putAll(
                                fieldName.getCompleteName(),
                                simulator.getPossibleValues(putter.getRegister()));

                            return false;
                        }
                    });

                    simulator.simulate();
                }
            }
        }
    }

    public SmaliConstantFinder generateConstantFinder() {
        return new SmaliConstantFinder(classes, initializedFieldValues);
    }

    public SmaliConstantFinder generateConstantFinder(Collection<SmaliClass> classesSubset) {
        return new SmaliConstantFinder(classesSubset, initializedFieldValues);
    }

    public SmaliConstantFinder generateConstantFinder(SmaliClass klass) {
        List<SmaliClass> singleton = new ArrayList<SmaliClass>();
        singleton.add(klass);
        return this.generateConstantFinder(singleton);
    }

    public SmaliInspector generateInspector() {
        if (inspector != null)
            return inspector;

        return (inspector = new SmaliInspector(classes));
    }
}
