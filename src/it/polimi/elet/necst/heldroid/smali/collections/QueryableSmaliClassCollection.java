package it.polimi.elet.necst.heldroid.smali.collections;

import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;

import java.util.*;

public class QueryableSmaliClassCollection implements Collection<SmaliClass> {
    private Collection<SmaliClass> innerCollection;
    private Map<String, SmaliClass> quickClassesMap;

    public QueryableSmaliClassCollection() {
        this.innerCollection = new ArrayList<SmaliClass>();
    }

    public QueryableSmaliClassCollection(Collection<SmaliClass> classCollection) {
        this.innerCollection = classCollection;
    }

    public SmaliClass getClassByName(SmaliClassName className) {
        String completeClassName = className.getCompleteName();

        if (quickClassesMap != null)
            return quickClassesMap.get(completeClassName);

        SmaliClass result = null;

        quickClassesMap = new HashMap<String, SmaliClass>();

        for (SmaliClass klass : innerCollection) {
            quickClassesMap.put(klass.getName().getCompleteName(), klass);

            if (klass.getName().getCompleteName().equals(completeClassName))
                result = klass;
        }

        return result;
    }

    /***
     * Checks whether a class extends another known class (usually from android api).
     * @param klass Instance of SmaliClass to check.
     * @param baseClassName Complete smali name of the base class.
     * @return Returns true iif klass is a subclass of the class determined by baseClassCompleteName, even directly
     *     or indirectly (through any other class defined in the inspector files).
     */
    public boolean classExtends(SmaliClass klass, SmaliClassName baseClassName) {
        SmaliClassName superClassName = klass.getSuperClassName();

        if (superClassName == null)
            return false;

        if (superClassName.equals(baseClassName))
            return true;

        SmaliClass base = this.getClassByName(klass.getSuperClassName());

        if (base != null)
            return this.classExtends(base, baseClassName);

        return false;
    }

    @Override
    public int size() {
        return innerCollection.size();
    }

    @Override
    public boolean isEmpty() {
        return innerCollection.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return innerCollection.contains(o);
    }

    @Override
    public Iterator<SmaliClass> iterator() {
        return innerCollection.iterator();
    }

    @Override
    public Object[] toArray() {
        return innerCollection.toArray();
    }

    @Override
    public <T> T[] toArray(T[] ts) {
        return innerCollection.toArray(ts);
    }

    @Override
    public boolean add(SmaliClass smaliClass) {
        if (quickClassesMap != null)
            quickClassesMap.put(smaliClass.getName().getCompleteName(), smaliClass);

        return innerCollection.add(smaliClass);
    }

    @Override
    public boolean remove(Object o) {
        if (o.getClass().equals(SmaliClass.class) && (quickClassesMap != null))
            quickClassesMap.remove(((SmaliClass)o).getName().getCompleteName());

        return innerCollection.remove(o);
    }

    @Override
    public boolean containsAll(Collection<?> objects) {
        return innerCollection.containsAll(objects);
    }

    @Override
    public boolean addAll(Collection<? extends SmaliClass> smaliClasses) {
        return innerCollection.addAll(smaliClasses);
    }

    @Override
    public boolean removeAll(Collection<?> objects) {
        return innerCollection.removeAll(objects);
    }

    @Override
    public boolean retainAll(Collection<?> objects) {
        return innerCollection.retainAll(objects);
    }

    @Override
    public void clear() {
        innerCollection.clear();
    }

    @Override
    public boolean equals(Object o) {
        return innerCollection.equals(o);
    }

    @Override
    public int hashCode() {
        return innerCollection.hashCode();
    }
}
