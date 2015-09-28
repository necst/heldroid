package it.polimi.elet.necst.heldroid.ransomware.locking;

import it.polimi.elet.necst.heldroid.pipeline.FileTree;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliInspector;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.apk.DecodedPackage;

public abstract class  SmaliLockingStrategy extends LockingStrategy {
    protected SmaliLoader loader;
    protected SmaliInspector inspector;
    protected SmaliConstantFinder constantFinder;

    @Override
    public void setTarget(DecodedPackage target) {
        if (!target.getSmaliDirectory().exists())
            throw new RuntimeException("Smali directory doesn't exist!");

        FileTree smaliTree = new FileTree(target.getSmaliDirectory());

        this.loader = SmaliLoader.onSources(smaliTree.getAllFiles());
        this.inspector = loader.generateInspector();
        this.constantFinder = loader.generateConstantFinder();

        this.target = target;
    }

    public void setTarget(DecodedPackage target, SmaliLoader loader, SmaliInspector inspector, SmaliConstantFinder constantFinder) {
        this.target = target;
        this.loader = loader;
        this.inspector = inspector;
        this.constantFinder = constantFinder;
    }
}
