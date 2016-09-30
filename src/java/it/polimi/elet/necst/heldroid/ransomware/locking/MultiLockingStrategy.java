package it.polimi.elet.necst.heldroid.ransomware.locking;

import it.polimi.elet.necst.heldroid.pipeline.FileTree;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliInspector;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.apk.DecodedPackage;

import java.util.ArrayList;
import java.util.List;

public class MultiLockingStrategy extends LockingStrategy {
    private List<LockingStrategy> lockingStrategies;
    private boolean needsSmali;

    private SmaliLoader loader;
    private SmaliInspector inspector;
    private SmaliConstantFinder constantFinder;
	private String successfulStrategy;

    public MultiLockingStrategy() {
        this.lockingStrategies = new ArrayList<LockingStrategy>();
        this.needsSmali = false;
    }

    public void add(LockingStrategy strategy) {
        this.lockingStrategies.add(strategy);

        if (strategy instanceof SmaliLockingStrategy)
            this.needsSmali = true;
    }

    @Override
    public void setTarget(DecodedPackage target) {
        super.setTarget(target);

        if (needsSmali) {
            if (!target.getSmaliDirectory().exists())
                throw new RuntimeException("Smali directory doesn't exist!");

            FileTree smaliTree = new FileTree(target.getSmaliDirectory());

            this.loader = SmaliLoader.onSources(smaliTree.getAllFiles());
            this.inspector = loader.generateInspector();
            this.constantFinder = loader.generateConstantFinder();
        }

        for (LockingStrategy strategy : lockingStrategies)
            if (strategy instanceof SmaliLockingStrategy)
                ((SmaliLockingStrategy)strategy).setTarget(target, loader, inspector, constantFinder);
            else
                strategy.setTarget(target);
    }

    @Override
    protected boolean detectStrategy() {
        for (LockingStrategy strategy : lockingStrategies)
            if (strategy.detect()) {
            	this.successfulStrategy = strategy.strategyName();
                return true;
            }

        return false;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected String strategyName() {
    	return "MultiLockingStrategy";
    }
    
    public String getSuccessfulStrategy() {
    	return this.successfulStrategy;
    }
}
