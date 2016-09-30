package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;

public class SystemCallsFilter extends FeatureGatherer {
    private static final String FEATURE_PREFIX = "Calls a System Routine: ";
    private static final SmaliMemberName EXEC = new SmaliMemberName("Ljava/lang/Runtime;->exec");
    private static final int COMMAND_PARAMETER_INDEX = 0;

    private boolean[] commandFound;

    public SystemCallsFilter() {
        this.commandFound = new boolean[DANGEROUS_COMMANDS.length];
    }

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    private void reset() {
        for (int i = 0; i < commandFound.length; i++)
            commandFound[i] = false;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        if (!super.isAnyFeatureEnabled(FEATURE_PREFIX))
            return false;

        SmaliLoader loader = applicationData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        this.reset();

        boolean result = false;

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                for (int i = 0; i < DANGEROUS_COMMANDS.length; i++)
                    if (value.contains(DANGEROUS_COMMANDS[i]))
                        commandFound[i] = true;

                return false;
            }
        });

        constantFinder.searchParameters(EXEC, COMMAND_PARAMETER_INDEX);

        for (int i = 0; i < DANGEROUS_COMMANDS.length; i++) {
            super.setFeatureValue(i, commandFound[i]);

            if (commandFound[i])
                result = true;
        }

        return result;
    }

    @Override
    protected void defineFeatures() {
        for (int i = 0; i < DANGEROUS_COMMANDS.length; i++)
            super.addFeature(FEATURE_PREFIX + DANGEROUS_COMMANDS[i]);
    }

    private static final String[] DANGEROUS_COMMANDS = {
            "su", "ls", "loadjar", "grep",
            "/sh", "/bin", "pm install", "/dev/net", "insmod",
            "rm", "mount", "root", "/system", "stdout",
            "reboot", "killall", "chmod", "stderr", "ratc"
    };
}
