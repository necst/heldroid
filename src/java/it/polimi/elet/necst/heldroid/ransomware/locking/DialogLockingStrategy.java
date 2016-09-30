package it.polimi.elet.necst.heldroid.ransomware.locking;

import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

import java.util.ArrayList;
import java.util.Collection;

public class DialogLockingStrategy extends SmaliLockingStrategy {
    private static final SmaliClassName ALERT_DIALOG = new SmaliClassName("Landroid/app/AlertDialog;");
    private static final SmaliMemberName SET_FLAGS = new SmaliMemberName("Landroid/view/Window;->setFlags");
    private static final int FLAG_SHOW_WHEN_LOCKED = 0x00080000;

    private static Collection<String> zeroCodes;

    static {
        zeroCodes = new ArrayList<String>();
        zeroCodes.add("0x00");
        zeroCodes.add("0x0");
        zeroCodes.add("0");
    }

    @Override
    protected boolean detectStrategy() {
        Collection<SmaliClass> alertDialogs = this.getAlertDialogs();

        if (alertDialogs.size() == 0)
            return false;

        for (SmaliClass dialog : alertDialogs)
            if (this.isDialogImmortal(dialog))
                return true;

        return false;
    }

    private Collection<SmaliClass> getAlertDialogs() {
        return this.loader.getSubclassesOf(ALERT_DIALOG);
    }

    private boolean isDialogImmortal(SmaliClass dialog) {
        SmaliConstantFinder finder = this.loader.generateConstantFinder(dialog);
        SmaliMemberName setCancelable = new SmaliMemberName(dialog.getName(), "setCancelable");

        final Wrapper<Boolean> isUncancelable = new Wrapper<Boolean>(false);
        final Wrapper<Boolean> showWhenLocked = new Wrapper<Boolean>(false);

        finder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                return (isUncancelable.value = zeroCodes.contains(value));
            }
        });

        finder.searchParameters(setCancelable, 0);

        finder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                String literal = value;
                int radix = 10;

                if (value.contains("0x")) {
                    literal = value.replace("0x", "");
                    radix = 16;
                }

                try {
                    int number = Integer.parseInt(literal, radix);
                    if ((number & FLAG_SHOW_WHEN_LOCKED) != 0)
                        return (showWhenLocked.value = true);
                } catch (NumberFormatException nfex) { }

                return false;
            }
        });

        finder.searchParameters(SET_FLAGS, 0);

        return isUncancelable.value && showWhenLocked.value;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected String strategyName() {
    	return "Dialog";
    }
}
