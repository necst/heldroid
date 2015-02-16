package it.polimi.elet.necst.heldroid.goodware.ripper;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliInvocationStatement;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliStatement;
import it.polimi.elet.necst.heldroid.utils.Literal;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class FeatureRipper {
    private BufferedWriter writer;
    private ApplicationData currentData;

    private Collection<String> permissions, intentFilters, usedFeatures;
    private Collection<String> androidApis, otherApis, packageNames;
    private Collection<String> hosts, phoneNumbers, osPrimitives, contents;
    private Collection<String> activities, services, receivers, providers;

    public FeatureRipper(File outputFile) throws IOException {
        this.writer = new BufferedWriter(new FileWriter(outputFile));
    }

    public void rip(ApplicationData applicationData) {
        this.currentData = applicationData;

        ExecutorService executor = Executors.newFixedThreadPool(8);

        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripPermissions();
            }
        });
        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripIntentFilters();
            }
        });
        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripUsedFeatures();
            }
        });
        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripApisAndPackageNames();
            }
        });
        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripHostsAndContents();
            }
        });
        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripPhoneNumbers();
            }
        });
        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripOsPrimitives();
            }
        });
        executor.execute(new Runnable() {
            @Override
            public void run() {
                ripClasses();
            }
        });

        try {
            executor.shutdown();
            if (!executor.awaitTermination(10, TimeUnit.SECONDS))
                executor.shutdownNow();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void writeout(Double detectionRatio, boolean adware) {
        try {
            writer.write("APK:");
            writer.write(currentData.getDecodedPackage().getOriginalApk().getAbsolutePath());
            writer.newLine();

            writer.write("PERMISSIONS:");
            writer.write(makeStringList(permissions));
            writer.newLine();

            writer.write("INTENT_FILTERS:");
            writer.write(makeStringList(intentFilters));
            writer.newLine();

            writer.write("USED_FEATURES:");
            writer.write(makeStringList(usedFeatures));
            writer.newLine();

            writer.write("ANDROID_APIS:");
            writer.write(makeStringList(androidApis));
            writer.newLine();

            writer.write("OTHER_APIS:");
            writer.write(makeStringList(otherApis));
            writer.newLine();

            writer.write("PACKAGE_NAMES:");
            writer.write(makeStringList(packageNames));
            writer.newLine();

            writer.write("HOSTS:");
            writer.write(makeStringList(hosts));
            writer.newLine();

            writer.write("PHONE_NUMBERS:");
            writer.write(makeStringList(phoneNumbers));
            writer.newLine();

            writer.write("OS_PRIMITIVES:");
            writer.write(makeStringList(osPrimitives));
            writer.newLine();

            writer.write("CONTENTS:");
            writer.write(makeStringList(contents));
            writer.newLine();

            writer.write("ACTIVITIES:");
            writer.write(makeStringList(activities));
            writer.newLine();

            writer.write("SERVICES:");
            writer.write(makeStringList(services));
            writer.newLine();

            writer.write("RECEIVERS:");
            writer.write(makeStringList(receivers));
            writer.newLine();

            writer.write("PROVIDERS:");
            writer.write(makeStringList(providers));
            writer.newLine();

            writer.write("DETECTION_RATIO:");
            writer.write(detectionRatio == null ? "?" : String.valueOf(detectionRatio));
            writer.newLine();

            writer.write("ADWARE:");
            writer.write(String.valueOf(adware));
            writer.newLine();

            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void ripPermissions() {
        permissions = currentData.getManifestReport().getPermissions();
    }

    private void ripIntentFilters() {
        intentFilters = new ArrayList<String>(currentData.getManifestReport().getIntentFilters());

        SmaliLoader loader = currentData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String intentName) {
                if (Literal.isString(intentName))
                    intentFilters.add(Literal.getStringValue(intentName));

                return false;
            }
        });

        constantFinder.searchParameters(new SmaliMemberName("Landroid/content/IntentFilter->addAction"), 0);
        constantFinder.searchParameters(new SmaliMemberName("Landroid/content/IntentFilter;-><init>"), 0);
    }

    private void ripUsedFeatures() {
        this.usedFeatures = currentData.getManifestReport().getUsedFeatures();
    }

    private void ripApisAndPackageNames() {
        androidApis = new HashSet<String>();
        otherApis = new HashSet<String>();
        packageNames = new HashSet<String>();

        SmaliLoader loader = currentData.getSmaliLoader();

        for (SmaliClass klass : loader.getClasses()) {
            packageNames.add(klass.getName().getPackageName());

            for (SmaliMethod method : klass.getMethods())
                for (SmaliStatement statement : method.getInterestingStatements()) {
                    if (!statement.is(SmaliInvocationStatement.class))
                        continue;

                    SmaliInvocationStatement invocation = (SmaliInvocationStatement) statement;
                    SmaliMemberName invokedName = invocation.getMethodName();

                    if (invokedName.getCompleteName().startsWith("Landroid"))
                        androidApis.add(invokedName.getCompleteName());
                    else if ((otherApis.size() < OTHER_APIS.size()) && OTHER_APIS.contains(invokedName.getCompleteName()))
                        otherApis.add(invokedName.getCompleteName());
                }
        }
    }

    private void ripHostsAndContents() {
        hosts = new HashSet<String>();
        contents = new HashSet<String>();

        SmaliLoader loader = currentData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                if (!Literal.isString(value))
                    return false;

                String literal = Literal.getStringValue(value);

                if (literal.startsWith("content://")) {
                    contents.add(literal);
                    return false;
                }

                try {
                    URL url = new URL(literal);
                    String host = url.getHost();
                    hosts.add(host);
                } catch (MalformedURLException e) { }

                return false;
            }
        });

        constantFinder.searchAllLiterals();
    }

    private void ripPhoneNumbers() {
        phoneNumbers = new HashSet<String>();

        SmaliLoader loader = currentData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                if (!Literal.isString(value))
                    return false;

                String literal = Literal.getStringValue(value);

                if (!isPhoneNumber(literal))
                    return false;

                if (isSuspiciousNumber(literal))
                    phoneNumbers.add(literal);

                return false;
            }
        });

        constantFinder.searchParameters(new SmaliMemberName("Landroid/telephony/SmsManager;->sendTextMessage"), 0);
    }

    private void ripOsPrimitives() {
        osPrimitives = new HashSet<String>();

        SmaliLoader loader = currentData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                if (!Literal.isString(value))
                    return false;

                String literal = Literal.getStringValue(value);
                osPrimitives.add(literal);

                return false;
            }
        });

        constantFinder.searchParameters(new SmaliMemberName("Ljava/lang/Runtime;->exec"), 0);
    }

    private void ripClasses() {
        activities = new ArrayList<String>();
        services = new ArrayList<String>();
        receivers = new ArrayList<String>();
        providers = new ArrayList<String>();

        SmaliLoader loader = currentData.getSmaliLoader();

        for (SmaliClass klass : loader.getClasses()) {
            if (klass.isSubclassOf(ACTIVITY))
                activities.add(klass.getName().getSimpleName());
            else if (klass.isSubclassOf(SERVICE))
                services.add(klass.getName().getSimpleName());
            else if (klass.isSubclassOf(RECEIVER))
                receivers.add(klass.getName().getSimpleName());
            else if (klass.isSubclassOf(PROVIDER))
                providers.add(klass.getName().getSimpleName());
        }
    }

    private boolean isPhoneNumber(String literal) {
        boolean prefix = true;
        boolean isNumber = true;

        for (Character c : literal.toCharArray()) {
            if (!Character.isDigit(c)) {
                if (prefix && c.equals(ALLOWED_NUMBER_PREFIXE))
                    continue;

                isNumber = false;
                break;
            }

            prefix = false;
        }

        return isNumber;
    }

    private boolean isSuspiciousNumber(String number) {
        boolean isCarrierServiceNumber = false;

        for (String prefix : CARRIER_NUMBERS_PREFIXES)
            if (number.startsWith(prefix)) {
                isCarrierServiceNumber = true;
                break;
            }

        return !isCarrierServiceNumber;
    }

    private String makeStringList(Collection<String> strings) {
        StringBuilder builder = new StringBuilder();
        int i = 0;

        for (String str : strings) {
            if (i++ > 0) builder.append(",");
            builder.append(str);
        }

        return builder.toString();
    }

    private static final String[] CARRIER_NUMBERS_PREFIXES = { "#", "*" };
    private static final Character ALLOWED_NUMBER_PREFIXE =  '+';

    private static final SmaliClassName ACTIVITY = new SmaliClassName("Landroid/app/Activity;");
    private static final SmaliClassName SERVICE = new SmaliClassName("Landroid/app/Service;");
    private static final SmaliClassName RECEIVER = new SmaliClassName("Landroid/content/BroadcastReceiver;");
    private static final SmaliClassName PROVIDER = new SmaliClassName("Landroid/content/ContentProvider;");

    private static List<String> OTHER_APIS = Arrays.asList(
            "Ljava/lang/System;->loadLibrary",
            "Ljavax/crypto/Cipher;->getInstance",
            "Ljava/lang/Runtime;->exec"
    );
}
