package it.polimi.elet.necst.heldroid.pipeline;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.apk.DecodingException;
import it.polimi.elet.necst.heldroid.apk.PackageDecoder;
import it.polimi.elet.necst.heldroid.apk.PackageDecoders;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.xml.ParsingException;
import it.polimi.elet.necst.heldroid.xml.manifest.ManifestAnalysisReport;
import it.polimi.elet.necst.heldroid.xml.manifest.ManifestAnalyzer;
import it.polimi.elet.necst.heldroid.xml.manifest.ManifestAnalyzers;
import it.polimi.elet.necst.heldroid.xml.resources.StringResource;
import it.polimi.elet.necst.heldroid.xml.resources.StringResourceMetaParser;
import it.polimi.elet.necst.heldroid.xml.resources.StringResourceParsers;

import java.io.File;

public class ApplicationData {
    private static PackageDecoder decoder;
    private static StringResourceMetaParser parser;
    private static ManifestAnalyzer analyzer;

    private DecodedPackage decodedPackage;
    private ManifestAnalysisReport manifestReport;
    private StringResource stringResource;
    private FileTree decodedFileTree;
    private SmaliLoader smaliLoader;

    public DecodedPackage getDecodedPackage() {
        return decodedPackage;
    }

    public ManifestAnalysisReport getManifestReport() {
        return manifestReport;
    }

    public StringResource getStringResource() {
        return stringResource;
    }

    public synchronized FileTree getDecodedFileTree() {
        if (decodedFileTree != null)
            return decodedFileTree;

        return (decodedFileTree = new FileTree(decodedPackage.getDecodedDirectory()));
    }

    public synchronized SmaliLoader getSmaliLoader() {
        if (smaliLoader != null)
            return smaliLoader;

        return (smaliLoader = SmaliLoader.onSources(this.getDecodedFileTree().getAllFilesIn(decodedPackage.getSmaliDirectory())));
    }

    private ApplicationData() { }


    public static ApplicationData open(File file) throws ParsingException, DecodingException {
        ApplicationData result = null;

        if (isApkFile(file))
            result = extract(file);
        else if (isUnpackedApkDirectory(file)) {
            result = read(file);
        }

        if (result != null)
        {
            try {
                result.getSmaliLoader();
            } catch (Exception ex) {
                throw new DecodingException("Invalid smali files.");
            }

            return result;
        }

        throw new DecodingException(file.getAbsolutePath() + " is not a valid android package.");
    }

    private static boolean isUnpackedApkDirectory(File directory) {
        File manifest = new File(directory, "AndroidManifest.xml");
        return manifest.exists();
    }

    private static boolean isApkFile(File file) {
        return file.getName().toLowerCase().endsWith(".apk");
    }

    private static ApplicationData extract(File apk) throws DecodingException, ParsingException {
        DecodedPackage decodedPackage;

        if (decoder == null)
            decoder = PackageDecoders.apkTool();

        decodedPackage = decoder.decode(apk);

        return process(decodedPackage);
    }

    private static ApplicationData read(File unpackedApkDirectory) throws ParsingException {
        final File mainDirectory = unpackedApkDirectory;
        DecodedPackage decodedPackage = new DecodedPackage() {
            @Override
            public File getClassesDex() {
                return new File(mainDirectory, "classes.dex");
            }
            
            @Override
            public File getResourcesDirectory() {
            	throw new UnsupportedOperationException("This method is not implemented yet");
            }

            @Override
            public File getAndroidManifest() {
                return new File(mainDirectory, "AndroidManifest.xml");
            }

            @Override
            public File getDecodedDirectory() {
                return mainDirectory;
            }

            @Override
            public File getSmaliDirectory() {
                return new File(mainDirectory, "it/polimi/elet/necst/heldroid/smali");
            }

            @Override
            public File getOriginalApk() {
                return mainDirectory;
            }

            @Override
            public void dispose() { /* Do nothing, since directory is not created by the application */ }
        };

        return process(decodedPackage);
    }

    private static ApplicationData process(DecodedPackage decodedPackage) throws ParsingException {
        ApplicationData result = new ApplicationData();

        result.decodedPackage = decodedPackage;

        if (parser == null)
            parser = new StringResourceMetaParser(StringResourceParsers.domBased());

        result.stringResource = parser.parseDirectory(decodedPackage.getDecodedDirectory());

        if (analyzer == null)
            analyzer = ManifestAnalyzers.domBased(result.stringResource);

        result.manifestReport = analyzer.analyze(decodedPackage.getAndroidManifest());

        return result;
    }


    public void dispose() {
        decodedPackage.dispose();
    }
}
