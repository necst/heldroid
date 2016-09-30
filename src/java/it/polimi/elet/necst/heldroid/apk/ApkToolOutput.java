package it.polimi.elet.necst.heldroid.apk;

import it.polimi.elet.necst.heldroid.utils.FileSystem;

import java.io.File;
import java.io.FileNotFoundException;

class ApkToolOutput implements DecodedPackage {
    private File classesDex, androidManifest, decodedDirectory, originalApk, smaliDirectory, resourcesDirectory;

    @Override
    public File getClassesDex() {
        return classesDex;
    }

    @Override
    public File getAndroidManifest() {
        return androidManifest;
    }

    @Override
    public File getDecodedDirectory() {
        return decodedDirectory;
    }

    @Override
    public File getOriginalApk() {
        return originalApk;
    }
    
    @Override
    public File getResourcesDirectory() {
    	return resourcesDirectory;
    }

    @Override
    public File getSmaliDirectory() { return smaliDirectory; }

    @Override
    public void dispose() {
        FileSystem.deleteDirectory(decodedDirectory);
    }

    public ApkToolOutput(File originalApk, File mainDirectory) throws FileNotFoundException {
        this.decodedDirectory = mainDirectory;
        this.originalApk = originalApk;

        File dex = new File(mainDirectory, CLASSES_DEX_FILE_NAME);
        File xml = new File(mainDirectory, ANDROID_MANIFEST_FILE_NAME);
        File res = new File(mainDirectory, RESOURCES_DIRECTORY_NAME);

        if (!xml.exists())
            throw new FileNotFoundException(ANDROID_MANIFEST_FILE_NAME +  " is missing!");

        this.classesDex = dex;
        this.androidManifest = xml;
        this.smaliDirectory = new File(mainDirectory, SMALI_DIRECTORY_NAME);
        this.resourcesDirectory = res;
    }
}
