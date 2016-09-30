package it.polimi.elet.necst.heldroid.apk;

import java.io.File;

public interface PackageDecoder {
    DecodedPackage decode(File apkFile) throws DecodingException;
}
