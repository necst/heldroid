package it.polimi.elet.necst.heldroid.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class FileSystem {
    public static boolean deleteDirectory(File directory) {
        if (isUnix()) {
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"rm", "-rf", directory.getAbsolutePath()});

                exhaustStreamAsync(p.getInputStream());
                exhaustStreamAsync(p.getErrorStream());

                p.waitFor();
            } catch (Exception e) {
                return false;
            }
        } else {
            for (File file : directory.listFiles()) {
                if (file.isDirectory())
                    deleteDirectory(file);
                else
                    file.delete();
            }

            return (directory.delete());
        }

        return true;
    }

    private static void exhaustStream(InputStream inputStream) {
        InputStreamReader reader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(reader);

        try {
            while (bufferedReader.readLine() != null)
                ;
            inputStream.close();
        } catch (IOException e) { }
    }

    private static void exhaustStreamAsync(final InputStream inputStream) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                exhaustStream(inputStream);
            }
        }).start();
    }

    private static boolean isUnix() {
        return (File.separatorChar == '/');
    }

    public static String readFileAsString(File file) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder stringBuilder = new StringBuilder();
        String line = null;

        while((line = reader.readLine()) != null) {
            stringBuilder.append(line);
            stringBuilder.append("\n");
        }

        return stringBuilder.toString();
    }

    public static String hashOf(File file) throws IOException {
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        InputStream stream = new FileInputStream(file);
        DigestInputStream digestStream = new DigestInputStream(stream, md);

        byte[] buffer = new byte[4096];
        int rb = 0;

        while ((rb = digestStream.read(buffer, 0, buffer.length)) > 0)
            ;

        digestStream.close();

        return hex(md.digest());
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();

        for (byte b : bytes)
            builder.append(String.format("%02x", b));

        return builder.toString();
    }

    public static List<File> listFiles(File directory, final String suffix) {
        List<File> files = new ArrayList<File>();
        File[] array = directory.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(suffix);
            }
        });

        if (array == null)
            return files;

        for (File file : array)
            files.add(file);

        return files;
    }
    
    /**
     * Lists all files contained inside {@code directory} or
     * its subfolders.
     * @param directory
     * @return
     */
    public static List<File> listFilesRecursively(File directory) {
    	return FileSystem.listFilesRecursively(directory, "");
    }
    
    public static List<File> listFilesRecursively(File directory, FilenameFilter filter) {
    	List<File> files = new ArrayList<File>();
    	File[] array = directory.listFiles();
    	
    	if (array == null) {
    		return files;
    	}
    	
    	for (File file : array) {
    		if (file.isDirectory()) {
    			files.addAll(listFilesRecursively(file, filter));
    		} else if (filter.accept(file.getParentFile(), file.getName())) {
    			files.add(file);
    		}
    	}
    	
    	return files;
    }

    public static List<File> listFilesRecursively(File directory, final String suffix) {
        List<File> files = new ArrayList<File>();
        File[] array = directory.listFiles();

        if (array == null)
            return files;

        for (File file : array)
            if (file.isDirectory())
                files.addAll(listFilesRecursively(file, suffix));
            else if (file.getName().endsWith(suffix))
                files.add(file);

        return files;
    }
    
    /**
     * Searches recursively in all files contained inside {@code directory}
     * (or its subfolders) for the regular expression {@code regex}.
     * @param directory The parent directory in which perform the search
     * @param regex The regex to search for
     * @return {@code true} if at least one file contains a string that matches
     * the {@code regex}, {@code false} otherwise.
     */
    public static boolean searchRecursively(File directory, String regex) {
    	if (directory == null) {
    		throw new IllegalArgumentException("Directory cannot be null");
    	}
    	
    	if (regex == null) {
    		throw new IllegalArgumentException("You must provide a valid pattern");
    	}
    	
    	List<File> files = FileSystem.listFilesRecursively(directory, "smali");
    	
    	for (File f : files) {
    		
    		try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
    			String line;
    			while ((line = reader.readLine()) != null) {
    				if (line.matches(regex))
    					return true;
    			}
    		} catch (IOException e) {
    			e.printStackTrace();
    		}
    	}
    	
    	return false;
    }
}