package it.polimi.elet.necst.heldroid.pipeline;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class FileTree {
    private class DirectoryNode {
        private File directory;
        private String name;
        private List<File> files;
        private Collection<DirectoryNode> childNodes;
        private int startIndexInAllFiles, endIndexInAllFiles;

        public DirectoryNode(File directory) {
            if (!directory.isDirectory())
                throw new IllegalArgumentException("Expected a directory.");

            Collection<File> subfolders = new ArrayList<File>();

            this.directory = directory;
            this.name = directory.getName();
            this.files = new ArrayList<File>();

            for (File file : directory.listFiles()) {
                if (file.isFile())
                    this.files.add(file);
                else
                    subfolders.add(file);
            }

            startIndexInAllFiles = FileTree.this.allFiles.size();
            FileTree.this.allFiles.addAll(this.files);

            this.childNodes = new ArrayList<DirectoryNode>(subfolders.size());

            for (File folder : subfolders)
                this.childNodes.add(new DirectoryNode(folder));

            endIndexInAllFiles = FileTree.this.allFiles.size() - 1;
        }

        public File getDirectory() {
            return directory;
        }

        public String getName() {
            return name;
        }

        public Collection<File> getFiles() {
            return files;
        }

        public Collection<File> getAllFiles() {
            return FileTree.this.allFiles.subList(startIndexInAllFiles, endIndexInAllFiles);
        }

        public Collection<DirectoryNode> getChildNodes() {
            return childNodes;
        }
    }

    private DirectoryNode root;
    private List<File> allFiles;

    public FileTree(File rootDirectory) {
        this.allFiles = new ArrayList<File>();
        this.root = new DirectoryNode(rootDirectory);
    }

    public Collection<File> getAllFiles() {
        return allFiles;
    }

    public Collection<File> getFilesIn(File directory) {
        return this.selectNode(directory).getFiles();
    }

    public Collection<File> getAllFilesIn(File directory) {
        return this.selectNode(directory).getAllFiles();
    }

    private DirectoryNode selectNode(File directory) {
        String relativePath = directory.getAbsolutePath().substring(root.getDirectory().getAbsolutePath().length());
        String[] chunks = relativePath.split(File.separator.replace("\\", "\\\\"));
        DirectoryNode currentNode = root;

        for (int i = 0; i < chunks.length; i++) {
            if (chunks[i].isEmpty())
                continue;

            for (DirectoryNode subNode : currentNode.getChildNodes())
                if (subNode.getName().equals(chunks[i])) {
                    currentNode = subNode;
                    break;
                }
        }

        return currentNode;
    }
}
