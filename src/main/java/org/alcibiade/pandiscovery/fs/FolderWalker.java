package org.alcibiade.pandiscovery.fs;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;

/**
 * Explore paths as a stream.
 */
public class FolderWalker {

    private List<String> paths;

    public FolderWalker(List<String> paths) {
        this.paths = paths;
    }

    public void walk(FolderVisitor visitor) {
        paths.forEach(pathString -> {
            Path p = Paths.get(pathString);

            try {
                Files.walkFileTree(p, new PathStorageVisitor(visitor));
            } catch (IOException e) {
                throw new IllegalStateException("IO Access failed for " + p);
            }
        });
    }

    private class PathStorageVisitor extends SimpleFileVisitor<Path> implements FileVisitor<Path> {

        private FolderVisitor visitor;

        public PathStorageVisitor(FolderVisitor visitor) {
            this.visitor = visitor;
        }

        @Override
        public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException {
            visitor.visit(path);
            return FileVisitResult.CONTINUE;
        }
    }
}