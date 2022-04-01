package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * This resources factory stores temporary documents to a unique file within filesystem.
 * Removes temporary files on exit, unless they have been used within a {@code eu.europa.esig.dss.model.FileDocument}.
 *
 */
public class TempFileResourcesFactory implements DSSResourcesFactory {

    /** The prefix (beginning) of a filename to be used for created documents */
    private final String fileNamePrefix;

    /** The suffix (ending/extension) of a filename to be used for created documents */
    private final String fileNameSuffix;

    /** The directory containing created documents */
    private final File tempFileDirectory;

    /**
     * Default constructor
     *
     * @param fileNamePrefix {@link String} filename prefix string
     * @param fileNameSuffix {@link String} filename suffix string
     * @param tempFileDirectory {@link File} representing a directory to store temporary documents in
     */
    public TempFileResourcesFactory(final String fileNamePrefix, final String fileNameSuffix,
                                    final File tempFileDirectory) {
        this.fileNamePrefix = fileNamePrefix;
        this.fileNameSuffix = fileNameSuffix;
        this.tempFileDirectory = tempFileDirectory;
    }

    @Override
    public OutputStream createOutputStream() throws IOException {
        if (!tempFileDirectory.exists()) {
            boolean dirCreated = tempFileDirectory.mkdirs();
            if (!dirCreated) {
                throw new DSSException(String.format("Unable to create a new directory '%s'!", tempFileDirectory.getPath()));
            }
        }
        File tempFile = createFile();
        tempFile.deleteOnExit(); // ensure the temporary file is being deleted on exit
        return new DSSFileOutputStream(tempFile);
    }

    @Override
    public DSSDocument toDSSDocument(OutputStream os) throws IOException {
        if (!(os instanceof DSSFileOutputStream)) {
            throw new UnsupportedOperationException(String.format(
                    "The OutputStream shall be of type DSSFileOutputStream. Received object is of type '%s'", os.getClass()));
        }
        DSSFileOutputStream dssFileOutputStream = (DSSFileOutputStream) os;

        File tempFile = dssFileOutputStream.getFile();
        if (!tempFile.exists()) {
            throw new IllegalStateException(String.format(
                    "The temporary file '%s' is not accessible or does not exist!", tempFile.getName()));
        }

        // Move tempFile content to a new File to be used to store DSSDocument
        File fileDocumentLocation = createFile();
        Files.move(tempFile.toPath(), fileDocumentLocation.toPath(), StandardCopyOption.REPLACE_EXISTING);

        return new FileDocument(fileDocumentLocation);
    }

    private File createFile() throws IOException {
        return File.createTempFile(fileNamePrefix, fileNameSuffix, tempFileDirectory);
    }

    /**
     * A wrapper for {@code FileOutputStream} meaning to store the original {@code File} reference
     *
     */
    private static class DSSFileOutputStream extends FileOutputStream {

        /** The original File to store the OutputStream into */
        private final File file;

        /**
         * Default constructor
         *
         * @param file {@link File} to be used to stream the output
         * @throws FileNotFoundException if the given {@code file} was not found
         */
        public DSSFileOutputStream(File file) throws FileNotFoundException {
            super(file);
            this.file = file;
        }

        /**
         * Gets the file
         *
         * @return {@code File}
         */
        private File getFile() {
            return file;
        }

        @Override
        public void close() throws IOException {
            super.close();
        }

    }

}
