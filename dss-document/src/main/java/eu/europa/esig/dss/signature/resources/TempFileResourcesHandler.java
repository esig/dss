package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;

/**
 * This resources factory stores temporary documents to a unique file within filesystem.
 * Removes temporary files on exit, unless they have been used within a {@code eu.europa.esig.dss.model.FileDocument}.
 *
 */
public class TempFileResourcesHandler extends AbstractResourcesHandler {

    private static final Logger LOG = LoggerFactory.getLogger(TempFileResourcesHandler.class);

    /** Temporary file used for streaming the data */
    private final File tempFile;

    /** Indicates whether the File should be removed on calling {@code #close()} method */
    private boolean toBeDeleted = true;

    /**
     * Default constructor
     *
     * @param fileNamePrefix {@link String} filename prefix string
     * @param fileNameSuffix {@link String} filename suffix string
     * @param tempFileDirectory {@link File} representing a directory to store temporary documents in
     */
    public TempFileResourcesHandler(String fileNamePrefix, String fileNameSuffix, File tempFileDirectory) {
        try {
            this.tempFile = Files.createTempFile(tempFileDirectory.toPath(), fileNamePrefix, fileNameSuffix).toFile();
            this.tempFile.deleteOnExit();
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to create a temporary file. Reason : %s", e.getMessage()), e);
        }
    }

    @Override
    protected OutputStream buildOutputStream() throws IOException {
        assertFileExists();
        return new FileOutputStream(tempFile);
    }

    @Override
    public DSSDocument writeToDSSDocument() throws IOException {
        assertFileExists();
        // Avoid deletion of the File on exit
        toBeDeleted = false;
        return new FileDocument(tempFile);
    }

    private void assertFileExists() {
        if (!tempFile.exists()) {
            throw new IllegalStateException(String.format("The file '%s' does not exists!", tempFile.getName()));
        }
    }

    @Override
    public void close() throws IOException {
        super.close();
        if (tempFile != null && toBeDeleted) {
            boolean deleted = tempFile.delete();
            if (!deleted) {
                LOG.warn("Unable to remove a temporary file '{}'", tempFile.getName());
            }
        }
    }

}
