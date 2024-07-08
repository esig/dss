package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipOutputStream;

/**
 * This class provides utilities for handling a ZIP archive creation using a temporary file,
 * instead of in-memory processing.
 *
 */
public class TempFileSecureContainerHandler extends SecureContainerHandler {

    /**
     * Default constructor
     */
    public TempFileSecureContainerHandler() {
        // empty
    }

    @Override
    public DSSDocument createZipArchive(List<DSSDocument> containerEntries, Date creationTime, String zipComment) {
        File temp = createTemporaryFile();
        try (FileOutputStream fos = new FileOutputStream(temp); ZipOutputStream zos = new ZipOutputStream(fos)) {
            buildZip(containerEntries, creationTime, zipComment, zos);
            return new FileDocument(temp);
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to create an ASiC container. Reason : %s", e.getMessage()), e);
        }
    }

    private File createTemporaryFile() {
        try {
            File temp = File.createTempFile("asic-container", "dss");
            temp.deleteOnExit();
            return temp;
        } catch (IOException e) {
            throw new DSSException("Unable to create a temporary file", e);
        }
    }

}
