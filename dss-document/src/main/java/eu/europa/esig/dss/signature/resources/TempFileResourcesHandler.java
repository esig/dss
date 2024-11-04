/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.File;
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
        return new BufferedOutputStream(Files.newOutputStream(tempFile.toPath()));
    }

    @Override
    public DSSDocument writeToDSSDocument() throws IOException {
        assertFileExists();
        // Avoid deletion of the File on exit
        toBeDeleted = false;
        // close to finalize OutputStream
        close();
        // create the document
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
        if (toBeDeleted) {
            forceDelete();
        }
    }

    /**
     * This method is used to delete the temporary File forcibly, even with a flag {@code toBeDeleted} set to false.
     * Method should be called responsively and the temp file should be preserved when needed
     * (e.g. output of signDocument() method).
     */
    public void forceDelete() {
        if (tempFile != null) {
            try {
                Files.delete(tempFile.toPath());
            } catch (IOException e) {
                String errorMessage = "Unable to remove a temporary file '{}'. Reason : {}";
                if (LOG.isDebugEnabled()) {
                    LOG.warn(errorMessage, tempFile.getName(), e.getMessage(), e);
                } else {
                    LOG.warn(errorMessage, tempFile.getName(), e.getMessage());
                }
            }
        }
    }

}
