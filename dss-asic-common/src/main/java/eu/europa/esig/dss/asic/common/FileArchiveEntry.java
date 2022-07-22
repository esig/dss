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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Internal class that is used for performance purposes, accessing ZIP-archive entries on request,
 * instead of loading all files into memory.
 *
 */
@SuppressWarnings("serial")
public class FileArchiveEntry extends CommonDocument implements DSSZipEntryDocument {

    /** File system document representing a ZIP-container */
    private final FileDocument zipArchive;

    /** Represents the original instance of ZipEntry : important to access the relevant entry from stream */
    private final ZipEntry zipEntry;

    /** Contains metadata about the extracted entry */
    private final DSSZipEntry dssZipEntry;

    /**
     * Default constructor
     *
     * @param zipArchive {@link FileDocument} representing a ZIP-container
     * @param zipEntry {@link DSSZipEntry} containing metadata for zip container entry to be extracted
     */
    protected FileArchiveEntry(final FileDocument zipArchive, final ZipEntry zipEntry) {
        Objects.requireNonNull(zipArchive, "ZIP Archive cannot be null!");
        Objects.requireNonNull(zipEntry, "ZIP Entry cannot be null!");
        this.zipArchive = zipArchive;
        this.zipEntry = zipEntry;
        this.dssZipEntry = new DSSZipEntry(zipEntry);
        this.name = dssZipEntry.getName();
        this.mimeType = MimeType.fromFileName(dssZipEntry.getName());
    }

    @Override
    public InputStream openStream() {
        try {
            return new ZipFileEntryInputStream();
        } catch (IOException e) {
            throw new DSSException("Unable to create an InputStream", e);
        }
    }

    @Override
    public void setName(String name) {
        super.setName(name);
        dssZipEntry.setName(name);
    }

    @Override
    public DSSZipEntry getZipEntry() {
        return dssZipEntry;
    }

    /**
     * Creates InputStream for a ZipEntry from the provided archive file.
     * Handles closing of {@code java.util.zip.ZipFile}
     */
    class ZipFileEntryInputStream extends InputStream {

        /** Reads ZIP file in file system */
        private final ZipFile zipFile;

        /** InputStream for the given ZIP entry */
        private final InputStream entryInputStream;

        /**
         * Default constructor
         *
         * @throws IOException if an error occurs during the ZIP file access
         */
        ZipFileEntryInputStream() throws IOException {
            this.zipFile = new ZipFile(zipArchive.getFile());
            this.entryInputStream = zipFile.getInputStream(zipEntry);
        }

        @Override
        public int read() throws IOException {
            return entryInputStream.read();
        }

        @Override
        public void close() throws IOException {
            entryInputStream.close();
            zipFile.close();
        }

    }

}
