/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;
import java.util.Objects;

/**
 * Represents an entry within a ZIP archive, containing its metadata and file's content.
 * This class can be used to create a file entry to be incorporated within an ASiC container
 * with customized {@code ZipEntry} metadata (e.g. creation time, compression method, etc.).
 *
 */
@SuppressWarnings("serial")
public class ContainerEntryDocument extends CommonDocument implements DSSZipEntryDocument {

    /**
     * Document representing content of a file to be embedded into ZIP container
     */
    private final DSSDocument content;

    /**
     * ZipEntry containing metadata about a file within ZIP archive
     */
    private final DSSZipEntry zipEntry;

    /**
     * Default constructor
     *
     * @param content {@link DSSDocument} representing file's content
     */
    public ContainerEntryDocument(final DSSDocument content) {
        Objects.requireNonNull(content, "Document content cannot be null!");
        Objects.requireNonNull(content.getName(), "Document shall contain name!");

        this.content = content;
        this.zipEntry = new DSSZipEntry(content.getName());
        this.name = content.getName();
        this.mimeType = content.getMimeType();
    }

    /**
     * Constructor with provided {@code DSSZipEntry}
     *
     * @param content {@link DSSDocument} representing file's content
     * @param zipEntry {@link DSSZipEntry} containing metadata about the ZIP entry
     */
    public ContainerEntryDocument(final DSSDocument content, final DSSZipEntry zipEntry) {
        Objects.requireNonNull(content, "Document content cannot be null!");
        Objects.requireNonNull(content.getName(), "Document shall contain name!");
        Objects.requireNonNull(zipEntry, "ZipEntry cannot be null!");
        if (!content.getName().equals(zipEntry.getName())) {
            throw new IllegalArgumentException("Name of the document shall match the name of ZipEntry!");
        }

        this.content = content;
        this.zipEntry = zipEntry;
        this.name = content.getName();
        this.mimeType = content.getMimeType();
    }

    @Override
    public InputStream openStream() {
        return content.openStream();
    }

    @Override
    public void setName(String name) {
        super.setName(name);
        zipEntry.setName(name);
    }

    @Override
    public DSSZipEntry getZipEntry() {
        return zipEntry;
    }

}
