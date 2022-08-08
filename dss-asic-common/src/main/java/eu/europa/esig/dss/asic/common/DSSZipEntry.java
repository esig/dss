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

import java.io.Serializable;
import java.nio.file.attribute.FileTime;
import java.util.Date;
import java.util.Objects;
import java.util.zip.ZipEntry;

/**
 * Contains metadata for a ZIP-container entry
 *
 */
public class DSSZipEntry implements Serializable {

    private static final long serialVersionUID = -6639922911484163896L;

    /**
     * ZIP entry name
     */
    private String name;

    /**
     * Comment for ZIP entry
     */
    private String comment;

    /**
     * The compression method to be used for the current document within a ZIP-container to be created
     *
     * Default : DEFLATED (8) - the entry will be compressed
     */
    private int compressionMethod = ZipEntry.DEFLATED;

    /**
     * Time indicating when the document has been created
     */
    private FileTime creationTime;

    /**
     * Contains an extra metadata for the ZIP entry
     */
    private byte[] extra;

    /**
     * Time of the last entry modification
     */
    private FileTime modificationTime;

    /**
     * Time of the last entry access
     */
    private FileTime lastAccessTime;

    /**
     * Size of the document
     */
    private long size;

    /**
     * Size of the document after compression
     */
    private long compressedSize;

    /**
     * CRC-32 hash of the uncompressed document
     */
    private long crc;

    /**
     * Default constructor
     *
     * @param name {@link String} of the zip-entry to be created
     */
    public DSSZipEntry(String name) {
        Objects.requireNonNull(name, "Name cannot be null!");
        this.name = name;
    }

    /**
     * Constructor from existing {@code ZipEntry}
     *
     * @param zipEntry {@link ZipEntry}
     */
    public DSSZipEntry(ZipEntry zipEntry) {
        Objects.requireNonNull(zipEntry, "ZipEntry cannot be null!");
        this.name = zipEntry.getName();
        if (zipEntry.getComment() != null) {
            this.comment = zipEntry.getComment();
        }
        if (zipEntry.getMethod() != -1) {
            this.compressionMethod = zipEntry.getMethod();
        }
        if (zipEntry.getCreationTime() != null) {
            this.creationTime = zipEntry.getCreationTime();
        }
        if (zipEntry.getExtra() != null) {
            this.extra = zipEntry.getExtra();
        }
        if (zipEntry.getLastModifiedTime() != null) {
            this.modificationTime = zipEntry.getLastModifiedTime();
        }
        if (zipEntry.getLastAccessTime() != null) {
            this.lastAccessTime = zipEntry.getLastAccessTime();
        }
        if (zipEntry.getSize() != -1) {
            this.size = zipEntry.getSize();
        }
        if (zipEntry.getCompressedSize() != -1) {
            this.compressedSize = zipEntry.getCompressedSize();
        }
        if (zipEntry.getCrc() != -1) {
            this.crc = zipEntry.getCrc();
        }
    }

    /**
     * Gets name of the ZIP entry
     *
     * @return {@link String}
     */
    public String getName() {
        return name;
    }

    /**
     * Sets name of the ZIP entry
     *
     * @param name {@link String}
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets comment defined for the ZIP entry
     *
     * @return {@link String}
     */
    public String getComment() {
        return comment;
    }

    /**
     * Sets comment defined for the ZIP entry
     *
     * @param comment {@link String}
     */
    public void setComment(String comment) {
        this.comment = comment;
    }

    /**
     * Gets compression method for the ZIP entry
     *
     * @return int identifier of the compression method
     */
    public int getCompressionMethod() {
        return compressionMethod;
    }

    /**
     * Sets compression method for the ZIP entry
     *
     * @param compressionMethod int identifier of the compression method
     */
    public void setCompressionMethod(int compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    /**
     * Gets creation time of the document
     *
     * @return {@link FileTime}
     */
    public FileTime getCreationTime() {
        return creationTime;
    }

    /**
     * Sets creation time of the document
     *
     * @param creationTime {@link FileTime}
     */
    public void setCreationTime(FileTime creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * Sets creation time of the document
     *
     * @param creationTime {@link Date}
     */
    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime != null ? toFileTime(creationTime) : null;
    }

    /**
     * Gets extra field for the document
     *
     * @return byte array
     */
    public byte[] getExtra() {
        return extra;
    }

    /**
     * Sets extra field for the document
     *
     * @param extra byte array
     */
    public void setExtra(byte[] extra) {
        this.extra = extra;
    }

    /**
     * Gets the last modification time of the document
     *
     * @return {@link Date}
     */
    public Date getModificationTime() {
        return modificationTime != null ? toDate(modificationTime) : null;
    }

    /**
     * Gets the last access time of the document
     *
     * @return {@link Date}
     */
    public Date getLastAccessTime() {
        return lastAccessTime != null ? toDate(lastAccessTime) : null;
    }

    /**
     * Gets the size of uncompressed document
     *
     * @return size
     */
    public long getSize() {
        return size;
    }

    /**
     * Gets the size of compressed document
     *
     * @return compressed size
     */
    public long getCompressedSize() {
        return compressedSize;
    }

    /**
     * Gets CRC-32 checksum of the uncompressed document
     *
     * @return CRC-32 checksum
     */
    public long getCrc() {
        return crc;
    }

    /**
     * Creates a new copy of {@code ZipEntry}.
     *
     * NOTE: some fields are not copied, as they can be changed during container creation
     *       (i.e. modification time, size, crc, etc.).
     *
     * @return {@link ZipEntry}
     */
    public ZipEntry createZipEntry() {
        ZipEntry zipEntry = new ZipEntry(name);
        if (comment != null) {
            zipEntry.setComment(comment);
        }
        if (compressionMethod != -1) {
            zipEntry.setMethod(compressionMethod);
        }
        if (creationTime != null) {
            zipEntry.setCreationTime(creationTime);
        }
        if (extra != null) {
            zipEntry.setExtra(extra);
        }
        return zipEntry;
    }

    /**
     * This method converts {@code java.util.Date} to {@code java.nio.file.attribute.FileTime}
     *
     * @param date {@link Date} to convert
     * @return {@link FileTime}
     */
    private FileTime toFileTime(Date date) {
        return FileTime.fromMillis(date.getTime());
    }

    /**
     * This method converts {@code java.nio.file.attribute.FileTime} to {@code java.util.Date}
     *
     * @param fileTime {@link FileTime} to convert
     * @return {@link Date}
     */
    private Date toDate(FileTime fileTime) {
        return new Date(fileTime.toMillis());
    }

}
