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
package eu.europa.esig.dss.enumerations;

import java.io.File;
import java.io.Serializable;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Identifies a file MimeType and its attributes
 *
 */
public interface MimeType extends Serializable {

    /**
     * Gets String identifying the MimeType
     *
     * @return the mimeTypeString
     */
    String getMimeTypeString();

    /**
     * Returns file extension corresponding to the MimeType
     *
     * @return {@link String} file extension
     */
    String getExtension();

    /**
     * This method returns the first representation of the {@code MimeType}
     * corresponding to the given mime-type string.
     *
     * @param mimeTypeString
     *            is a string identifier composed of two parts: a "type" and a
     *            "subtype"
     * @return the extrapolated mime-type from the {@code String}
     */
    static MimeType fromMimeTypeString(final String mimeTypeString) {
        Objects.requireNonNull(mimeTypeString, "The mimeTypeString cannot be null!");

        for (MimeTypeLoader mimeTypeLoader : mimeTypeLoaders()) {
            MimeType mimeType = mimeTypeLoader.fromMimeTypeString(mimeTypeString);
            if (mimeType != null) {
                return mimeType;
            }
        }
        return MimeTypeEnum.BINARY;
    }

    /**
     * Returns {@code MimeType} matching to the provided {@code fileExtension} String
     *
     * @param fileExtension {@link String}
     * @return {@link MimeType} if associated MimeType found, {@code MimeTypeEnum.BINARY} otherwise
     */
    static MimeType fromFileExtension(String fileExtension) {
        for (MimeTypeLoader mimeTypeLoader : mimeTypeLoaders()) {
            MimeType mimeType = mimeTypeLoader.fromFileExtension(fileExtension);
            if (mimeType != null) {
                return mimeType;
            }
        }
        return MimeTypeEnum.BINARY;
    }

    /**
     * This method returns the mime-type extrapolated from the file name.
     *
     * @param fileName {@link String} the file name to be analysed
     * @return {@link String} the extrapolated mime-type of the file name if found,
     *                        {@code MimeTypeEnum.BINARY} otherwise
     */
    static MimeType fromFileName(final String fileName) {
        final String fileExtension = getFileExtension(fileName);
        if (fileExtension != null) {
            final String lowerCaseExtension = fileExtension.toLowerCase();
            return fromFileExtension(lowerCaseExtension);
        }
        return MimeTypeEnum.BINARY;
    }

    /**
     * This method returns the mime-type extrapolated from the file.
     *
     * @param file {@link File} the file to be analysed
     * @return the extrapolated mime-type of the file if found, {@code MimeTypeEnum.BINARY} otherwise
     */
    static MimeType fromFile(final File file) {
        Objects.requireNonNull(file, "The file cannot be null!");

        final String fileName = file.getName();
        return fromFileName(fileName);
    }

    /**
     * Returns the file extension based on the position of the '.' in the fileName.
     * File paths as "xxx.y/toto" are not handled.
     *
     * @param fileName
     *            to be analysed
     * @return the file extension or null
     */
    static String getFileExtension(final String fileName) {
        if (fileName == null || fileName.trim().length() == 0) {
            return null;
        }

        String extension = "";
        int lastIndexOf = fileName.lastIndexOf('.');
        if (lastIndexOf > 0) {
            extension = fileName.substring(lastIndexOf + 1);
        }
        return extension;
    }

    /**
     * This method loads available {@code MimeTypeLoader}s using a ServiceLoader
     *
     * @return iterable of {@link MimeTypeLoader}
     */
    static Iterable<MimeTypeLoader> mimeTypeLoaders() {
        return ServiceLoader.load(MimeTypeLoader.class);
    }

}
