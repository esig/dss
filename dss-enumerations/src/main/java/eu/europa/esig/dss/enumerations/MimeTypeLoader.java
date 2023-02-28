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

/**
 * This class is used to load an enumeration(s) of {@code eu.europa.esig.dss.enumerations.MimeType} interface
 *
 */
public interface MimeTypeLoader {

    /**
     * Returns a {@code MimeType} matching the MimeType {@code String}
     *
     * @param mimeTypeString {@link String} identifying the MimeType
     * @return {@link MimeType} if associated MimeType found, NULL otherwise
     */
    MimeType fromMimeTypeString(String mimeTypeString);

    /**
     * Returns {@code MimeType} matching to the provided {@code fileExtension} String
     *
     * @param fileExtension {@link String}
     * @return {@link MimeType} if associated MimeType found, NULL otherwise
     */
    MimeType fromFileExtension(String fileExtension);

}
