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
package eu.europa.esig.dss.enumerations;

/**
 * Contains methods to extract {@code MimeTypeEnum}s
 *
 */
public class MimeTypeEnumLoader implements MimeTypeLoader {

    /**
     * Default constructor
     */
    public MimeTypeEnumLoader() {
        // empty
    }

    @Override
    public MimeType fromMimeTypeString(String mimeTypeString) {
        for (MimeTypeEnum mimeTypeEnum : MimeTypeEnum.values()) {
            if (mimeTypeString.equalsIgnoreCase(mimeTypeEnum.mimeTypeString)) {
                return mimeTypeEnum;
            }
        }
        return null;
    }

    @Override
    public MimeType fromFileExtension(String fileExtension) {
        for (MimeTypeEnum mimeTypeEnum : MimeTypeEnum.values()) {
            for (String extension : mimeTypeEnum.extensions) {
                if (fileExtension.equalsIgnoreCase(extension)) {
                    return mimeTypeEnum;
                }
            }
        }
        return null;
    }

}
