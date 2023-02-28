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
package eu.europa.esig.dss.cookbook.example;

// tag::demo[]
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeLoader;

public class CustomMimeTypeLoader implements MimeTypeLoader {

    @Override
    public MimeType fromMimeTypeString(String mimeTypeString) {
        for (CustomMimeType mimeType : CustomMimeType.values()) {
            if (mimeTypeString.equalsIgnoreCase(mimeType.mimeTypeString)) {
                return mimeType;
            }
        }
        return null;
    }

    @Override
    public MimeType fromFileExtension(String fileExtension) {
        for (CustomMimeType mimeType : CustomMimeType.values()) {
            for (String extension : mimeType.extensions) {
                if (fileExtension.equalsIgnoreCase(extension)) {
                    return mimeType;
                }
            }
        }
        return null;
    }

    public enum CustomMimeType implements MimeType {

        CER("application/pkix-cert", "cer", "crt", "p7c"),
        CSS("text/css", "css"),
        JPEG("image/jpeg", "jpeg"),
        WEBM("audio/webm", "webm");

        private final String mimeTypeString;

        private final String[] extensions;

        CustomMimeType(final String mimeTypeString, final String... extensions) {
            this.mimeTypeString = mimeTypeString;
            this.extensions = extensions;
        }

        @Override
        public String getMimeTypeString() {
            return mimeTypeString;
        }

        @Override
        public String getExtension() {
            if (extensions != null && extensions.length > 0) {
                return extensions[0];
            }
            return null;
        }

    }

}
// end::demo[]