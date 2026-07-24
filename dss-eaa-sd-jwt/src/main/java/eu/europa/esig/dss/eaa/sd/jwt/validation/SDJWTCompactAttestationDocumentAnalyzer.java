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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.eaa.sd.jwt.SDJWTCompactSerializationParser;
import eu.europa.esig.dss.eaa.sd.jwt.SDJWTSerializationObject;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class performs validation of an SD-JWT VC serialized using compact JWS serialization form
 *
 */
public class SDJWTCompactAttestationDocumentAnalyzer extends AbstractSDJWTDocumentAnalyzer {

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTCompactAttestationDocumentAnalyzer.class);

    /**
     * Empty constructor
     */
    public SDJWTCompactAttestationDocumentAnalyzer() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to validate
     */
    public SDJWTCompactAttestationDocumentAnalyzer(DSSDocument document) {
        super(document);
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        SDJWTCompactSerializationParser parser = new SDJWTCompactSerializationParser(document);
        return parser.isSupported();
    }

    @Override
    protected SDJWTSerializationObject buildSDJWTSerializationObject() {
        SDJWTCompactSerializationParser parser = new SDJWTCompactSerializationParser(document);
        return parser.parse();
    }

    @Override
    protected DSSDocument getKeyBindingDetachedContent(SDJWTSerializationObject sdJwtSerializationObject) {
        try (InputStream is = document.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ByteArrayOutputStream tail = new ByteArrayOutputStream()) {

            boolean tildeReached = false;
            byte[] buffer = new byte[8192];
            int len;

            while ((len = is.read(buffer)) != -1) {
                for (int i = 0; i < len; i++) {
                    byte b = buffer[i];

                    if (tildeReached) {
                        tail.write(b);
                        if (b == '~') {
                            tail.writeTo(baos);
                            tail.reset();
                        }

                    } else {
                        baos.write(b);
                        if (b == '~') {
                            tildeReached = true;
                        }
                    }
                }
            }

            return new InMemoryDocument(baos.toByteArray());

        } catch (IOException e) {
            LOG.warn("Unable to compute input for the key binding signature verification : {}", e.getMessage(), e);
            return null;
        }
    }

}
