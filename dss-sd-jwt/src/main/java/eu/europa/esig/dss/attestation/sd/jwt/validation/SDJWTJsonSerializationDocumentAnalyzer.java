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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTJsonSerializationParser;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * This class performs analysis and processing of an SD-JWT token, created using either
 * a Flattened JSON Serialization or General JSON Serialization
 *
 */
public class SDJWTJsonSerializationDocumentAnalyzer extends AbstractSDJWTDocumentAnalyzer {

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTJsonSerializationDocumentAnalyzer.class);

    /**
     * Empty constructor
     */
    public SDJWTJsonSerializationDocumentAnalyzer() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to validate
     */
    public SDJWTJsonSerializationDocumentAnalyzer(DSSDocument document) {
        super(document);
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        SDJWTJsonSerializationParser parser = new SDJWTJsonSerializationParser(document);
        return parser.isSupported();
    }

    @Override
    public SDJWTSerializationObject buildSDJWTSerializationObject() {
        SDJWTJsonSerializationParser parser = new SDJWTJsonSerializationParser(document);
        return parser.parse();
    }

    @Override
    protected DSSDocument getKeyBindingDetachedContent(SDJWTSerializationObject sdJwtSerializationObject) {
        /*
         * RFC 9901 "8.1. New Unprotected Header Parameters":
         *
         * In an SD-JWT+KB, kb_jwt MUST be present when using the JWS JSON Serialization,
         * and the digest in the sd_hash claim MUST be computed over the SD-JWT as described
         * in Section 4.3.1. This means that even when using the JWS JSON Serialization,
         * the representation as a regular SD-JWT Compact Serialization MUST be created temporarily
         * to calculate the digest. In detail, the SD-JWT Compact Serialization part is built by
         * concatenating the protected header, the payload, and the signature of the JWS JSON serialized
         * SD-JWT using a . character as a separator, and using the Disclosures from the disclosures
         * member of the unprotected header.
         *
         * <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~
         */
        JWSJsonSerializationObject attestationSignature = sdJwtSerializationObject.getSignature();
        JWS jws = attestationSignature.getSignatures().get(0);

        StringBuilder compactSerialization = new StringBuilder();
        compactSerialization.append(jws.getEncodedHeader());
        compactSerialization.append(".");
        compactSerialization.append(jws.getEncodedPayload());
        compactSerialization.append(".");
        compactSerialization.append(jws.getEncodedSignature());
        compactSerialization.append("~");
        List<String> disclosures = getDisclosures(jws);
        if (Utils.isCollectionNotEmpty(disclosures)) {
            for (String disclosure : disclosures) {
                compactSerialization.append(disclosure);
                compactSerialization.append("~");
            }
        }

        return new InMemoryDocument(compactSerialization.toString().getBytes());
    }

    private List<String> getDisclosures(JWS jws) {
        Map<String, Object> unprotectedHeader = jws.getUnprotected();
        if (Utils.isMapNotEmpty(unprotectedHeader)) {
            Object disclosuresObject = unprotectedHeader.get(SDJWTConstants.DISCLOSURES);
            if (disclosuresObject instanceof List) {
                final List<String> disclosures = new ArrayList<>();
                List<?> disclosuresList = (List<?>) disclosuresObject;
                for (Object disclosure : disclosuresList) {
                    if (disclosure instanceof String) {
                        disclosures.add((String) disclosure);
                    } else {
                        LOG.warn("Disclosure shall be represented by a String!");
                    }
                }
                return disclosures;
            } else {
                LOG.warn("Disclosures shall be represented by a JSON Array!");
            }
        }
        return Collections.emptyList();
    }

}
