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
package eu.europa.esig.dss.attestation.sd.jwt;

import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * This class is used to parse SD-JWT token created using either a Flattened JSON Serialization or
 * General JSON Serialization as defined in RFC 9901 "Selective Disclosure for JSON Web Tokens"
 *
 */
public class SDJWTJsonSerializationParser {

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTJsonSerializationParser.class);

    /** The document to be parsed */
    private final DSSDocument document;


    /**
     * The default constructor
     *
     * @param document {@link DSSDocument} to parse
     */
    public SDJWTJsonSerializationParser(DSSDocument document) {
        this.document = document;
    }

    /**
     * Verifies if the provided file is an SD-JWT in a form of JSON Serialization
     *
     * @return TRUE if the document is an SD-JWT in a JSON Serialization form and supported by the parser, FALSE otherwise
     */
    public boolean isSupported() {
        return new JWSJsonSerializationParser(document).isSupported();
    }

    /**
     * Parses the provided document and returns an SD-JWT serialized object, if supported
     *
     * @return {@link SDJWTSerializationObject}
     */
    public SDJWTSerializationObject parse() {
        JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(document);
        if (!jwsJsonSerializationParser.isSupported()) {
            throw new IllegalInputException("The given document is not supported by SDJWTJsonSerializationParser!");
        }
        JWSJsonSerializationObject jwsJsonSerializationObject = jwsJsonSerializationParser.parse();

        List<JWS> signatures = jwsJsonSerializationObject.getSignatures();
        if (Utils.collectionSize(signatures) == 0) {
            throw new IllegalInputException("The provided SD-JWT token does not contain any signature!");
        }

        final SDJWTSerializationObject sdjwtSerializationObject = new SDJWTSerializationObject();
        sdjwtSerializationObject.setJWSSerializationType(jwsJsonSerializationObject.getJWSSerializationType());
        sdjwtSerializationObject.setSignature(jwsJsonSerializationObject);

        JWS signature = signatures.get(0);
        if (Utils.collectionSize(signatures) > 1) {
            LOG.info("More than one signature found used to create the SD-JWT token. " +
                    "The disclosures and key binding signature from the first entry will be extracted only, if any.");
        }
        sdjwtSerializationObject.setDisclosures(getDisclosures(signature));
        sdjwtSerializationObject.setKeyBindingSignature(getKeyBindingJWT(signature));

        return sdjwtSerializationObject;
    }

    private List<SDJWTSelectiveDisclosure> getDisclosures(JWS signature) {
        Map<String, Object> unprotectedHeader = signature.getUnprotected();
        if (Utils.isMapEmpty(unprotectedHeader)) {
            return null;
        }

        List<?> disclosures = DSSJsonUtils.getAsList(unprotectedHeader, SDJWTConstants.DISCLOSURES);
        if (Utils.isCollectionEmpty(disclosures)) {
            return Collections.emptyList();
        }

        final List<SDJWTSelectiveDisclosure> result = new ArrayList<>();
        for (Object disclosureObject : disclosures) {
            if (!(disclosureObject instanceof String)) {
                LOG.warn("The disclosure object shall be of String type! Skip the array item.");
                continue;
            }
            String disclosureB64Url = (String) disclosureObject;
            try {
                final SDJWTSelectiveDisclosure disclosure = new SDJWTSelectiveDisclosure(disclosureB64Url);
                result.add(disclosure);

            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.warn("An error occurred on selective disclosure '{}' processing. Reason : {}.",
                            disclosureB64Url, e.getMessage(), e);
                } else {
                    LOG.warn("An error occurred on selective disclosure processing. Reason : {}. " +
                            "More details are in debug mode.", e.getMessage(), e);
                }
            }
        }
        return result;
    }

    private JWSJsonSerializationObject getKeyBindingJWT(JWS signature) {
        Map<String, Object> unprotectedHeader = signature.getUnprotected();
        if (Utils.isMapEmpty(unprotectedHeader)) {
            return null;
        }

        String kbJwt = DSSJsonUtils.getAsString(unprotectedHeader, SDJWTConstants.KB_JWT);
        if (Utils.isStringEmpty(kbJwt)) {
            return null;
        }

        DSSDocument kbJwtDocument = new InMemoryDocument(kbJwt.getBytes());
        JWSCompactSerializationParser jwsCompactSerializationParser = new JWSCompactSerializationParser(kbJwtDocument);
        if (jwsCompactSerializationParser.isSupported()) {
            JWS jws = jwsCompactSerializationParser.parse();
            JWSJsonSerializationObject jwsJsonSerializationObject = DSSJsonUtils.toJWSJsonSerializationObject(jws);
            jwsJsonSerializationObject.setJWSSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
            return jwsJsonSerializationObject;
        }
        throw new IllegalInputException("The document is not a valid key binding JWT. The provided part is not a valid JWT!");
    }

}
