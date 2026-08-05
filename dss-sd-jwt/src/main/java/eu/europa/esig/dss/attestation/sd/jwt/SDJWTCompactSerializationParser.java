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
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

/**
 * Parses and read SD-JWT attestation
 *
 */
public class SDJWTCompactSerializationParser {

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTCompactSerializationParser.class);

    /** Defines the maximum number of '.' character inside a JWS signature */
    private static final int NUMBER_DOTS_PER_SIGNATURE = 2;

    /** Defines the maximum number of '.' character inside a SD-JWT KB token */
    private static final int NUMBER_DOTS_PER_SDJWT_KB = 4;

    /** Dot character, used as a separator of parts within a JWS Compact signature */
    private static final char DOT_CHARACTER = '.';

    /** Tilde character, used as a separator of parts within an SD-JWT */
    private static final char TILDE_CHARACTER = '~';

    /** Tilde character in a form of String, used as a separator of parts within an SD-JWT */
    private static final String TILDE_STR = String.valueOf(TILDE_CHARACTER);

    /** The document to be parsed */
    private final DSSDocument document;

    /**
     * The default constructor
     *
     * @param document {@link DSSDocument} to parse
     */
    public SDJWTCompactSerializationParser(DSSDocument document) {
        this.document = document;
    }

    /**
     * Verifies if the provided file is a compact SD-JWT
     *
     * @return TRUE if the document is a compact SD-JWT and supported by the parser, FALSE otherwise
     */
    public boolean isSupported() {
        if (!DSSJsonUtils.isAllowedSignatureDocumentType(document)) {
            return false;
        }

        int dotCounter = 0;
        int tildeCounter = 0;
        boolean ending = false; // used to detect and "trim" line breaks in the end of JWS string
        try (InputStream is = document.openStream();
             BufferedInputStream bis = new BufferedInputStream(is)) {

            int b;
            while ((b = bis.read()) != -1) {
                byte currentByte = (byte) b;

                if (DSSUtils.isLineBreakByte(currentByte)) {
                    ending = true;
                } else if (ending) {
                    return false;
                } else if (currentByte == DOT_CHARACTER) {
                    dotCounter++;
                    if (tildeCounter == 0 && dotCounter > NUMBER_DOTS_PER_SIGNATURE) {
                        return false;
                    }
                    if (dotCounter > NUMBER_DOTS_PER_SDJWT_KB) {
                        return false;
                    }
                } else if (currentByte == TILDE_CHARACTER) {
                    tildeCounter++;
                    if (dotCounter != NUMBER_DOTS_PER_SIGNATURE) {
                        return false;
                    }
                } else if (DSSJsonUtils.isBase64UrlEncoded(currentByte)) {
                    // continue
                } else if ((dotCounter == 1 || dotCounter == 3) && DSSJsonUtils.isUrlSafe(currentByte)) {
                    // continue (payload can be not Base64Url encoded)
                } else {
                    return false;
                }
            }

            if (dotCounter != NUMBER_DOTS_PER_SIGNATURE && dotCounter != NUMBER_DOTS_PER_SDJWT_KB && tildeCounter == 0) {
                return false;
            }

        } catch (IOException e) {
            throw new DSSException(String.format("Cannot read the document. Reason : %s", e.getMessage()), e);
        }
        if (ending) {
            LOG.warn("Line break characters found within the SD-JWT document!");
        }
        return true;
    }

    /**
     * Parses the provided document and returns an SD-JWT serialized object, if supported
     *
     * @return {@link SDJWTSerializationObject}
     */
    public SDJWTSerializationObject parse() {
        try (Scanner scanner = new Scanner(document.openStream(), StandardCharsets.UTF_8.name())) {
            String compactSerialization = scanner.nextLine();
            if (!compactSerialization.contains(TILDE_STR)) {
                throw new IllegalInputException("The document is not a valid SD-JWT. No tilde `~` character has been found.");
            }

            String[] parts = compactSerialization.split(TILDE_STR);
            if (parts.length == 0) {
                throw new IllegalInputException("The document is not a valid SD-JWT. No parts have been found.");
            }

            final SDJWTSerializationObject sdJwt = new SDJWTSerializationObject();
            sdJwt.setJWSSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

            JWSJsonSerializationObject signature = getSignature(parts);
            sdJwt.setSignature(signature);

            JWSJsonSerializationObject keyBinding = null;
            // if does not end with `~`, we expect the key binding signature to be in the last slot
            if (!compactSerialization.endsWith(TILDE_STR)) {
                keyBinding = getKeyBinding(parts);
            }
            sdJwt.setKeyBindingSignature(keyBinding);

            List<SDJWTSelectiveDisclosure> disclosures = getDisclosures(parts, keyBinding != null);
            sdJwt.setDisclosures(disclosures);

            return sdJwt;
        }
    }

    private JWSJsonSerializationObject getSignature(String[] parts) {
        DSSDocument jwsDocument = new InMemoryDocument(parts[0].getBytes());
        return getJWSJsonSerializationObject(jwsDocument);
    }

    private JWSJsonSerializationObject getJWSJsonSerializationObject(DSSDocument jwsDocument) {
        JWSCompactSerializationParser jwsCompactSerializationParser = new JWSCompactSerializationParser(jwsDocument);
        if (jwsCompactSerializationParser.isSupported()) {
            JWS jws = jwsCompactSerializationParser.parse();
            JWSJsonSerializationObject jwsJsonSerializationObject = DSSJsonUtils.toJWSJsonSerializationObject(jws);
            jwsJsonSerializationObject.setJWSSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
            return jwsJsonSerializationObject;
        }
        throw new IllegalInputException("The document is not a valid SD-JWT. The provided part is not a valid JWS!");
    }

    private JWSJsonSerializationObject getKeyBinding(String[] parts) {
        DSSDocument jwsDocument = new InMemoryDocument(parts[parts.length - 1].getBytes());
        return getJWSJsonSerializationObject(jwsDocument);
    }

    private List<SDJWTSelectiveDisclosure> getDisclosures(String[] parts, boolean keyBindingPresent) {
        int disclosuresAmount = parts.length - 1 - (keyBindingPresent ? 1 :0);
        if (disclosuresAmount == 0) {
            return Collections.emptyList();
        }

        final List<SDJWTSelectiveDisclosure> disclosures = new ArrayList<>();

        // NOTE: skip the JWS signature
        for (int i = 1; i < disclosuresAmount + 1; i++) {
            String disclosureB64Url = parts[i];
            try {
                final SDJWTSelectiveDisclosure disclosure = new SDJWTSelectiveDisclosure(disclosureB64Url);
                disclosures.add(disclosure);

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

        return disclosures;
    }

}
