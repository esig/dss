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
package eu.europa.esig.dss.attestation.revocation.cwt.validation.identifierlist;

import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.COSEDocumentAnalyzer;
import eu.europa.esig.dss.attestation.revocation.cwt.model.identifierlist.CWTIdentifierListPayload;
import eu.europa.esig.dss.attestation.revocation.model.identifierlist.IdentifierListToken;
import eu.europa.esig.dss.attestation.revocation.model.identifierlist.IdentifierListPayload;
import eu.europa.esig.dss.attestation.revocation.validation.identifierlist.IdentifierListValidator;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationTokenBinary;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Validates an Identifier List token as defined in ISO/IEC 18013-5
 *
 */
public class CWTIdentifierListValidator implements IdentifierListValidator {

    private static final Logger LOG = LoggerFactory.getLogger(CWTIdentifierListValidator.class);

    /** Binaries of the retrieved revocation list */
    protected byte[] identifierListDocument;

    /** Cached instance of a signature used to sign the token */
    private AdvancedSignature tokenSignature;

    /**
     * Empty constructor
     */
    public CWTIdentifierListValidator() {
        // empty
    }

    /**
     * Constructor with the identifier list
     *
     * @param identifierListDocument byte array of the identifier list document
     */
    public CWTIdentifierListValidator(final byte[] identifierListDocument) {
        this.identifierListDocument = identifierListDocument;
    }

    @Override
    public boolean isSupported(byte[] identifierListDocument) {
        return COSEParser.isSupported(identifierListDocument);
    }

    /**
     * Builds a signature of the token
     *
     * @return {@link AdvancedSignature}
     */
    protected AdvancedSignature buildTokenSignature() {
        COSEDocumentAnalyzer documentAnalyzer = new COSEDocumentAnalyzer(new InMemoryDocument(identifierListDocument));
        List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();
        if (Utils.collectionSize(signatures) == 1) {
            CBAdESSignature signature = toCBAdESSignature(signatures.get(0));
            if (COSESignatureType.COSE_SIGN1 != signature.getCOSESignatureType()) {
                LOG.warn("The signature of the CWT-encoded Identifier List shall be a COSE_Sign1 object!");
                return null;
            }
            return signature;

        } else {
            LOG.warn("One and only one signature shall be present within JWT Status List body! " +
                    "Found : {} signatures", Utils.collectionSize(signatures));
        }
        return null;
    }

    /**
     * Gets the representation of the Identifier List Payload signed by the {@code signature}
     *
     * @param signature {@link AdvancedSignature}
     * @return {@link IdentifierListPayload}
     */
    protected IdentifierListPayload getPayload(AdvancedSignature signature) {
        try {
            CBAdESSignature cbadesSignature = toCBAdESSignature(signature);
            CBORObject cborPayload = cbadesSignature.getCoseSignature().getPayload();

            if (!cborPayload.isByteString()) {
                throw new IllegalInputException("COSE payload shall be encoded as a CBOR byte string!");
            }
            try {
                CBORByteString payloadByteString = (CBORByteString) cborPayload;
                CBORMap cborMap = new CBORMap(payloadByteString);
                return new CWTIdentifierListPayload(cborMap);

            } catch (Exception e) {
                throw new IllegalInputException(String.format(
                        "An error occurred on CWT token processing : %s", e.getMessage()), e);
            }

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to extract CWT payload : %s", e.getMessage()));
        }
    }

    private CBAdESSignature toCBAdESSignature(AdvancedSignature signature) {
        if (signature instanceof CBAdESSignature) {
            return (CBAdESSignature) signature;
        } else {
            throw new IllegalStateException("CBAdESSignature is expected!");
        }
    }


    @Override
    public AttestationRevocationToken getRevocationToken(byte[] identifier) {
        Objects.requireNonNull(identifierListDocument, "Identifier List Document cannot be null!");

        /*
         * 8.2. Status List Response
         *
         * The body of such an HTTP response contains the raw Status List Token,
         * that means the binary encoding as defined in Section 9.2.1 of [RFC8392] for
         * a Status List Token in CWT format and the JWS Compact Serialization form for
         * a Status List Token in JWT format.
         */
        AdvancedSignature signature = getTokenSignature();
        if (signature != null) {
            IdentifierListPayload identifierListPayload = getPayload(signature);
            return IdentifierListToken.initBuilder()
                    .setBinary(new AttestationRevocationTokenBinary(identifierListDocument))
                    .setSignature(signature)
                    .setPayload(identifierListPayload)
                    .setStatus(getAttestationStatus(identifierListPayload, identifier))
                    .build();
        }
        return null;
    }

    /**
     * Gets the token signature. If already built, returns the cached value.
     *
     * @return {@link AdvancedSignature}
     */
    protected AdvancedSignature getTokenSignature() {
        if (tokenSignature == null) {
            tokenSignature = buildTokenSignature();
        }
        return tokenSignature;
    }

    /**
     * Gets the attestation Status for the given {@code attestation} based on the information retrieved from {@code identifierListPayload}
     *
     * @param identifierListPayload {@link IdentifierListPayload} of the retrieved token
     * @param identifier byte array of the identifier of the attestation
     * @return {@link AttestationStatus}
     */
    protected AttestationStatus getAttestationStatus(IdentifierListPayload identifierListPayload, byte[] identifier) {
        List<byte[]> identifierListIdentifiers = identifierListPayload.getIdentifierListIdentifiers();
        if (Utils.isCollectionNotEmpty(identifierListIdentifiers)
            && identifierListIdentifiers.stream().anyMatch(i -> Arrays.equals(identifier, i))) {
                return AttestationStatus.INVALID;
        }
        return AttestationStatus.VALID;
    }

}
