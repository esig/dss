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

import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentAnalyzer;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTSerializationObject;
import eu.europa.esig.dss.enumerations.AttestationPresentationType;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Performs validation of a JWT based presentation of Electronic Attestation of Attributes. e.g. SD-JWT VC
 *
 */
public abstract class AbstractSDJWTDocumentAnalyzer extends DefaultAttestationDocumentAnalyzer {

    /** Cached instance of a parsed SD-JWT VC object */
    private SDJWTSerializationObject sdJWTSerializationObject;

    /**
     * Default constructor
     */
    protected AbstractSDJWTDocumentAnalyzer() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to validate
     */
    protected AbstractSDJWTDocumentAnalyzer(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");

        this.document = document;
        this.sdJWTSerializationObject = buildSDJWTSerializationObject();
    }

    /**
     * Builds a {@code SDJWTSerializationObject}
     *
     * @return {@link SDJWTSerializationObject}
     */
    protected abstract SDJWTSerializationObject buildSDJWTSerializationObject();

    @Override
    protected SDJWTEAAPresentation buildEAAPresentation() {
        SDJWTEAAPresentation attestationPresentation = new SDJWTEAAPresentation();
        attestationPresentation.setEAAPresentationType(AttestationPresentationType.SD_JWT);

        List<AdvancedSignature> signatures = getSignatures(sdJWTSerializationObject);
        SDJWTAttestation sdJwtEaa = SDJWTAttestation.initBuilder()
                .setSignatures(signatures)
                .setDisclosures(sdJWTSerializationObject.getDisclosures())
                .setKeyBindingSignature(getKeyBindingSignature(sdJWTSerializationObject, signatures))
                .setFilename(document.getName())
                .build();
        attestationPresentation.setElectronicAttestationsOfAttributes(Collections.singletonList(sdJwtEaa)); // only one EAA is possible

        return attestationPresentation;
    }

    /**
     * Gets a list of {@code AdvancedSignature}s from a {@code SDJWTSerializationObject} object
     *
     * @param sdJwtSerializationObject {@link SDJWTSerializationObject} to extract EAA signatures from
     * @return a list of {@link AdvancedSignature}s
     */
    protected List<AdvancedSignature> getSignatures(SDJWTSerializationObject sdJwtSerializationObject) {
        JWSJsonSerializationObject signature = sdJwtSerializationObject.getSignature();
        if (signature == null) {
            throw new IllegalStateException("Signature cannot be absent within SD-JWS VC token!");
        }
        List<JWS> jwsSignatures = signature.getSignatures();
        if (Utils.isCollectionEmpty(jwsSignatures)) {
            throw new IllegalStateException("Signatures cannot be null or empty within SD-JWS VC token!");
        }
        return jwsSignatures.stream().map(this::buildSignature).collect(Collectors.toList());
    }

    /**
     * Gets a key binding {@code AdvancedSignature}, when present
     *
     * @param sdJwtSerializationObject {@link SDJWTSerializationObject}
     * @param signatures a list of {@link AdvancedSignature}s
     * @return {@link AdvancedSignature}
     */
    protected AdvancedSignature getKeyBindingSignature(SDJWTSerializationObject sdJwtSerializationObject, List<AdvancedSignature> signatures) {
        JWSJsonSerializationObject keyBindingSignatureJsonObject = sdJwtSerializationObject.getKeyBindingSignature();
        if (keyBindingSignatureJsonObject == null) {
            return null;
        }
        List<JWS> jwsKeyBindingList = keyBindingSignatureJsonObject.getSignatures();
        if (Utils.isCollectionEmpty(jwsKeyBindingList)) {
            // should not happen
            return null;
        } else if (Utils.collectionSize(jwsKeyBindingList) != 1) {
            throw new IllegalStateException("Only one Key Binding signature is expected within an SD-JWT token!");
        }
        JAdESSignature keyBindingSignature = buildSignature(jwsKeyBindingList.get(0));
        keyBindingSignature.setSigningCertificateSource(signingCertificateSource);
        DSSDocument keyBindingDetachedContent = getKeyBindingDetachedContent(sdJwtSerializationObject);
        if (keyBindingDetachedContent != null) {
            keyBindingSignature.setDetachedContents(Collections.singletonList(keyBindingDetachedContent));
        }
        return keyBindingSignature;
    }

    /**
     * This method returns a computed detached content used for a payload computation of the key binding signature
     *
     * @param sdJwtSerializationObject {@link SDJWTSerializationObject} representing a serialized SD-JWT
     * @return {@link DSSDocument}
     */
    protected abstract DSSDocument getKeyBindingDetachedContent(SDJWTSerializationObject sdJwtSerializationObject);

    /**
     * This method build a JAdES Signature from a {@code JWS} object
     *
     * @param jws {@link JWS}
     * @return {@link JAdESSignature}
     */
    protected JAdESSignature buildSignature(JWS jws) {
        JAdESSignature jadesSignature = new JAdESSignature(jws);
        jadesSignature.setFilename(document.getName());
        jadesSignature.setSigningCertificateSource(signingCertificateSource);
        jadesSignature.setDetachedContents(detachedContents);
        jadesSignature.initBaselineRequirementsChecker(certificateVerifier);
        validateSignaturePolicy(jadesSignature);
        return jadesSignature;
    }

}
