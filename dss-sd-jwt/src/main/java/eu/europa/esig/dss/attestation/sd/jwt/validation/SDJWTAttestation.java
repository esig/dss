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

import eu.europa.esig.dss.attestation.common.validation.DefaultAttestation;
import eu.europa.esig.dss.attestation.common.validation.AttestationPayloadVerifier;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.spi.attestation.KeyBindingSignaturePayload;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * This class represents an SD-JWT object, as per IETF draft-ietf-oauth-selective-disclosure-jwt-22.
 *
 */
public class SDJWTAttestation extends DefaultAttestation {

    /**
     * Default constructor
     */
    protected SDJWTAttestation() {
        // empty
    }

    /**
     * Instantiates a builder to create an {@code SDJWT} object
     *
     * @return {@link SDJWTAttestationBuilder}
     */
    public static SDJWTAttestationBuilder initBuilder() {
        return new SDJWTAttestationBuilder();
    }

    @Override
    public AttestationProfile getAttestationProfile() {
        return AttestationProfile.SD_JWT_VC;
    }

    @Override
    public KeyBindingSignaturePayload getKeyBindingSignaturePayload() {
        if (getKeyBindingSignature() == null) {
            return null;
        }

        return new SDJWTKeyBindingSignaturePayload(getKeyBindingPayloadMap());
    }


    private Map<String, Object> getKeyBindingPayloadMap() {
        JAdESSignature signature = (JAdESSignature) getKeyBindingSignature();
        LinkedHashMap<String, Object> result = new LinkedHashMap<>(signature.getJws().getDecodedPayload());
        result.remove(SDJWTConstants.SD_HASH);
        return result;
    }

    @Override
    protected AttestationPayloadVerifier initAttestationPayloadVerifier() {
        List<AdvancedSignature> signatures = getSignatures();
        if (Utils.isCollectionEmpty(signatures)) {
            throw new IllegalStateException("SD-JWT signatures cannot be empty!");
        }
        JAdESSignature signature = (JAdESSignature) signatures.get(0); // payload is the same for attestation signatures
        try {
            return new SDJWTPayloadVerifier(signature.getJws().getDecodedPayload());
        } catch (Exception e) {
            throw new DSSException(String.format("Unable to read SD-JWT payload : %s", e.getMessage()), e);
        }
    }

    /**
     * This class is used to build a {@code eu.europa.esig.dss.attestation.sd.jwt.validation.SDJWTAttestation} object
     *
     */
    public static class SDJWTAttestationBuilder extends DefaultAttestationBuilder {

        /**
         * Default constructor
         */
        public SDJWTAttestationBuilder() {
            // empty
        }

        @Override
        public SDJWTAttestationBuilder setSignatures(List<AdvancedSignature> signatures) {
            return (SDJWTAttestationBuilder) super.setSignatures(signatures);
        }

        @Override
        public SDJWTAttestationBuilder setDisclosures(List<SelectiveDisclosure> disclosures) {
            return (SDJWTAttestationBuilder) super.setDisclosures(disclosures);
        }

        @Override
        public SDJWTAttestationBuilder setKeyBindingSignature(AdvancedSignature keyBindingSignature) {
            return (SDJWTAttestationBuilder) super.setKeyBindingSignature(keyBindingSignature);
        }

        @Override
        public SDJWTAttestationBuilder setFilename(String filename) {
            return (SDJWTAttestationBuilder) super.setFilename(filename);
        }

        @Override
        protected DefaultAttestation initAttestation() {
            return new SDJWTAttestation();
        }

        @Override
        public SDJWTAttestation build() {
            return (SDJWTAttestation) super.build();
        }

    }

}
