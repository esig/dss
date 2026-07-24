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
package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.eaa.common.validation.DefaultAttestation;
import eu.europa.esig.dss.eaa.common.validation.AttestationPayloadVerifier;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDeviceNameSpaces;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDocument;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.model.eaa.ValidationDisclosure;
import eu.europa.esig.dss.spi.eaa.KeyBindingSignaturePayload;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * Represents an attestation embedded within an mdoc response
 *
 */
public class MdocAttestation extends DefaultAttestation {

    /** Document mdoc object enveloping the EAA */
    private MdocDocument document;

    /**
     * Default constructor
     */
    protected MdocAttestation() {
        // empty
    }

    /**
     * Instantiates a builder to create an {@code SDJWTPresentation} object
     *
     * @return {@link MdocAttestationBuilder}
     */
    public static MdocAttestationBuilder initBuilder() {
        return new MdocAttestationBuilder();
    }

    /**
     * Gets mdoc Document
     *
     * @return {@link MdocDocument}
     */
    public MdocDocument getDocument() {
        return document;
    }

    /**
     * Sets the Document
     *
     * @param document {@link MdocDocument}
     */
    public void setDocument(MdocDocument document) {
        this.document = document;
    }

    @Override
    public AttestationFormat getEAAType() {
        return AttestationFormat.ISO_IEC_MDOC;
    }

    @Override
    protected AttestationPayloadVerifier initEAAPayloadVerifier() {
        List<AdvancedSignature> signatures = getSignatures();
        if (Utils.isCollectionEmpty(signatures)) {
            throw new IllegalStateException("SD-JWT VC signatures cannot be empty!");
        }
        CBAdESSignature signature = (CBAdESSignature) signatures.get(0); // payload is the same for EAA signatures within the same mdoc Document
        MdocPayloadVerifier payloadVerifier = new MdocPayloadVerifier(signature.getCoseSignature().getPayload());
        if (document != null) {
            payloadVerifier.setDocType(document.getDocType());
        }
        return payloadVerifier;
    }

    @Override
    public KeyBindingSignaturePayload getKeyBindingSignaturePayload() {
        if ((document == null) || (document.getDeviceSigned() == null)) {
            return null;
        }
        final MdocDeviceNameSpaces deviceNameSpaces = document.getDeviceSigned().getDeviceNameSpaces();
        return new MdocKeyBindingSignaturePayload(deviceNameSpaces.getNamespaces());
    }

    /**
     * This class is used to build a {@code eu.europa.esig.dss.eaa.mdoc.validation.MdocEAA} object
     *
     */
    public static class MdocAttestationBuilder extends DefaultAttestationBuilder {

        /** Document mdoc object enveloping the EAA */
        private MdocDocument document;

        /**
         * Default constructor
         */
        public MdocAttestationBuilder() {
            // empty
        }

        @Override
        public MdocAttestationBuilder setSignatures(List<AdvancedSignature> signatures) {
            return (MdocAttestationBuilder) super.setSignatures(signatures);
        }

        @Override
        public MdocAttestationBuilder setDisclosures(List<ValidationDisclosure> disclosures) {
            return (MdocAttestationBuilder) super.setDisclosures(disclosures);
        }

        @Override
        public MdocAttestationBuilder setKeyBindingSignature(AdvancedSignature keyBindingSignature) {
            return (MdocAttestationBuilder) super.setKeyBindingSignature(keyBindingSignature);
        }

        @Override
        public MdocAttestationBuilder setFilename(String filename) {
            return (MdocAttestationBuilder) super.setFilename(filename);
        }

        /**
         * Sets the mdoc docType
         *
         * @param document {@link String}
         * @return {@link MdocAttestationBuilder}
         */
        public MdocAttestationBuilder setDocument(MdocDocument document) {
            this.document = document;
            return this;
        }

        @Override
        protected DefaultAttestation initEAA() {
            return new MdocAttestation();
        }

        @Override
        public MdocAttestation build() {
            MdocAttestation mdocEAA = (MdocAttestation) super.build();
            mdocEAA.setDocument(document);
            return mdocEAA;
        }

    }

}
