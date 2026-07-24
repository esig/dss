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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentAnalyzer;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.attestation.AttestationValidationParameters;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Abstract implementation for analyzing an ISO/IEC 18013-5 mdoc document instance
 *
 */
public abstract class AbstractMdocAttestationDocumentAnalyzer extends DefaultAttestationDocumentAnalyzer {

    /**
     * Default constructor
     */
    protected AbstractMdocAttestationDocumentAnalyzer() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to validate
     */
    protected AbstractMdocAttestationDocumentAnalyzer(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");
        this.document = document;
    }

    @Override
    protected MdocValidationParameters getEAAValidationParameters() {
        AttestationValidationParameters attestationValidationParameters = super.getEAAValidationParameters();
        if (attestationValidationParameters != null && !(attestationValidationParameters instanceof MdocValidationParameters)) {
            throw new IllegalStateException("attestationValidationParameters shall be an instance of MdocValidationParameters!");
        }
        return (MdocValidationParameters) attestationValidationParameters;
    }

    @Override
    public void setEAAValidationParameters(AttestationValidationParameters attestationValidationParameters) {
        if (attestationValidationParameters != null && !(attestationValidationParameters instanceof MdocValidationParameters)) {
            throw new IllegalArgumentException("attestationValidationParameters shall be an instance of MdocValidationParameters!");
        }
        super.setEAAValidationParameters(attestationValidationParameters);
    }

    /**
     * Builds a COSE signature instance from a {@code COSESignStructure}
     *
     * @param coseSignStructure {@link COSESignStructure}
     * @return {@link CBAdESSignature}
     */
    protected CBAdESSignature getCoseSignature(COSESignStructure coseSignStructure) {
        if (COSESignatureType.COSE_SIGN1 != coseSignStructure.getContext()) {
            throw new IllegalInputException("The mdoc signature shall be represented by a 'COSE_Sign1' object!");
        }

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESignStructure(coseSignStructure);
        if (Utils.collectionSize(cborSignatures) != 1) {
            throw new IllegalInputException(String.format("1 signature is expected. Obtained : '%s'", Utils.collectionSize(cborSignatures)));
        }
        CBORSignature cose = cborSignatures.get(0);
        CBAdESSignature cbadesSignature = new MdocCBAdESSignature(cose);
        cbadesSignature.setFilename(document.getName());
        cbadesSignature.setSigningCertificateSource(signingCertificateSource);
        cbadesSignature.setDetachedContents(detachedContents);
        cbadesSignature.initBaselineRequirementsChecker(certificateVerifier);
        validateSignaturePolicy(cbadesSignature);
        return cbadesSignature;
    }

    /**
     * CBAdESSignature for ISO/IEC mdoc document
     */
    private static class MdocCBAdESSignature extends CBAdESSignature {

        private static final long serialVersionUID = -3472806679784132688L;

        /**
         * Default constructor
         *
         * @param cose {@link CBORSignature}
         */
        public MdocCBAdESSignature(CBORSignature cose) {
            super(cose);
        }

        @Override
        protected List<String> validateStructure() {
            List<String> structureValidation = super.validateStructure();
            if (isTagged()) {
                structureValidation = new ArrayList<>(structureValidation);
                structureValidation.add("Signature is a tagged COSE_Sign1! Shall be untagged COSE_Sign1.");
            }
            return structureValidation;
        }

    }

}
