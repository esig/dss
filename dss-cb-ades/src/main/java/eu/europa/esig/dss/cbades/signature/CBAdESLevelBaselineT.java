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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeaders;
import eu.europa.esig.dss.cbades.validation.COSEDocumentAnalyzer;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.enumerations.SignatureLevel.CB_AdES_BASELINE_T;

/**
 * This class provides a functionality for the CB-AdES-BASELINE-T profile augmentation.
 *
 */
public class CBAdESLevelBaselineT extends CBAdESExtensionBuilder implements CBAdESLevelBaselineExtension {

    /** The CertificateVerifier to use */
    protected final CertificateVerifier certificateVerifier;

    /**
     * The object encapsulating the Time Stamp Protocol needed to create the level
     * -T, of the signature
     */
    protected TSPSource tspSource;

    /**
     * The cached instance of a document validator
     */
    protected COSEDocumentAnalyzer documentAnalyzer;

    /**
     * Internal variable: defines the current signing procedure (used in signature creation/extension)
     */
    private SigningOperation operationKind;

    /**
     * The default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier} to use
     */
    public CBAdESLevelBaselineT(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    /**
     * Sets the TSP source to be used when extending the digital signature
     *
     * @param tspSource the tspSource to set
     */
    public void setTspSource(final TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    /**
     * Sets the signing operation type.
     * NOTE: the internal variable, used in the signature creation/extension process
     *
     * @param signingOperation {@link SigningOperation}
     */
    public void setOperationKind(SigningOperation signingOperation) {
        this.operationKind = signingOperation;
    }

    @Override
    public DSSDocument extendSignatures(DSSDocument document, CBAdESSignatureParameters params) {
        Objects.requireNonNull(document, "The document cannot be null");
        Objects.requireNonNull(tspSource, "The TSPSource cannot be null");

        documentAnalyzer = new COSEDocumentAnalyzer(document);
        initDocumentAnalyzer(documentAnalyzer, params);

        COSESignStructure coseSignStructure = documentAnalyzer.getCoseSignStructure();
        assertCOSESignStructureValid(coseSignStructure);

        List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();
        if (Utils.isCollectionEmpty(signatures)) {
            throw new IllegalInputException("There is no signature to extend!");
        }

        List<AdvancedSignature> signaturesToExtend = signatures;
        // this method allows extension of only the current signature on creation
        if (SigningOperation.SIGN.equals(operationKind)) {
            signaturesToExtend = Collections.singletonList(signatures.get(signatures.size() - 1));
        }
        assertAugmentationPossible(signaturesToExtend);

        extendSignatures(signaturesToExtend, params);

        byte[] serializedBytes = coseSignStructure.serialize();
        return new InMemoryDocument(serializedBytes);
    }

    /**
     * Extends the signatures
     *
     * @param signatures a list of {@link AdvancedSignature}s to be extended
     * @param params {@link CBAdESSignatureParameters} the extension parameters
     */
    protected void extendSignatures(List<AdvancedSignature> signatures, CBAdESSignatureParameters params) {
        final List<AdvancedSignature> signaturesToExtend = getExtendToTLevelSignatures(signatures, params);
        if (Utils.isCollectionEmpty(signaturesToExtend)) {
            return;
        }

        final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker(params);
        signatureRequirementsChecker.assertExtendToTLevelPossible(signaturesToExtend);

        signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
        signatureRequirementsChecker.assertSigningCertificateIsValid(signaturesToExtend);

        for (AdvancedSignature signature : signaturesToExtend) {
            CBAdESSignature cbadesSignature = (CBAdESSignature) signature;

            assertUHeadersComponentsConsistent(cbadesSignature);

            CBAdESTimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
            DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();

            final DSSMessageDigest messageDigest = cbadesSignature.getTimestampSource()
                    .getSignatureTimestampData(timestampDigestAlgorithm);
            TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(timestampDigestAlgorithm, messageDigest.getValue());

            CBORValue tstContainer = CBAdESUtils.getTstContainer(Collections.singletonList(timeStampResponse));

            CBAdESUHeaders uHeaders = cbadesSignature.getUHeaders();
            uHeaders.addComponent(COSEHeaderParameter.SIG_TST.cbor(), tstContainer);
        }
    }

    private List<AdvancedSignature> getExtendToTLevelSignatures(List<AdvancedSignature> signatures, CBAdESSignatureParameters parameters) {
        final List<AdvancedSignature> toBeExtended = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            if (tLevelExtensionRequired(signature, parameters)) {
                toBeExtended.add(signature);
            }
        }
        return toBeExtended;
    }

    /**
     * Verifies if the T-level extension is required and possible
     *
     * @param signature {@link AdvancedSignature} to check
     * @param parameters {@link CBAdESSignatureParameters}
     * @return TRUE if the extension is possible, FALSE otherwise
     */
    protected boolean tLevelExtensionRequired(AdvancedSignature signature, CBAdESSignatureParameters parameters) {
        return CB_AdES_BASELINE_T.equals(parameters.getSignatureLevel()) || !signature.hasTProfile();
    }

    /**
     * This method returns validation data for the given {@code signatures}
     *
     * @param signatures a list of {@link AdvancedSignature}s to get validation data for
     * @param params {@link CBAdESSignatureParameters} signature augmentation parameters
     * @return {@link ValidationDataContainer}
     */
    protected ValidationDataContainer getValidationData(List<AdvancedSignature> signatures, CBAdESSignatureParameters params) {
        // Empty DocumentAnalyzer should be instantiated for counter-signatures, because of their different structure
        if (documentAnalyzer == null) {
            documentAnalyzer = new COSEDocumentAnalyzer();
            initDocumentAnalyzer(documentAnalyzer, params);
        }
        return documentAnalyzer.getValidationData(signatures);
    }

    private void initDocumentAnalyzer(COSEDocumentAnalyzer documentAnalyzer, CBAdESSignatureParameters params) {
        documentAnalyzer.setCertificateVerifier(certificateVerifier);
        documentAnalyzer.setDetachedContents(params.getDetachedContents());
        documentAnalyzer.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);
    }

    /**
     * Instantiates a {@code SignatureRequirementsChecker}
     *
     * @param parameters {@link CBAdESSignatureParameters}
     * @return {@link SignatureRequirementsChecker}
     */
    protected SignatureRequirementsChecker getSignatureRequirementsChecker(CBAdESSignatureParameters parameters) {
        return new SignatureRequirementsChecker(certificateVerifier, parameters);
    }

    private void assertAugmentationPossible(List<AdvancedSignature> signatures) {
        for (AdvancedSignature signature : signatures) {
            assertSignatureTypeSupported(signature);
            assertSignatureNotTimestampedRecursively(signature);
        }
    }

    private void assertSignatureTypeSupported(AdvancedSignature targetSignature) {
        CBAdESSignature cbadesSignature = (CBAdESSignature) targetSignature;
        switch (cbadesSignature.getCOSESignatureType()) {
            case COSE_SIGN:
            case COSE_SIGN1:
            case COSE_COUNTER_SIGNATURE:
            case COSE_COUNTER_SIGNATURE_V2:
                // supported types
                break;
            default:
                throw new IllegalArgumentException(String.format("The augmentation of a signature type '%s' is not supported!",
                        cbadesSignature.getCOSESignatureType().getLabel()));
        }
    }

    private void assertSignatureNotTimestampedRecursively(AdvancedSignature signature) {
        if (signature != null && signature.getMasterSignature() != null) {
            AdvancedSignature masterSignature = signature.getMasterSignature();
            if (masterSignature.getTimestampSource().isTimestamped(signature.getId(), TimestampedObjectType.SIGNATURE)) {
                throw new IllegalInputException(String.format("Unable to counter sign a signature with Id '%s'. "
                        + "The signature is timestamped by a master signature!", signature.getId()));
            }
            assertSignatureNotTimestampedRecursively(masterSignature);
        }
    }

    /**
     * Checks if the {@code coseSignStructure} is valid and can be extended
     *
     * @param coseSignStructure {@link COSESignStructure} to check
     */
    protected void assertCOSESignStructureValid(COSESignStructure coseSignStructure) {
        if (coseSignStructure == null) {
            throw new IllegalInputException("The provided document is not a valid CB-AdES signature! Unable to extend.");
        }
    }

}
