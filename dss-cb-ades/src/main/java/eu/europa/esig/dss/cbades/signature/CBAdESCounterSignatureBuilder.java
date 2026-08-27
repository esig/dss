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

import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSECounterSignStructure;
import eu.europa.esig.dss.cbades.COSECounterSignature;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.cbades.COSEStructure;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeaders;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeadersComponent;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.cbades.validation.COSEDocumentAnalyzer;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.Objects;

/**
 * Creates a CB-AdES Counter signature.
 * This class creates only RFC 9338 Countersignature version 2 type,
 * as other counter signature types do not meet CB-AdES requirements.
 * 
 */
public class CBAdESCounterSignatureBuilder extends CBAdESBuilder {

    /** Master signature to be counter signed */
    private final CBAdESSignature masterSignature;

    private final CertificateVerifier certificateVerifier;

    /** The TSPSource to use for timestamp requests */
    protected TSPSource tspSource;

    /**
     * Constructor for counter signature creation
     *
     * @param certificateVerifier {@link CertificateVerifier} to use
     * @param parameters {@link CBAdESSignatureParameters}
     * @param signatureDocument {@link DSSDocument} containing the target signature to be counter signed
     */
    public CBAdESCounterSignatureBuilder(final CertificateVerifier certificateVerifier, final CBAdESCounterSignatureParameters parameters,
                                         final DSSDocument signatureDocument) {
        super(parameters, new CBAdESLevelBaselineB(certificateVerifier, parameters));
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier must be defined!");
        Objects.requireNonNull(signatureDocument, "Signature document cannot be null!");

        this.masterSignature = extractSignatureById(signatureDocument, parameters.getSignatureIdToCounterSign());
        this.certificateVerifier = certificateVerifier;
    }

    private CBAdESSignature extractSignatureById(final DSSDocument signatureDocument, String signatureId) {
        Objects.requireNonNull(signatureId, "The Id of a signature to be counter signed shall be defined! "
                + "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");

        COSEDocumentAnalyzer documentAnalyzer = new COSEDocumentAnalyzer(signatureDocument);
        AdvancedSignature signatureById = documentAnalyzer.getSignatureById(signatureId);
        if (signatureById == null) {
            throw new IllegalArgumentException(String.format("The requested CB-AdES Signature with id '%s' " +
                    "has not been found in the provided file!", signatureId));
        }
        assertCounterSignaturePossible(signatureById);
        return (CBAdESSignature) signatureById;
    }

    private void assertCounterSignaturePossible(AdvancedSignature targetSignature) {
        assertSignatureTypeSupported(targetSignature);
        assertSignatureNotTimestampedRecursively(targetSignature);
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
                throw new IllegalArgumentException(String.format("The counter signing of a signature type '%s' is not supported!",
                        cbadesSignature.getCOSESignatureType().getLabel()));
        }
    }

    private void assertSignatureNotTimestampedRecursively(AdvancedSignature signature) {
        if (signature != null && signature.getMasterSignature() != null) {
            AdvancedSignature currentMasterSignature = signature.getMasterSignature();
            if (currentMasterSignature.getTimestampSource().isTimestamped(signature.getId(), TimestampedObjectType.SIGNATURE)) {
                throw new IllegalInputException(String.format("Unable to counter sign a signature with Id '%s'. "
                        + "The signature is timestamped by a master signature!", signature.getId()));
            }
            assertSignatureNotTimestampedRecursively(currentMasterSignature);
        }
    }

    /**
     * Sets the TSPSource to be used in case of counter signature augmentation
     *
     * @param tspSource {@link TSPSource}
     */
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    @Override
    protected CBORSignature prepareCBORSignature() {
        COSECounterSignature coseCounterSignature = (COSECounterSignature) createCOSESignStructure();
        CBORSignature counterSignature = CBORSignature.fromCOSECounterSignature(coseCounterSignature);
        ensureDetachedPayload(counterSignature);
        return counterSignature;
    }

    private void ensureDetachedPayload(CBORSignature counterSignature) {
        if (COSESignatureType.COSE_SIGN1 == masterSignature.getCOSESignatureType() && masterSignature.isDetachedSignature()) {
            if (Utils.isCollectionEmpty(parameters.getDetachedContents())) {
                throw new IllegalArgumentException(String.format("Detached contents shall be provided " +
                        "on counter signing a '%s' signature.", masterSignature.getCOSESignatureType().getLabel()));
            }
            masterSignature.setDetachedContents(parameters.getDetachedContents());
            masterSignature.checkSignatureIntegrity(); // required to extract the payload

            counterSignature.setPayload(masterSignature.getCoseSignature().getPayload());
        }
    }

    @Override
    protected CBORObject getPayload(boolean dataToSign) {
        throw new UnsupportedOperationException("The method #getPayload(boolean dataToSign) is not supported " +
                "for CBAdESCounterSignatureBuilder class!");
    }

    /**
     * Embeds and returns the original CBAdES signature containing the embedded counter signature
     *
     * @param signatureValue {@link SignatureValue} to be incorporated
     * @return {@link DSSDocument} original signature document enveloping the {@code counterSignature} in an unprotected header
     */
    public DSSDocument buildEmbeddedCounterSignature(SignatureValue signatureValue) {
        CBAdESUHeaders uHeaders = masterSignature.getUHeaders();
        COSECounterSignature coseCounterSignature = (COSECounterSignature) createCOSESignStructure(signatureValue);

        CBAdESLevelBaselineT signatureExtension = getExtensionProfile(parameters);
        if (signatureExtension != null) {
            CBAdESSignature counterSignature = getCounterSignatureToExtend(coseCounterSignature);

            signatureExtension.setOperationKind(SigningOperation.COUNTER_SIGN);
            signatureExtension.extendSignatures(Collections.singletonList(counterSignature), parameters);

            coseCounterSignature = (COSECounterSignature) counterSignature.getCoseSignature().getSignerSignature();
        }

        uHeaders.addComponent(COSEHeaderParameter.COUNTER_SIGNATURE_V2.cbor(), coseCounterSignature.toCBORObject());

        CBAdESSignature upperSignature = updateMasterSignatureRecursively(masterSignature);
        COSEStructure coseSignStructure = upperSignature.getCoseSignature().getCoseSignStructure();
        byte[] serializedBytes = coseSignStructure.serialize();
        return new InMemoryDocument(serializedBytes);
    }

    private CBAdESSignature getCounterSignatureToExtend(COSECounterSignature coseCounterSignature) {
        CBAdESSignature counterSignature = CBAdESUtils.buildCounterSignatures(masterSignature, COSEHeaderParameter.COUNTER_SIGNATURE_V2.cbor(),
                coseCounterSignature.toCBORObject(), false).iterator().next();
        counterSignature.initBaselineRequirementsChecker(certificateVerifier);
        return counterSignature;
    }

    private CBAdESSignature updateMasterSignatureRecursively(CBAdESSignature signature) {
        CBAdESSignature currentMasterSignature = (CBAdESSignature) signature.getMasterSignature();
        if (signature.getMasterSignature() == null) {
            return signature;
        }

        CBAdESUHeadersComponent masterCSigComponent = signature.getMasterCounterSignatureComponent();
        if (masterCSigComponent != null) {
            CBORSignature coseSignature = signature.getCoseSignature();
            COSECounterSignStructure coseSignStructure = (COSECounterSignStructure) (coseSignature.getCoseSignStructure() != null ?
                    coseSignature.getCoseSignStructure() : coseSignature.getSignerSignature());

            CBAdESUHeadersComponent updatedCSigAttribute = CBAdESUHeadersComponent.build(masterCSigComponent.getHeaderId(),
                    coseSignStructure.toCBORObject(), masterCSigComponent.getIdentifier());

            replaceCSigComponent(currentMasterSignature, updatedCSigAttribute);
        }

        return updateMasterSignatureRecursively(currentMasterSignature);
    }

    private void replaceCSigComponent(CBAdESSignature masterSignature, CBAdESUHeadersComponent cSigAttribute) {
        CBAdESUHeaders uHeaders = masterSignature.getUHeaders();
        uHeaders.replaceComponent(cSigAttribute);
    }

    @Override
    protected COSEStructure createCOSESignStructure(SignatureValue signatureValue) {
        final COSECounterSignature coseCounterSignature = new COSECounterSignature();
        coseCounterSignature.setContext(COSESignatureType.COSE_COUNTER_SIGNATURE_V2); // the only supported counter signature type
        coseCounterSignature.setMasterSignature(getMasterSignatureStructure());
        coseCounterSignature.setTagged(Utils.isTrue(parameters.isTagged()));
        coseCounterSignature.setProtectedHeader(getProtectedHeader());
        coseCounterSignature.setSignature(getSignature(signatureValue));
        return coseCounterSignature;
    }

    private COSEStructure getMasterSignatureStructure() {
        CBORSignature cose = masterSignature.getCoseSignature();
        return COSESignatureType.COSE_SIGN1 == cose.getContext() ? cose.getCoseSignStructure() : cose.getSignerSignature();
    }

    private CBAdESLevelBaselineT getExtensionProfile(CBAdESSignatureParameters parameters) {
        // NOTE: enforce extension to skip the signature validation -> only the current signature is provided to extension
        switch (parameters.getSignatureLevel()) {
            case CB_AdES_BASELINE_B:
                return null;
            case CB_AdES_BASELINE_T:
                final CBAdESLevelBaselineT extensionT = new CBAdESLevelBaselineT(certificateVerifier);
                extensionT.setTspSource(tspSource);
                return extensionT;

            case CB_AdES_BASELINE_LT:
                final CBAdESLevelBaselineLT extensionLT = new CBAdESLevelBaselineLT(certificateVerifier);
                extensionLT.setTspSource(tspSource);
                return extensionLT;

            case CB_AdES_BASELINE_LTA:
                final CBAdESLevelBaselineLTA extensionLTA = new CBAdESLevelBaselineLTA(certificateVerifier);
                extensionLTA.setTspSource(tspSource);
                return extensionLTA;

            default:
                throw new UnsupportedOperationException(
                        String.format("Unsupported signature format '%s' for extension.", parameters.getSignatureLevel()));
        }
    }

}
