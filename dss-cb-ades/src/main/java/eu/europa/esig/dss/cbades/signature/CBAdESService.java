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
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSPKUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Contains methods for CB-AdES signature creation/extension
 *
 */
public class CBAdESService extends AbstractSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> implements
        MultipleDocumentsSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters>,
        CounterSignatureService<CBAdESCounterSignatureParameters> {

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESService.class);

    /**
     * This is the constructor to create an instance of the {@code CBAdESService}. A
     * certificate verifier must be provided.
     *
     * @param certificateVerifier {@code CertificateVerifier} provides information
     *                            on the sources to be used in the validation
     *                            process in the context of a signature.
     */
    public CBAdESService(final CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
        LOG.debug("+ CBAdESService created");
    }

    @Override
    public ToBeSigned getDataToSign(DSSDocument toSignDocument, CBAdESSignatureParameters parameters) {
        Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");

        assertSignatureParameters(parameters);

        CBAdESBuilder cbadesBuilder = getCBAdESBuilder(parameters, Collections.singletonList(toSignDocument));
        return cbadesBuilder.buildDataToBeSigned();
    }

    @Override
    public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, CBAdESSignatureParameters parameters) {
        Objects.requireNonNull(toSignDocuments, "toSignDocuments cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");

        assertMultiDocumentsAllowed(toSignDocuments, parameters);

        CBAdESBuilder cbadesBuilder = getCBAdESBuilder(parameters, toSignDocuments);
        return cbadesBuilder.buildDataToBeSigned();
    }

    @Override
    public DSSDocument signDocument(DSSDocument toSignDocument, CBAdESSignatureParameters parameters, SignatureValue signatureValue) {
        Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
        return signDocument(Collections.singletonList(toSignDocument), parameters, signatureValue);
    }

    @Override
    public DSSDocument signDocument(List<DSSDocument> toSignDocuments, CBAdESSignatureParameters parameters, SignatureValue signatureValue) {
        Objects.requireNonNull(toSignDocuments, "toSignDocuments cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
        Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
        assertMultiDocumentsAllowed(toSignDocuments, parameters);
        assertSignatureParameters(parameters);

        CBAdESBuilder cbadesBuilder = getCBAdESBuilder(parameters, toSignDocuments);
        DSSDocument signedDocument = cbadesBuilder.build(signatureValue);
        
        CBAdESLevelBaselineExtension signatureExtension = getExtensionProfile(parameters);
        if (signatureExtension != null) {
            if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging()) &&
                    Utils.isCollectionEmpty(parameters.getDetachedContents())) {
                parameters.getContext().setDetachedContents(toSignDocuments);
            }
            signatureExtension.setOperationKind(SigningOperation.SIGN);
            signedDocument = signatureExtension.extendSignatures(signedDocument, parameters);
        }

        parameters.reinit();
        signedDocument.setName(getFinalFileName(toSignDocuments.iterator().next(), SigningOperation.SIGN, parameters.getSignatureLevel()));
        signedDocument.setMimeType(MimeTypeEnum.COSE);
        return signedDocument;
    }

    @Override
    public DSSDocument extendDocument(DSSDocument toExtendDocument, CBAdESSignatureParameters parameters) {
        Objects.requireNonNull(toExtendDocument, "toExtendDocument cannot be null!");
        Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");
        Objects.requireNonNull(parameters.getSignatureLevel(), "SignatureLevel must be defined!");

        final CBAdESLevelBaselineExtension signatureExtension = getExtensionProfile(parameters);
        if (signatureExtension != null) {
            signatureExtension.setOperationKind(SigningOperation.EXTEND);
            final DSSDocument dssDocument = signatureExtension.extendSignatures(toExtendDocument, parameters);
            dssDocument.setName(
                    getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
            dssDocument.setMimeType(MimeTypeEnum.COSE);
            return dssDocument;
        }
        throw new UnsupportedOperationException(
                String.format("Unsupported signature format '%s' for extension.", parameters.getSignatureLevel()));
    }

    @Override
    public TimestampToken getContentTimestamp(DSSDocument toSignDocument, CBAdESSignatureParameters parameters) {
        return getContentTimestamp(Collections.singletonList(toSignDocument), parameters);
    }

    /**
     * This method allows creation of a TimestampToken for a detached CBAdES (with a 'sigD' parameter).
     * NOTE: The toSignDocuments must be present in the same order they will be passed to signature computation process
     *
     * @param toSignDocuments a list of {@link DSSDocument}s to be timestamped
     * @param parameters {@link CBAdESSignatureParameters}
     * @return content {@link TimestampToken}
     */
    @Override
    public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, CBAdESSignatureParameters parameters) {
        Objects.requireNonNull(tspSource, "A TSPSource is required!");
        assertContentTimestampCreationPossible(toSignDocuments);

        byte[] messageImprint = CBAdESUtils.concatenateDSSDocuments(toSignDocuments);
        /*
         * 1) If the sigD header parameter, as specified in clause 5.2.8 of the present document,
         * is absent then the message imprint computation input shall be:
         * - The CBOR byte string of the payload field, if the payload field is present.
         * - The bytes of the detached COSE Payload, encapsulated in a CBOR byte string,
         *   if the COSE Payload is detached (the payload field is absent).
         */
        if (SignaturePackaging.DETACHED != parameters.getSignaturePackaging() || SigDMechanism.NO_SIG_D == parameters.getSigDMechanism()) {
            CBORByteString cborByteString = new CBORByteString(messageImprint);
            messageImprint = CBORUtils.serializeCborObject(cborByteString);
        }

        DigestAlgorithm digestAlgorithm = parameters.getContentTimestampParameters().getDigestAlgorithm();
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm,
                DSSUtils.digest(digestAlgorithm, messageImprint));
        try {
            return new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
        } catch (Exception e) {
            throw new DSSException("Cannot create a content TimestampToken", e);
        }
    }

    private void assertContentTimestampCreationPossible(List<DSSDocument> documents) {
        if (Utils.isCollectionEmpty(documents)) {
            throw new IllegalArgumentException("Original documents must be provided to generate a content timestamp!");
        }
        for (DSSDocument document : documents) {
            if (document instanceof DigestDocument) {
                throw new IllegalArgumentException("Content timestamp creation is not possible with DigestDocument!");
            }
        }
    }

    @Override
    public DSSDocument timestamp(List<DSSDocument> toTimestampDocuments, CBAdESTimestampParameters parameters) {
        throw new UnsupportedOperationException("Unsupported operation for this file format");
    }

    @Override
    public ToBeSigned getDataToBeCounterSigned(DSSDocument signatureDocument, CBAdESCounterSignatureParameters parameters) {
        Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
        verifyAndSetCounterSignatureParameters(parameters);

        final CBAdESCounterSignatureBuilder counterSignatureBuilder =
                new CBAdESCounterSignatureBuilder(certificateVerifier, parameters, signatureDocument);
        return counterSignatureBuilder.buildDataToBeSigned();
    }

    @Override
    public DSSDocument counterSignSignature(DSSDocument signatureDocument, CBAdESCounterSignatureParameters parameters,
                                            SignatureValue signatureValue) {
        Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
        Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
        verifyAndSetCounterSignatureParameters(parameters);

        final CBAdESCounterSignatureBuilder counterSignatureBuilder =
                new CBAdESCounterSignatureBuilder(certificateVerifier, parameters, signatureDocument);
        counterSignatureBuilder.setTspSource(tspSource);
        DSSDocument counterSigned = counterSignatureBuilder.buildEmbeddedCounterSignature(signatureValue);

        parameters.reinit();
        counterSigned.setName(getFinalFileName(signatureDocument, SigningOperation.COUNTER_SIGN,
                parameters.getSignatureLevel()));
        counterSigned.setMimeType(signatureDocument.getMimeType());

        return counterSigned;
    }

    /**
     * Returns the CBAdESBuilder to be used
     *
     * @param parameters {@link CBAdESSignatureParameters}
     * @param documentsToSign a list of {@link DSSDocument}s
     * @return {@link CBAdESBuilder}
     */
    protected CBAdESBuilder getCBAdESBuilder(CBAdESSignatureParameters parameters, List<DSSDocument> documentsToSign) {
        COSESignStructure coseSignStructure = getCOSESignStructureToSign(documentsToSign);
        if (containsSignatures(coseSignStructure)) {
            // TODO : add validation against schema ?
            // return a builder for parallel signing
            return new CBAdESBuilder(certificateVerifier, parameters, (COSESign) coseSignStructure);
        }

        return new CBAdESBuilder(certificateVerifier, parameters, documentsToSign);
    }

    private COSESignStructure getCOSESignStructureToSign(List<DSSDocument> documentsToSign) {
        if (Utils.isCollectionNotEmpty(documentsToSign) && documentsToSign.size() == 1) {
            DSSDocument document = documentsToSign.get(0);
            try {
                return COSEParser.fromDocument(document).parse();
            } catch (Exception e) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("The provided document with name '{}' is not of COSE type", document.getName());
                }
            }
        }
        return null;
    }

    private boolean containsSignatures(COSESignStructure coseSignStructure) {
        if (coseSignStructure != null) {
            if (COSESignatureType.COSE_SIGN == coseSignStructure.getContext()) {
                return Utils.isCollectionNotEmpty(((COSESign) coseSignStructure).getSignatures());
            }
            throw new IllegalInputException("Parallel signing is not supported for COSE_Sign1 RFC 9052 signatures!");
        }
        return false;
    }

    private CBAdESLevelBaselineExtension getExtensionProfile(CBAdESSignatureParameters parameters) {
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

    private void verifyAndSetCounterSignatureParameters(CBAdESCounterSignatureParameters parameters) {
        // detached counter signature is the only allowed type
        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        if (parameters.getSigDMechanism() == null) {
            parameters.setSigDMechanism(SigDMechanism.NO_SIG_D);
        } else if (!SigDMechanism.NO_SIG_D.equals(parameters.getSigDMechanism())) {
            throw new IllegalArgumentException(String.format("The SigDMechanism '%s' is not supported by CBAdES Counter Signature!",
                    parameters.getSigDMechanism()));
        }

        assertSignatureParameters(parameters);
    }

    /**
     * This method verifies validity of the signature parameters and provides the necessary configuration, where applicable
     *
     * @param signatureParameters {@link CBAdESSignatureParameters}
     */
    protected void assertSignatureParameters(final CBAdESSignatureParameters signatureParameters) {
        assertSigningCertificateValid(signatureParameters);
        if (signatureParameters.isTagged() == null) {
            signatureParameters.setTagged(true);
            LOG.debug("No tagged parameters provided. Use default value 'true' instead.'");
        }
    }

    @Override
    protected void assertSigningCertificateValid(AbstractSignatureParameters<?> parameters) {
        super.assertSigningCertificateValid(parameters);
        assertSigningCertificateValid(parameters.getSignatureAlgorithm(), parameters.getSigningCertificate());
    }

    private void assertSigningCertificateValid(SignatureAlgorithm signatureAlgorithm, CertificateToken signingCertificate) {
        if (signatureAlgorithm.getEncryptionAlgorithm() != null && signatureAlgorithm.getDigestAlgorithm() != null &&
                signatureAlgorithm.getEncryptionAlgorithm().isEquivalent(EncryptionAlgorithm.ECDSA) &&
                signingCertificate != null) {
            String errorMessage = "For ECDSA with %s a key with P-%s curve shall be used for a COSE! See RFC 9053.";
            int keySize = DSSPKUtils.getPublicKeySize(signingCertificate.getPublicKey());
            switch (signatureAlgorithm.getDigestAlgorithm()) {
                case SHA256:
                    if (256 != keySize) {
                        throw new IllegalArgumentException(String.format(errorMessage, signatureAlgorithm.getDigestAlgorithm(), 256));
                    }
                    break;
                case SHA384:
                    if (320 != keySize && 384 != keySize) {
                        throw new IllegalArgumentException(String.format(errorMessage, signatureAlgorithm.getDigestAlgorithm(), 384));
                    }
                    break;
                case SHA512:
                    if (512 != keySize && 521 != keySize) {
                        throw new IllegalArgumentException(String.format(errorMessage, signatureAlgorithm.getDigestAlgorithm(), 521));
                    }
                    break;
                default:
                    throw new UnsupportedOperationException(String.format(
                            "ECDSA with %s is not supported for COSE!", signatureAlgorithm.getDigestAlgorithm()));
            }
        }
    }

    /**
     * Only DETACHED signatures are allowed
     *
     * @param toSignDocuments list of {@link DSSDocument}s
     * @param parameters {@link CBAdESSignatureParameters}
     */
    private void assertMultiDocumentsAllowed(List<DSSDocument> toSignDocuments, CBAdESSignatureParameters parameters) {
        Objects.requireNonNull(parameters.getSignaturePackaging(), "SignaturePackaging shall be defined!");

        if (Utils.isCollectionEmpty(toSignDocuments)) {
            throw new IllegalArgumentException("The documents to sign must be provided!");
        }
        SignaturePackaging signaturePackaging = parameters.getSignaturePackaging();
        if (!SignaturePackaging.DETACHED.equals(signaturePackaging) && toSignDocuments.size() > 1) {
            throw new IllegalArgumentException("Not supported operation (only DETACHED are allowed for multiple document signing)!");
        }
        if (SignaturePackaging.DETACHED.equals(signaturePackaging) && SigDMechanism.NO_SIG_D.equals(parameters.getSigDMechanism())
                && toSignDocuments.size() > 1) {
            throw new IllegalArgumentException("NO_SIG_D mechanism is not allowed for multiple documents!");
        }
    }

}
