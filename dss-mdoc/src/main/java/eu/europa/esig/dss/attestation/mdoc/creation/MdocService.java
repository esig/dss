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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.attestation.common.creation.AbstractAttestationService;
import eu.europa.esig.dss.attestation.common.creation.SelectiveDisclosure;
import eu.europa.esig.dss.attestation.common.creation.AttestationPayloadBuilder;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This service is used to handle creation and issuance workflow for ISO/IEC 18013-5 mdoc EAAs and presentations
 *
 */
public class MdocService extends AbstractAttestationService<CBAdESSignatureParameters, MdocPayloadParameters, MdocClaim, MdocSelectiveDisclosure, MdocKeyBindingParameters> {

    private static final long serialVersionUID = 6514504397480840459L;

    private static final Logger LOG = LoggerFactory.getLogger(MdocService.class);

    /**
     * Default constructor to instantiate an {@code SDJWTEAAService}
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    public MdocService(final CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
        LOG.debug("+ MdocService created");
    }

    @Override
    public ToBeSigned getDataToBeSigned(DSSDocument payload, CBAdESSignatureParameters signatureParameters) {
        validatePayload(payload);
        ensureSignatureParameters(signatureParameters);
        return dataToBeSigned(payload, signatureParameters);
    }

    @Override
    public ToBeSigned getDataToBeSigned(MdocPayloadParameters payloadParameters, CBAdESSignatureParameters signatureParameters) {
        Objects.requireNonNull(payloadParameters, "MdocEAAPayloadParameters cannot be null!");
        ensureSignatureParameters(signatureParameters);
        ensurePayloadParameters(payloadParameters, signatureParameters);
        return dataToBeSigned(getPayloadBuilder().buildPayload(payloadParameters), signatureParameters);
    }

    /**
     * This method retrieves to be signed data without performing validation of the provided data.
     * NOTE: used to avoid redundant parsing when the payload is generated within the service.
     *
     * @param payload {@link DSSDocument}
     * @param signatureParameters {@link CBAdESSignatureParameters}
     * @return {@link ToBeSigned}
     */
    protected ToBeSigned dataToBeSigned(DSSDocument payload, CBAdESSignatureParameters signatureParameters) {
        return getCBAdESService().getDataToSign(payload, signatureParameters);
    }

    @Override
    public DSSDocument signEAA(DSSDocument payload, CBAdESSignatureParameters signatureParameters, SignatureValue signatureValue) {
        validatePayload(payload);
        ensureSignatureParameters(signatureParameters);
        return signDocument(payload, signatureParameters, signatureValue);
    }

    @Override
    public DSSDocument signEAA(MdocPayloadParameters payloadParameters, CBAdESSignatureParameters signatureParameters, SignatureValue signatureValue) {
        Objects.requireNonNull(payloadParameters, "MdocEAAPayloadParameters cannot be null!");
        ensureSignatureParameters(signatureParameters);
        ensurePayloadParameters(payloadParameters, signatureParameters);
        return signDocument(getPayloadBuilder().buildPayload(payloadParameters), signatureParameters, signatureValue);
    }

    /**
     * This method signs the obtained document without performing validation of the provided data.
     * NOTE: used to avoid redundant parsing when the payload is generated within the service.
     *
     * @param payload {@link DSSDocument}
     * @param signatureParameters {@link CBAdESSignatureParameters}
     * @param signatureValue {@link SignatureValue}
     * @return {@link DSSDocument}
     */
    protected DSSDocument signDocument(DSSDocument payload, CBAdESSignatureParameters signatureParameters, SignatureValue signatureValue) {
        return getCBAdESService().signDocument(payload, signatureParameters, signatureValue);
    }

    /**
     * This method verifies validity of the signature parameters and provides the necessary configuration, where applicable
     *
     * @param signatureParameters {@link CBAdESSignatureParameters}
     */
    protected void ensureSignatureParameters(final CBAdESSignatureParameters signatureParameters) {
        Objects.requireNonNull(signatureParameters, "signatureParameters cannot be null!");

        if (signatureParameters.getSignatureLevel() == null) {
            signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
            LOG.debug("SignatureLevel is absent and was set to '{}'", SignatureLevel.CB_AdES_BASELINE_B);

        } else if (SignatureLevel.CB_AdES_BASELINE_B != signatureParameters.getSignatureLevel()) {
            throw new IllegalArgumentException("Signature level must be CB-AdES-BASELINE-B!");
        }

        if (signatureParameters.getSignaturePackaging() == null) {
            signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            LOG.debug("SignaturePackaging is absent and was set to '{}'", SignaturePackaging.ENVELOPING);

        } else if (SignaturePackaging.ENVELOPING != signatureParameters.getSignaturePackaging()) {
            throw new IllegalArgumentException("Signature packaging must be ENVELOPING");
        }

        if (COSEStructureType.COSE_SIGN1 != signatureParameters.getCoseStructureType()) {
            signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
            LOG.debug("COSEStructureType was set to '{}'", COSEStructureType.COSE_SIGN1);
        }

        if (signatureParameters.isTagged() == null) {
            signatureParameters.setTagged(false);
            LOG.debug("COSE_Sign1 structure shall be untagged for mdoc signature. The value was set to 'false'.");
        } else if (Utils.isTrue(signatureParameters.isTagged())) {
            throw new IllegalArgumentException("COSE_Sign1 structure shall be untagged!");
        }

        if (!signatureParameters.isIncludeCertificateChain()) {
            throw new IllegalArgumentException("Certificate chain must be included within the mdoc EAA signature!");
        }
        ensureSigningCertificateDigestAlgorithm(signatureParameters);

        if (signatureParameters.getX5ChainHeaderPlacement() == null) {
            signatureParameters.setX5ChainHeaderPlacement(CBAdESSignatureParameters.X5ChainHeaderPlacement.unprotectedHeader);
            LOG.debug("'x5chain' shall be placed within the unsigned header map. The value was set to 'unprotectedHeader'.");

        } else if (CBAdESSignatureParameters.X5ChainHeaderPlacement.unprotectedHeader != signatureParameters.getX5ChainHeaderPlacement()) {
            throw new IllegalArgumentException(String.format("'x5chain' shall be placed within the unsigned header map! " +
                    "Obtained value : '%s'", signatureParameters.getX5ChainHeaderPlacement()));
        }

        if (EncryptionAlgorithm.ECDSA != signatureParameters.getEncryptionAlgorithm() &&
                EncryptionAlgorithm.EDDSA != signatureParameters.getEncryptionAlgorithm()) {
            throw new IllegalArgumentException(String.format("MSO shall be signed by ECDSA or EDDSA algortihm! " +
                    "Obtained value : '%s'", signatureParameters.getEncryptionAlgorithm()));
        }

    }

    /**
     * This method ensures compliance of the used digest algorithm for signing-certificate signed attribute definition
     *
     * @param signatureParameters {@link CBAdESSignatureParameters}
     */
    protected void ensureSigningCertificateDigestAlgorithm(final CBAdESSignatureParameters signatureParameters) {
        // TODO : remove the method should the ETSI TS 119 472-1 be updated
        if (DigestAlgorithm.SHA256 != signatureParameters.getSigningCertificateDigestMethod()) {
            LOG.info("ETSI TS 119 472-1 v1.2.1 requires SHA256 to be used for the signing-certificate signed attribute definition. " +
                    "The value is enforced to DigestAlgorithm.SHA256. Should you need to use a different algorithm, " +
                    "please override the MdocEAAService#ensureSigningCertificateDigestAlgorithm method.");
            signatureParameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
        }
    }

    /**
     * This method verifies validity and/or provides some mandatory payload parameters for EAA creation
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @param signatureParameters {@link CBAdESSignatureParameters}
     */
    protected void ensurePayloadParameters(final MdocPayloadParameters payloadParameters, final CBAdESSignatureParameters signatureParameters) {
        if (payloadParameters.getSigned() == null) {
            payloadParameters.setSigned(signatureParameters.bLevel().getSigningDate());
            LOG.debug("EAA 'signed' date is absent and was set to {}", signatureParameters.bLevel().getSigningDate());
        }
        if (payloadParameters.getValidFrom() == null) {
            payloadParameters.setValidFrom(signatureParameters.bLevel().getSigningDate());
            LOG.debug("EAA 'validFrom' date is absent and was set to {}", signatureParameters.bLevel().getSigningDate());
        }
        if (payloadParameters.getValidUntil() == null && signatureParameters.getSigningCertificate() != null) {
            payloadParameters.setValidUntil(signatureParameters.getSigningCertificate().getNotAfter());
            LOG.debug("EAA 'validUntil' date is absent and was set to {}", signatureParameters.getSigningCertificate().getNotAfter());
        }
        if (payloadParameters.getDocType() == null) {
            String docType = computeDocType(payloadParameters);
            payloadParameters.setDocType(docType);
            LOG.debug("EAA 'docType' is absent and was set to {}", docType);
        }
    }

    /**
     * Derives the docType based on the provided payload parameters.
     * This method iterates over the provided claims and tries to find the best matching document type.
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link String} docType
     */
    protected String computeDocType(final MdocPayloadParameters payloadParameters) {
        MdocClaimParameters selectivelyDisclosable = payloadParameters.selectivelyDisclosable();
        if (Utils.isCollectionNotEmpty(selectivelyDisclosable.getDrivingPrivileges())) {
            return MdocConstants.ISO18013_5_MDL_DOC_TYPE;
        }
        if (Utils.isCollectionNotEmpty(selectivelyDisclosable.getOtherClaims())) {
            Set<String> namespaceSet = selectivelyDisclosable.getOtherClaims().stream()
                    .map(MdocClaim::getNamespace).collect(Collectors.toSet());
            if (namespaceSet.contains(MdocConstants.EUDI_PID_NAMESPACE)) {
                return MdocConstants.EUDI_PID_DOC_TYPE;
            } else if (namespaceSet.contains(MdocConstants.ISO23220_1_NAMESPACE)) {
                return MdocConstants.ISO23220_1_MID_DOC_TYPE;
            } else if (namespaceSet.contains(MdocConstants.ISO18013_5_NAMESPACE)) {
                return MdocConstants.ISO18013_5_MDL_DOC_TYPE;
            }
        }
        // TODO : processing of other claims is not yet implemented
        return MdocConstants.ISO23220_1_MID_DOC_TYPE; // default
    }

    /**
     * This method verifies validity of the payload
     *
     * @param payload {@link DSSDocument} to be verified
     */
    protected void validatePayload(final DSSDocument payload) {
        Objects.requireNonNull(payload, "payload cannot be null!");
        if (!CBORUtils.isCbor(payload)) {
            throw new IllegalInputException("Payload is not a CBOR document!");
        }
    }

    @Override
    public ToBeSigned getDataToSignForKeyBindingSignature(final DSSDocument eaa, final MdocKeyBindingParameters keyBindingParameters,
                                                          final CBAdESSignatureParameters signatureParameters) {
        return getDataToSignForKeyBindingSignature(eaa, null, keyBindingParameters, signatureParameters);
    }

    @Override
    public ToBeSigned getDataToSignForKeyBindingSignature(final DSSDocument eaa, final List<MdocSelectiveDisclosure> disclosures, final MdocKeyBindingParameters keyBindingParameters,
                                                          final CBAdESSignatureParameters signatureParameters) {
        ensureKeyBindingSignatureParameters(signatureParameters);
        DSSDocument deviceAuthentication = getMdocEAAPresentationBuilder().buildDeviceAuthentication(keyBindingParameters);
        return dataToBeSigned(deviceAuthentication, signatureParameters);
    }

    @Override
    public DSSDocument createKeyBindingSignature(final DSSDocument eaa, final MdocKeyBindingParameters keyBindingParameters, final CBAdESSignatureParameters signatureParameters,
                                                 final SignatureValue signatureValue) {
        return createKeyBindingSignature(eaa, null, keyBindingParameters, signatureParameters, signatureValue);
    }

    @Override
    public DSSDocument createKeyBindingSignature(final DSSDocument eaa, final List<MdocSelectiveDisclosure> disclosures, final MdocKeyBindingParameters keyBindingParameters,
                                                 final CBAdESSignatureParameters signatureParameters, final SignatureValue signatureValue) {
        ensureKeyBindingSignatureParameters(signatureParameters);
        DSSDocument deviceAuthentication = getMdocEAAPresentationBuilder().buildDeviceAuthentication(keyBindingParameters);
        return getCBAdESService().signDocument(deviceAuthentication, signatureParameters, signatureValue);
    }

    /**
     * This method verifies the validity of the key binding signature parameters
     *
     * @param signatureParameters {@link CBAdESSignatureParameters}
     */
    protected void ensureKeyBindingSignatureParameters(final CBAdESSignatureParameters signatureParameters) {
        Objects.requireNonNull(signatureParameters, "signatureParameters cannot be null!");

        if (signatureParameters.getSignatureLevel() == null) {
            signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
            LOG.debug("SignatureLevel is absent and was set to '{}'", SignatureLevel.CB_AdES_BASELINE_B);

        } else if (SignatureLevel.CB_AdES_BASELINE_B != signatureParameters.getSignatureLevel()) {
            throw new IllegalArgumentException("Signature level must be CB-AdES-BASELINE-B!");
        }

        if (signatureParameters.getSignaturePackaging() == null) {
            signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            LOG.debug("SignaturePackaging is absent and was set to '{}'", SignaturePackaging.DETACHED);

        } else if (SignaturePackaging.DETACHED != signatureParameters.getSignaturePackaging()) {
            throw new IllegalArgumentException("Signature packaging must be DETACHED!");
        }

        if (signatureParameters.getSigDMechanism() == null) {
            signatureParameters.setSigDMechanism(SigDMechanism.NO_SIG_D);
            LOG.debug("SigDMechanism is absent and was set to '{}'", SigDMechanism.NO_SIG_D);

        } else if (SigDMechanism.NO_SIG_D != signatureParameters.getSigDMechanism()) {
            throw new IllegalArgumentException("SigDMechanism must be NO_SIG_D!");
        }

        if (COSEStructureType.COSE_SIGN1 != signatureParameters.getCoseStructureType()) {
            signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
            LOG.debug("COSEStructureType was set to '{}'", COSEStructureType.COSE_SIGN1);
        }

        if (signatureParameters.isTagged() == null) {
            signatureParameters.setTagged(false);
            LOG.debug("COSE_Sign1 structure shall be untagged for mdoc signature. The value was set to 'false'.");
        } else if (Utils.isTrue(signatureParameters.isTagged())) {
            throw new IllegalArgumentException("COSE_Sign1 structure shall be untagged!");
        }

        if (signatureParameters.isIncludeCertificateChain()) {
            signatureParameters.setIncludeCertificateChain(false);
            LOG.debug("IncludeCertificateChain shall not be 'true'. The value was set to 'false'.");
        }

        if (EncryptionAlgorithm.ECDSA != signatureParameters.getEncryptionAlgorithm() &&
                EncryptionAlgorithm.EDDSA != signatureParameters.getEncryptionAlgorithm()) {
            throw new IllegalArgumentException(String.format("DeviceAuthentication shall be signed by ECDSA or EDDSA algortihm! " +
                    "Obtained value : '%s'", signatureParameters.getEncryptionAlgorithm()));
        }
    }

    @Override
    public List<MdocSelectiveDisclosure> getDisclosures(final MdocPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters, "MdocEAAPayloadParameters cannot be null!");
        Objects.requireNonNull(payloadParameters.getSigned(), "Signed date cannot be null!");
        Objects.requireNonNull(payloadParameters.getValidFrom(), "ValidFrom date cannot be null!");
        Objects.requireNonNull(payloadParameters.getValidUntil(), "ValidUntil date cannot be null!");
        Objects.requireNonNull(payloadParameters.getDocType(), "DocType cannot be null!");
        return getPayloadBuilder().buildDisclosures(payloadParameters);
    }

    /**
     * Creates IssuerSigned structure, incorporating the signed EAA and provided selectively disclosable claims.
     * For an Attestation Presentation (DeviceResponse structure for the mdoc), please use one of the {@code #issuePresentation} methods.
     *
     * @param eaa {@link DSSDocument} containing the signed EAA
     * @param disclosures a list of {@link MdocSelectiveDisclosure}s to be incorporated within the namespaces
     * @return {@link DSSDocument}
     */
    public DSSDocument createIssuerSigned(DSSDocument eaa, List<MdocSelectiveDisclosure> disclosures) {
        DSSDocument issuerSigned = getMdocEAAPresentationBuilder().buildIssuerSignedDocument(eaa, disclosures);
        issuerSigned.setName(getFinalDocumentName(eaa));
        issuerSigned.setMimeType(getEAAPresentationMimeType());
        return issuerSigned;
    }

    @Override
    public DSSDocument issuePresentation(DSSDocument eaa, List<MdocSelectiveDisclosure> disclosures) {
        throw new UnsupportedOperationException("#issuePresentation(DSSDocument attestation, List<MdocEAADisclosure> disclosures) method is not supported for the MdocService. " +
                "Please provide a key binding signature or use the method #issuerSigned(DSSDocument attestation, List<MdocEAADisclosure> disclosures) instead.");
    }

    @Override
    public DSSDocument issuePresentation(DSSDocument eaa, DSSDocument keyBinding) {
        return issuePresentation(eaa, null, keyBinding);
    }

    @Override
    public DSSDocument issuePresentation(DSSDocument eaa, List<MdocSelectiveDisclosure> disclosures, DSSDocument keyBinding) {
        return issuePresentation(eaa, disclosures, keyBinding, new MdocKeyBindingParameters());
    }

    /**
     * Creates an Attestation Presentation, with provided selective disclosures, key binding signature and
     * a list of device signed data elements
     *
     * @param eaa
     *            {@link DSSDocument} representing a signed EAA
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be provided with the EAA presentation
     * @param keyBinding
     *            {@link DSSDocument} representing a key binding signature
     * @param deviceSignedParameters
     *             {@link MdocDeviceSignedParameters} contains a list of device signed data elements
     * @return {@link DSSDocument} Attestation Presentation
     */
    public DSSDocument issuePresentation(DSSDocument eaa, List<MdocSelectiveDisclosure> disclosures, DSSDocument keyBinding, MdocDeviceSignedParameters deviceSignedParameters) {
        Objects.requireNonNull(deviceSignedParameters, "deviceSignedParameters must not be null!");
        if (!CBORUtils.isCbor(eaa)) {
            throw new DSSException("The attestation should be a cbor document!");
        }
        if (!CBORUtils.isCbor(keyBinding)) {
            throw new DSSException("The keyBinding should be a cbor document!");
        }

        DSSDocument deviceResponseDocument = getMdocEAAPresentationBuilder()
                .buildDeviceResponseDocument(eaa, disclosures, keyBinding, deviceSignedParameters);
        deviceResponseDocument.setName(getFinalDocumentName(eaa));
        deviceResponseDocument.setMimeType(getEAAPresentationMimeType());
        return deviceResponseDocument;
    }

    protected MdocPresentationBuilder getMdocEAAPresentationBuilder() {
        return new MdocPresentationBuilder();
    }

    /**
     * Gets service to be used for a CB-AdES signature creation
     *
     * @return {@link CBAdESService}
     */
    protected CBAdESService getCBAdESService() {
        return new CBAdESService(certificateVerifier);
    }

    @Override
    protected AttestationPayloadBuilder<MdocPayloadParameters, MdocSelectiveDisclosure> initDefaultPayloadBuilder() {
        return new MdocPayloadBuilder();
    }

    @Override
    protected MimeType getEAAPresentationMimeType() {
        return MimeTypeEnum.CBOR;
    }
}
