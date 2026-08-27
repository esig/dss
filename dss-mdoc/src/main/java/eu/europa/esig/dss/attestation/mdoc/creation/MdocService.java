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

import eu.europa.esig.dss.attestation.common.creation.AbstractAttestationSDService;
import eu.europa.esig.dss.attestation.common.creation.AttestationPresentationService;
import eu.europa.esig.dss.attestation.mdoc.IssuerSignedParser;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.MdocUtils;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
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
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service providing the complete lifecycle for ISO/IEC 18013-5 mdoc
 * attestations and presentations.
 * <p>
 * This class combines both issuer-side and holder-side operations for the
 * ISO/IEC 18013-5 mdoc format:
 * <ul>
 *   <li><b>Attestation Issuers</b> (e.g. EAA, PID providers), to create and sign
 *       mdoc attestations and issue them with selectively disclosable issuer-signed items.</li>
 *   <li><b>Wallets (holders)</b>, to parse issued mdocs, create holder
 *       key-binding signatures when required, and generate mdoc presentations.</li>
 * </ul>
 * Applications acting exclusively as issuers or
 * wallets typically invoke only the subset of methods relevant to their role.
 * <p>
 * <b>Attestation issuer workflow:</b>
 * <ol>
 *   <li>Create an {@link MdocPayloadParameters} instance describing the
 *       attestation claims.</li>
 *   <li>Generate the format-specific Data To Be Signed (DTBS) using
 *       {@link #getDataToSign(MdocPayloadParameters, CBAdESSignatureParameters)}
 *       (or {@link #getDataToSign(DSSDocument, CBAdESSignatureParameters)}
 *       if the payload has already been created).</li>
 *   <li>Compute the signature based on DTBS using an external signing component,
 *       such as an HSM, remote signing service, or cryptographic token.</li>
 *   <li>Create the signed mdoc using {@link #signAttestation(MdocPayloadParameters,
 *       CBAdESSignatureParameters, SignatureValue)}.</li>
 *   <li>Issue the final attestation by calling one of:
 *       <ul>
 *         <li>{@link #issueAttestation(DSSDocument)} to issue only the signed
 *             attestation;</li>
 *         <li>{@link #issueAttestation(DSSDocument, MdocPayloadParameters)}
 *             to automatically generate and attach all issuer-signed items;</li>
 *         <li>{@link #issueAttestation(DSSDocument, List)} to attach a custom
 *             set of issuer-signed items.</li>
 *       </ul>
 *   </li>
 * </ol>
 * <p>
 * <b>Wallet workflow:</b>
 * <ol>
 *   <li>Parse the received mdoc using {@link #parseAttestation(DSSDocument)}}.</li>
 *   <li>Select the issuer-signed items to disclose.</li>
 *   <li>Create the DTBS for the holder key-binding signature using
 *       {@link #getDataToSignForKeyBindingSignature(DSSDocument, List,
 *       MdocKeyBindingParameters, CBAdESSignatureParameters)} (or the overload without disclosures).</li>
 *   <li>Compute the signature based on DTBS using a device's or holder's key.</li>
 *   <li>Create the key-binding signature document using
 *       {@link #createKeyBindingSignature(DSSDocument, List,
 *       MdocKeyBindingParameters, CBAdESSignatureParameters,
 *       SignatureValue)} (or the overload without disclosures).</li>
 *   <li>Create the final presentation by calling one of:
 *       <ul>
 *         <li>{@link #issuePresentation(DSSDocument, DSSDocument)} to include
 *             only a key-binding signature;</li>
 *         <li>{@link #issuePresentation(DSSDocument, List, DSSDocument)} to
 *             include both selected issuer-signed items and a key-binding
 *             signature.</li>
 *       </ul>
 *   </li>
 * </ol>
 *
 */
public class MdocService extends AbstractAttestationSDService<CBAdESSignatureParameters, MdocPayloadParameters, MdocIssuerSignedItem>
        implements AttestationPresentationService<CBAdESSignatureParameters, MdocIssuerSignedItem, MdocKeyBindingParameters> {

    private static final long serialVersionUID = 6514504397480840459L;

    private static final Logger LOG = LoggerFactory.getLogger(MdocService.class);

    /**
     * Default constructor to instantiate an {@code SDJWTService}
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    public MdocService(final CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
        LOG.debug("+ MdocService created");
    }

    @Override
    public ToBeSigned getDataToSign(DSSDocument payload, CBAdESSignatureParameters signatureParameters) {
        validatePayload(payload);
        ensureSignatureParameters(signatureParameters);
        return dataToBeSigned(payload, signatureParameters);
    }

    @Override
    public ToBeSigned getDataToSign(MdocPayloadParameters payloadParameters, CBAdESSignatureParameters signatureParameters) {
        Objects.requireNonNull(payloadParameters, "MdocPayloadParameters cannot be null!");
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
    public DSSDocument signAttestation(DSSDocument payload, CBAdESSignatureParameters signatureParameters, SignatureValue signatureValue) {
        validatePayload(payload);
        ensureSignatureParameters(signatureParameters);
        return signDocument(payload, signatureParameters, signatureValue);
    }

    @Override
    public DSSDocument signAttestation(MdocPayloadParameters payloadParameters, CBAdESSignatureParameters signatureParameters, SignatureValue signatureValue) {
        Objects.requireNonNull(payloadParameters, "MdocPayloadParameters cannot be null!");
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
            throw new IllegalArgumentException("Certificate chain must be included within the mdoc attestation signature!");
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
            throw new IllegalArgumentException(String.format("MSO shall be signed by ECDSA or EDDSA algorithm! " +
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
                    "please override the MdocService#ensureSigningCertificateDigestAlgorithm method.");
            signatureParameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
        }
    }

    /**
     * This method verifies validity and/or provides some mandatory payload parameters for attestation creation
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @param signatureParameters {@link CBAdESSignatureParameters}
     */
    protected void ensurePayloadParameters(final MdocPayloadParameters payloadParameters, final CBAdESSignatureParameters signatureParameters) {
        if (payloadParameters.getSigned() == null) {
            payloadParameters.setSigned(signatureParameters.bLevel().getSigningDate());
            LOG.debug("Attestation 'signed' date is absent and was set to {}", signatureParameters.bLevel().getSigningDate());
        }
        if (payloadParameters.getValidFrom() == null) {
            payloadParameters.setValidFrom(signatureParameters.bLevel().getSigningDate());
            LOG.debug("Attestation 'validFrom' date is absent and was set to {}", signatureParameters.bLevel().getSigningDate());
        }
        if (payloadParameters.getValidUntil() == null && signatureParameters.getSigningCertificate() != null) {
            payloadParameters.setValidUntil(signatureParameters.getSigningCertificate().getNotAfter());
            LOG.debug("Attestation 'validUntil' date is absent and was set to {}", signatureParameters.getSigningCertificate().getNotAfter());
        }
        if (payloadParameters.getDocType() == null) {
            String docType = computeDocType(payloadParameters);
            payloadParameters.setDocType(docType);
            LOG.debug("Attestation 'docType' is absent and was set to {}", docType);
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
    public List<MdocIssuerSignedItem> generateDisclosures(final MdocPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters, "MdocPayloadParameters cannot be null!");
        return getPayloadBuilder().buildDisclosures(payloadParameters);
    }

    @Override
    public DSSDocument issueAttestation(DSSDocument signedAttestation) {
        return issueAttestation(signedAttestation, Collections.emptyList());
    }

    @Override
    public DSSDocument issueAttestation(DSSDocument signedAttestation, MdocPayloadParameters payloadParameters) {
        return issueAttestation(signedAttestation, generateDisclosures(payloadParameters));
    }

    @Override
    public DSSDocument issueAttestation(DSSDocument signedAttestation, List<MdocIssuerSignedItem> disclosures) {
        return createIssuerSigned(signedAttestation, disclosures);
    }

    /**
     * Creates IssuerSigned structure, incorporating the signed attestation and provided selectively disclosable claims.
     * For an Attestation Presentation (DeviceResponse structure for the mdoc), please use one of the {@code #issuePresentation} methods.
     *
     * @param attestation {@link DSSDocument} containing the signed attestation
     * @param disclosures a list of {@link MdocIssuerSignedItem}s to be incorporated within the namespaces
     * @return {@link DSSDocument}
     */
    protected DSSDocument createIssuerSigned(DSSDocument attestation, List<MdocIssuerSignedItem> disclosures) {
        Objects.requireNonNull(attestation, "The attestation cannot be null!");

        DSSDocument issuerSigned = getMdocPresentationBuilder().buildIssuerSignedDocument(attestation, disclosures);
        issuerSigned.setName(getFinalAttestationDocumentName(attestation));
        issuerSigned.setMimeType(getAttestationMimeType());
        return issuerSigned;
    }

    @Override
    public MdocIssuerSignedDocument parseAttestation(DSSDocument attestation) {
        Objects.requireNonNull(attestation, "The attestation cannot be null!");

        IssuerSignedParser issuerSignedParser = new IssuerSignedParser(attestation);
        if (issuerSignedParser.isSupported()) {
            MdocIssuerSigned issuerSigned = issuerSignedParser.parse();
            DSSDocument attestationSignature = new InMemoryDocument(issuerSigned.getIssuerAuth().serialize(), attestation.getName());
            List<MdocIssuerSignedItem> selectiveDisclosures = MdocUtils.getSelectiveDisclosures(issuerSigned.getNamespaces());
            MdocIssuerSignedDocument issuerSignedDocument = new MdocIssuerSignedDocument(
                    attestation, attestationSignature, selectiveDisclosures);
            issuerSignedDocument.setName(attestation.getName());
            return issuerSignedDocument;
        }
        throw new IllegalInputException("An instance of IssuerSigned is expected!");
    }

    @Override
    public ToBeSigned getDataToSignForKeyBindingSignature(final DSSDocument attestation, final MdocKeyBindingParameters keyBindingParameters,
                                                          final CBAdESSignatureParameters signatureParameters) {
        return getDataToSignForKeyBindingSignature(attestation, null, keyBindingParameters, signatureParameters);
    }

    @Override
    public ToBeSigned getDataToSignForKeyBindingSignature(final DSSDocument attestation, final List<MdocIssuerSignedItem> disclosures, final MdocKeyBindingParameters keyBindingParameters,
                                                          final CBAdESSignatureParameters signatureParameters) {
        ensureKeyBindingSignatureParameters(signatureParameters);
        DSSDocument deviceAuthentication = getMdocPresentationBuilder().buildDeviceAuthentication(keyBindingParameters);
        return dataToBeSigned(deviceAuthentication, signatureParameters);
    }

    @Override
    public DSSDocument createKeyBindingSignature(final DSSDocument attestation, final MdocKeyBindingParameters keyBindingParameters, final CBAdESSignatureParameters signatureParameters,
                                                 final SignatureValue signatureValue) {
        return createKeyBindingSignature(attestation, null, keyBindingParameters, signatureParameters, signatureValue);
    }

    @Override
    public DSSDocument createKeyBindingSignature(final DSSDocument attestation, final List<MdocIssuerSignedItem> disclosures, final MdocKeyBindingParameters keyBindingParameters,
                                                 final CBAdESSignatureParameters signatureParameters, final SignatureValue signatureValue) {
        ensureKeyBindingSignatureParameters(signatureParameters);
        DSSDocument deviceAuthentication = getMdocPresentationBuilder().buildDeviceAuthentication(keyBindingParameters);
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
            throw new IllegalArgumentException(String.format("DeviceAuthentication shall be signed by ECDSA or EDDSA algorithm! " +
                    "Obtained value : '%s'", signatureParameters.getEncryptionAlgorithm()));
        }
    }

    @Override
    public DSSDocument issuePresentation(DSSDocument attestation, List<MdocIssuerSignedItem> disclosures) {
        throw new UnsupportedOperationException("#issuePresentation(DSSDocument attestation, List<MdocDisclosure> disclosures) method is not supported for the MdocService. " +
                "Please provide a key binding signature or use the method #issuerSigned(DSSDocument attestation, List<MdocDisclosure> disclosures) instead.");
    }

    @Override
    public DSSDocument issuePresentation(DSSDocument attestation, DSSDocument keyBinding) {
        return issuePresentation(attestation, Collections.emptyList(), keyBinding);
    }

    @Override
    public DSSDocument issuePresentation(DSSDocument attestation, List<MdocIssuerSignedItem> disclosures, DSSDocument keyBinding) {
        return issuePresentation(attestation, disclosures, keyBinding, new MdocKeyBindingParameters());
    }

    /**
     * Creates an Attestation Presentation, with provided selective disclosures, key binding signature and
     * a list of device signed data elements
     *
     * @param attestation
     *            {@link DSSDocument} representing a signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be provided with the attestation presentation
     * @param keyBinding
     *            {@link DSSDocument} representing a key binding signature
     * @param deviceSignedParameters
     *             {@link MdocDeviceSignedParameters} contains a list of device signed data elements
     * @return {@link DSSDocument} Attestation Presentation
     */
    public DSSDocument issuePresentation(DSSDocument attestation, List<MdocIssuerSignedItem> disclosures, DSSDocument keyBinding, MdocDeviceSignedParameters deviceSignedParameters) {
        Objects.requireNonNull(deviceSignedParameters, "deviceSignedParameters must not be null!");
        if (!CBORUtils.isCbor(attestation)) {
            throw new DSSException("The attestation should be a cbor document!");
        }
        if (!CBORUtils.isCbor(keyBinding)) {
            throw new DSSException("The keyBinding should be a cbor document!");
        }

        DSSDocument deviceResponseDocument = getMdocPresentationBuilder()
                .buildDeviceResponseDocument(attestation, disclosures, keyBinding, deviceSignedParameters);
        deviceResponseDocument.setName(getFinalAttestationPresentationDocumentName(attestation));
        deviceResponseDocument.setMimeType(getAttestationMimeType());
        return deviceResponseDocument;
    }

    /**
     * Gets the mdoc presentation builder
     *
     * @return {@link MdocPresentationBuilder}
     */
    protected MdocPresentationBuilder getMdocPresentationBuilder() {
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
    protected MdocPayloadBuilder initDefaultPayloadBuilder() {
        return new MdocPayloadBuilder();
    }

    @Override
    protected MimeType getAttestationMimeType() {
        return MimeTypeEnum.CBOR;
    }
}
