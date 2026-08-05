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
package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.attestation.common.creation.AbstractAttestationSDService;
import eu.europa.esig.dss.attestation.common.creation.AttestationPresentationService;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTSerializationObject;
import eu.europa.esig.dss.attestation.sd.jwt.validation.SDJWTDocumentAnalyzerFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Service providing the complete lifecycle for SD-JWT attestations and
 * presentations.
 * <p>
 * This class combines both issuer-side and holder-side operations for the
 * SD-JWT format.
 * <ul>
 *   <li><b>Attestation issuers</b>, to create, sign, and issue SD-JWT
 *       credentials with selective disclosures.</li>
 *   <li><b>Wallets (holders)</b>, to parse issued credentials, select
 *       disclosures, optionally create a holder key-binding JWT, and generate
 *       SD-JWT presentations for verifiers.</li>
 * </ul>
 * Applications acting exclusively as issuers or wallets
 * typically invoke only the subset of methods relevant to their role.
 * <p>
 * <b>Attestation issuer workflow</b>
 * <ol>
 *   <li>Create an {@link SDJWTPayloadParameters} instance describing the
 *       credential claims.</li>
 *   <li>Generate the format-specific Data To Be Signed (DTBS) by calling
 *       {@link #getDataToSign(SDJWTPayloadParameters, JAdESSignatureParameters)}
 *       or {@link #getDataToSign(DSSDocument, JAdESSignatureParameters)}
 *       when using an existing payload.</li>
 *   <li>Compute the signature based on DTBS using an external signing component,
 *       such as an HSM, remote signing service, or cryptographic token.</li>
 *   <li>Create the signed SD-JWT by calling
 *       {@link #signAttestation(SDJWTPayloadParameters,
 *       JAdESSignatureParameters, SignatureValue)} or its overload accepting a
 *       precomputed payload.</li>
 *   <li>Issue the final credential by calling one of:
 *       <ul>
 *         <li>{@link #issueAttestation(DSSDocument)} to issue only the signed
 *             SD-JWT;</li>
 *         <li>{@link #issueAttestation(DSSDocument, SDJWTPayloadParameters)}
 *             to automatically generate and attach all disclosures;</li>
 *         <li>{@link #issueAttestation(DSSDocument, List)} to attach a custom
 *             set of disclosures.</li>
 *       </ul>
 *   </li>
 * </ol>
 * <p>
 * <b>Wallet workflow</b>
 * <ol>
 *   <li>Parse the received credential using
 *       {@link #parseAttestation(DSSDocument)}}.</li>
 *   <li>Select the disclosures to include in the presentation.</li>
 *   <li>Create the DTBS for the holder key-binding JWT using
 *       {@link #getDataToSignForKeyBindingSignature(DSSDocument, List, SDJWTKeyBindingParameters,
 *       JAdESSignatureParameters)} (or the overload without disclosures).</li>
 *   <li>Compute the signature based on DTBS using a device's or holder's key.</li>
 *   <li>Create the key-binding JWT using {@link #createKeyBindingSignature(DSSDocument,
 *       List, SDJWTKeyBindingParameters, JAdESSignatureParameters, SignatureValue)}
 *       (or the overload without disclosures).</li>
 *   <li>Create the final presentation by calling one of:
 *       <ul>
 *         <li>{@link #issuePresentation(DSSDocument, List)} to include only
 *             the selected disclosures;</li>
 *         <li>{@link #issuePresentation(DSSDocument, DSSDocument)} to include
 *             only the key-binding JWT;</li>
 *         <li>{@link #issuePresentation(DSSDocument, List, DSSDocument)} to
 *             include both selected disclosures and the key-binding JWT.</li>
 *       </ul>
 *   </li>
 * </ol>
 *
 * <p>
 */
public class SDJWTService extends AbstractAttestationSDService<JAdESSignatureParameters, SDJWTPayloadParameters, SDJWTSelectiveDisclosure>
        implements AttestationPresentationService<JAdESSignatureParameters, SDJWTSelectiveDisclosure, SDJWTKeyBindingParameters> {

    private static final long serialVersionUID = 6514504397480840459L;

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTService.class);

    /**
     * Default constructor to instantiate an {@code SDJWTService}
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    public SDJWTService(final CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
        LOG.debug("+ SDJWTService created");
    }

    @Override
    public ToBeSigned getDataToSign(final DSSDocument payload, final JAdESSignatureParameters signatureParameters) {
        validatePayload(payload);
        ensureSignatureParameters(signatureParameters);
        return getJAdESService().getDataToSign(payload, signatureParameters);
    }

    @Override
    public ToBeSigned getDataToSign(final SDJWTPayloadParameters payloadParameters, final JAdESSignatureParameters signatureParameters) {
        ensureSignatureParameters(signatureParameters);
        ensurePayloadParameters(payloadParameters, signatureParameters);
        return getDataToSign(getPayloadBuilder().buildPayload(payloadParameters), signatureParameters);
    }

    @Override
    public DSSDocument signAttestation(final DSSDocument payload, final JAdESSignatureParameters signatureParameters, final SignatureValue signatureValue) {
        validatePayload(payload);
        ensureSignatureParameters(signatureParameters);
        return getJAdESService().signDocument(payload, signatureParameters, signatureValue);
    }

    @Override
    public DSSDocument signAttestation(final SDJWTPayloadParameters payloadParameters, final JAdESSignatureParameters signatureParameters, final SignatureValue signatureValue) {
        ensureSignatureParameters(signatureParameters);
        ensurePayloadParameters(payloadParameters, signatureParameters);
        return signAttestation(getPayloadBuilder().buildPayload(payloadParameters), signatureParameters, signatureValue);
    }

    /**
     * This method verifies validity of the payload
     *
     * @param payload {@link DSSDocument} to be verified
     */
    protected void validatePayload(final DSSDocument payload) {
        Objects.requireNonNull(payload, "payload cannot be null!");

        if (!DSSJsonUtils.isJsonDocument(payload)) {
            throw new DSSException("Payload is not a JSON document!");
        }
    }

    /**
     * This method verifies validity of the signature parameters and provides the necessary configuration, where applicable
     *
     * @param signatureParameters {@link JAdESSignatureParameters}
     */
    protected void ensureSignatureParameters(final JAdESSignatureParameters signatureParameters) {
        Objects.requireNonNull(signatureParameters, "signatureParameters cannot be null!");

        if (signatureParameters.getSignatureLevel() == null) {
            signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
            LOG.debug("SignatureLevel is absent and was set to '{}'", SignatureLevel.JAdES_BASELINE_B);

        } else if (SignatureLevel.JAdES_BASELINE_B != signatureParameters.getSignatureLevel()) {
            throw new IllegalArgumentException("Signature level must be JAdES-BASELINE-B!");
        }

        if (signatureParameters.getSignaturePackaging() == null) {
            signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            LOG.debug("SignaturePackaging is absent and was set to '{}'", SignaturePackaging.ENVELOPING);

        } else if (SignaturePackaging.ENVELOPING != signatureParameters.getSignaturePackaging()) {
            throw new IllegalArgumentException("Signature packaging must be ENVELOPING");
        }

        if (signatureParameters.getSignatureType() == null) {
            signatureParameters.setSignatureType(MimeTypeEnum.SD_JWT_VC.getMimeTypeString());
            LOG.debug("SignatureType is absent and was set to '{}'", MimeTypeEnum.SD_JWT_VC.getMimeTypeString());
        }

        ensureSigningCertificateDigestAlgorithm(signatureParameters);
    }

    /**
     * This method ensures compliance of the used digest algorithm for signing-certificate signed attribute definition
     *
     * @param signatureParameters {@link JAdESSignatureParameters}
     */
    protected void ensureSigningCertificateDigestAlgorithm(final JAdESSignatureParameters signatureParameters) {
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
     * @param payloadParameters {@link SDJWTPayloadParameters}
     * @param signatureParameters {@link JAdESSignatureParameters}
     */
    protected void ensurePayloadParameters(final SDJWTPayloadParameters payloadParameters, final JAdESSignatureParameters signatureParameters) {
        if (payloadParameters.getNotBeforeDate() == null) {
            payloadParameters.setNotBeforeDate(signatureParameters.bLevel().getSigningDate());
            LOG.debug("Attestation 'nbf' date is absent and was set to {}", signatureParameters.bLevel().getSigningDate());
        }
        if (payloadParameters.getExpirationDate() == null && signatureParameters.getSigningCertificate() != null) {
            payloadParameters.setExpirationDate(signatureParameters.getSigningCertificate().getNotAfter());
            LOG.debug("Attestation 'exp' date is absent and was set to {}", signatureParameters.getSigningCertificate().getNotAfter());
        }
        if (Utils.isStringBlank(payloadParameters.getVerifiableCredentialsType())) {
            LOG.warn("Attestation 'vct' claim shall be defined! Absence of the value may lead to interoperability issued. " +
                    "Please use SDJWTPayloadParameters#setVerifiableCredentialsType method to provide the value.");
        }
        if (payloadParameters.getVerifiableCredentialsTypeIntegrity() == null) {
            LOG.warn("Attestation 'vct#integrity' claim shall be defined! Absence of the value may lead to interoperability issued. " +
                    "Please use SDJWTPayloadParameters#setVerifiableCredentialsTypeIntegrity method to provide the value.");
        }
    }

    @Override
    public List<SDJWTSelectiveDisclosure> generateDisclosures(final SDJWTPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters, "SDJWTPayloadParameters cannot be null!");
        return getPayloadBuilder().buildDisclosures(payloadParameters);
    }

    @Override
    public DSSDocument issueAttestation(DSSDocument signedAttestation) {
        return issueAttestation(signedAttestation, Collections.emptyList());
    }

    @Override
    public DSSDocument issueAttestation(DSSDocument signedAttestation, SDJWTPayloadParameters payloadParameters) {
        return issueAttestation(signedAttestation, generateDisclosures(payloadParameters));
    }

    @Override
    public DSSDocument issueAttestation(DSSDocument signedAttestation, List<SDJWTSelectiveDisclosure> disclosures) {
        // NOTE: in SD-JWT an attestation with SD is equivalent to SD-JWT presentation with SD, but no KB
        DSSDocument attestationDocument = issuePresentation(signedAttestation, disclosures);
        attestationDocument.setName(getFinalAttestationDocumentName(signedAttestation));
        return attestationDocument;
    }

    @Override
    public SDJWTAttestationDocument parseAttestation(DSSDocument attestation) {
        Objects.requireNonNull(attestation, "The attestation cannot be null!");

        SDJWTDocumentAnalyzerFactory factory = new SDJWTDocumentAnalyzerFactory();
        if (factory.isSupported(attestation)) {
            SDJWTSerializationObject sdjwtSerializationObject = factory.create(attestation).buildSDJWTSerializationObject();
            DSSDocument attestationSignature = getAttestationSignature(sdjwtSerializationObject);
            attestationSignature.setName(attestation.getName());

            SDJWTAttestationDocument attestationDocument = new SDJWTAttestationDocument(
                    attestation, attestationSignature, sdjwtSerializationObject.getDisclosures());
            attestationDocument.setName(attestation.getName());
            return attestationDocument;

        } else {
            throw new IllegalInputException("The provided document is not SD-JWT attestation!");
        }
    }

    /**
     * Serializes {@code sdjwtSerializationObject} into a DSSDocument
     *
     * @param sdjwtSerializationObject {@link SDJWTSerializationObject}
     * @return {@link DSSDocument}
     */
    protected DSSDocument getAttestationSignature(SDJWTSerializationObject sdjwtSerializationObject) {
        JWSJsonSerializationObject signature = sdjwtSerializationObject.getSignature();
        if (signature == null) {
            throw new IllegalInputException("The provided attestation document does not contain a signature!");
        }
        for (JWS jws : signature.getSignatures()) {
            Map<String, Object> unprotected = jws.getUnprotected();
            if (Utils.isMapNotEmpty(unprotected)) {
                unprotected = new LinkedHashMap<>(unprotected);
                unprotected.remove(SDJWTConstants.DISCLOSURES);
                unprotected.remove(SDJWTConstants.KB_JWT);
                jws.setUnprotected(unprotected);
            }
        }
        final JWSJsonSerializationGenerator jwsGenerator = new JWSJsonSerializationGenerator(
                signature, sdjwtSerializationObject.getJWSSerializationType());
        return jwsGenerator.generate();
    }

    @Override
    public ToBeSigned getDataToSignForKeyBindingSignature(final DSSDocument signedAttestation, final SDJWTKeyBindingParameters keyBindingParameters,
                                                          final JAdESSignatureParameters signatureParameters) {
        return getDataToSignForKeyBindingSignature(signedAttestation, null, keyBindingParameters, signatureParameters);
    }

    @Override
    public ToBeSigned getDataToSignForKeyBindingSignature(final DSSDocument signedAttestation, final List<SDJWTSelectiveDisclosure> disclosures,
                                                          final SDJWTKeyBindingParameters keyBindingParameters, final JAdESSignatureParameters signatureParameters) {
        ensureKeyBindingParameters(keyBindingParameters, signatureParameters);
        ensureKeyBindingSignatureParameters(signatureParameters);

        DSSDocument keyBindingPayload = getKeyBindingPayloadBuilder().buildPayload(signedAttestation, disclosures, keyBindingParameters);
        return getJAdESService().getDataToSign(keyBindingPayload, signatureParameters);
    }

    @Override
    public DSSDocument createKeyBindingSignature(final DSSDocument signedAttestation, final SDJWTKeyBindingParameters keyBindingParameters, final JAdESSignatureParameters signatureParameters,
                                                 final SignatureValue signatureValue) {
        return createKeyBindingSignature(signedAttestation, null, keyBindingParameters, signatureParameters, signatureValue);
    }

    @Override
    public DSSDocument createKeyBindingSignature(final DSSDocument signedAttestation, final List<SDJWTSelectiveDisclosure> disclosures, final SDJWTKeyBindingParameters keyBindingParameters,
                                                 final JAdESSignatureParameters signatureParameters, final SignatureValue signatureValue) {
        ensureKeyBindingParameters(keyBindingParameters, signatureParameters);
        ensureKeyBindingSignatureParameters(signatureParameters);

        DSSDocument keyBindingPayload = getKeyBindingPayloadBuilder().buildPayload(signedAttestation, disclosures, keyBindingParameters);
        return getJAdESService().signDocument(keyBindingPayload, signatureParameters, signatureValue);
    }

    /**
     * This method verifies validity of the parameters for the key binding
     *
     * @param keyBindingParameters {@link SDJWTKeyBindingParameters}
     * @param signatureParameters {@link JAdESSignatureParameters}
     */
    protected void ensureKeyBindingParameters(final SDJWTKeyBindingParameters keyBindingParameters,
                                              final JAdESSignatureParameters signatureParameters) {
        Objects.requireNonNull(keyBindingParameters, "keyBindingParameters must not be null");
        Objects.requireNonNull(keyBindingParameters.getAudience(), "Audience must not be null");
        Objects.requireNonNull(keyBindingParameters.getNonce(), "Nonce must not be null");

        if (keyBindingParameters.getIssuanceTime() == null) {
            keyBindingParameters.setIssuanceTime(signatureParameters.bLevel().getSigningDate());
            LOG.debug("'iat' date is absent within the key binding signature's payload and was set to {}", signatureParameters.bLevel().getSigningDate());
        }
    }

    /**
     * This method verifies validity of the signature parameters for the key binding and provides the necessary configuration, where applicable
     *
     * @param signatureParameters {@link JAdESSignatureParameters}
     */
    protected void ensureKeyBindingSignatureParameters(final JAdESSignatureParameters signatureParameters) {
        Objects.requireNonNull(signatureParameters, "signatureParameters cannot be null!");

        if (signatureParameters.getSignatureLevel() == null) {
            signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
            LOG.debug("SignatureLevel is absent and was set to '{}'", SignatureLevel.JAdES_BASELINE_B);
        } else if (SignatureLevel.JAdES_BASELINE_B != signatureParameters.getSignatureLevel()) {
            throw new DSSException("Signature level must be JAdES_BASELINE_B");
        }

        if (signatureParameters.getSignaturePackaging() == null) {
            signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            LOG.debug("SignaturePackaging is absent and was set to '{}'", SignaturePackaging.ENVELOPING);
        } else if (SignaturePackaging.ENVELOPING != signatureParameters.getSignaturePackaging()) {
            throw new DSSException("Signature packaging must be ENVELOPING");
        }

        if (signatureParameters.getJwsSerializationType() == null) {
            signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
            LOG.debug("JWSSerializationType is absent and was set to '{}'", JWSSerializationType.COMPACT_SERIALIZATION);
        } else if (JWSSerializationType.COMPACT_SERIALIZATION != signatureParameters.getJwsSerializationType()) {
            throw new DSSException("JWS serialization type must be COMPACT_SERIALIZATION");
        }

        if (signatureParameters.getSignatureType() == null) {
            signatureParameters.setSignatureType(MimeTypeEnum.KB_JWT.getMimeTypeString());
            LOG.debug("SignatureType is absent and was set to '{}'", MimeTypeEnum.KB_JWT.getMimeTypeString());
        }
    }

    /**
     * Gets the JAdES service for a signature creation
     *
     * @return {@link JAdESService}
     */
    protected JAdESService getJAdESService() {
        return new JAdESService(certificateVerifier);
    }

    @Override
    protected SDJWTPayloadBuilder initDefaultPayloadBuilder() {
        return new SDJWTPayloadBuilder();
    }

    @Override
    public DSSDocument issuePresentation(final DSSDocument signedAttestation, final List<SDJWTSelectiveDisclosure> disclosures, final DSSDocument keyBinding) {
        Objects.requireNonNull(signedAttestation, "The attestation cannot be null!");
        JWSCompactSerializationParser compactParser = new JWSCompactSerializationParser(signedAttestation);
        if (compactParser.isSupported()) {
            DSSDocument attestationPresentation = issueJWSCompactPresentation(signedAttestation, disclosures, keyBinding);
            attestationPresentation.setName(getFinalAttestationPresentationDocumentName(signedAttestation));
            attestationPresentation.setMimeType(getAttestationMimeType());
            return attestationPresentation;
        }

        JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(signedAttestation);
        if (jwsJsonSerializationParser.isSupported()) {
            DSSDocument attestationPresentation = issueJWSJsonSerializationPresentation(jwsJsonSerializationParser.parse(), disclosures, keyBinding);
            attestationPresentation.setName(getFinalAttestationPresentationDocumentName(signedAttestation));
            attestationPresentation.setMimeType(getAttestationMimeType());
            return attestationPresentation;
        }

        throw new IllegalInputException("The signed attestation must be a JWS Signature");
    }

    @Override
    public DSSDocument issuePresentation(final DSSDocument signedAttestation, final List<SDJWTSelectiveDisclosure> disclosures) {
        return issuePresentation(signedAttestation, disclosures, null);
    }

    @Override
    public DSSDocument issuePresentation(final DSSDocument signedAttestation, final DSSDocument keyBinding) {
        return issuePresentation(signedAttestation, Collections.emptyList(), keyBinding);
    }

    private DSSDocument issueJWSCompactPresentation(final DSSDocument attestation, final List<SDJWTSelectiveDisclosure> disclosures, final DSSDocument keyBinding) {
        String signedAttestation = new String(DSSUtils.toByteArray(attestation));

        StringBuilder issuedAttestation = new StringBuilder(signedAttestation).append("~");
        if (disclosures != null && !disclosures.isEmpty()) {
            for (SDJWTSelectiveDisclosure disclosure : disclosures) {
                issuedAttestation.append(disclosure.getDisclosure()).append("~");
            }
        }

        if (keyBinding != null) {
            String keyBindingValue = new String(DSSUtils.toByteArray(keyBinding));
            issuedAttestation.append(keyBindingValue);
        }

        return new InMemoryDocument(issuedAttestation.toString().getBytes());
    }

    private DSSDocument issueJWSJsonSerializationPresentation(JWSJsonSerializationObject jwsJsonSerializationObject, final List<SDJWTSelectiveDisclosure> disclosures,
                                                              final DSSDocument keyBinding) {
        if (jwsJsonSerializationObject.getSignatures().size() != 1) {
            throw new DSSException("The signed attestation can only contain one signature");
        }

        JWS jws = jwsJsonSerializationObject.getSignatures().get(0);
        Map<String, Object> unprotected = jws.getUnprotected();
        if (unprotected != null && (unprotected.containsKey(SDJWTConstants.DISCLOSURES) || unprotected.containsKey(SDJWTConstants.KB_JWT))) {
            throw new DSSException("The signed attestation is already an issued presentation");
        } else if (unprotected == null) {
            unprotected = new HashMap<>();
        }

        if (disclosures != null && !disclosures.isEmpty()) {
            List<String> disclosureList = disclosures.stream().map(SDJWTSelectiveDisclosure::getDisclosure).collect(Collectors.toList());
            unprotected.put(SDJWTConstants.DISCLOSURES, disclosureList);
        }

        if (keyBinding != null) {
            String keyBindingValue = new String(DSSUtils.toByteArray(keyBinding));
            unprotected.put(SDJWTConstants.KB_JWT, keyBindingValue);
        }

        jws.setUnprotected(unprotected);

        JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
                jwsJsonSerializationObject.getJWSSerializationType());
        return generator.generate();
    }

    @Override
    protected MimeType getAttestationMimeType() {
        return MimeTypeEnum.JSON; // TODO : improve
    }

    /**
     * Gets a builder to create a key binding signature's payload
     *
     * @return {@link SDJWTKeyBindingPayloadBuilder}
     */
    protected SDJWTKeyBindingPayloadBuilder getKeyBindingPayloadBuilder() {
        return new DefaultSDJWTKeyBindingPayloadBuilder();
    }

}
