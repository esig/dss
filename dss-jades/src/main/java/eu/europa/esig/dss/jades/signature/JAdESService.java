/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.validation.AbstractJWSDocumentValidator;
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Contains methods for JAdES signature creation/extension
 */
public class JAdESService extends AbstractSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> implements 
					MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters>,
					CounterSignatureService<JAdESCounterSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESService.class);

	/**
	 * This is the constructor to create an instance of the {@code JAdESService}. A
	 * certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information
	 *                            on the sources to be used in the validation
	 *                            process in the context of a signature.
	 */
	public JAdESService(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ JAdESService created");
	}
	
	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, JAdESSignatureParameters parameters) {
		return getContentTimestamp(Arrays.asList(toSignDocument), parameters);
	}
	
	/**
	 * This methods allows to create a TimestampToken for a detached JAdES (with a 'sigD' parameter).
	 * NOTE: The toSignDocuments must be present in the same order they will be passed to signature computation process
	 * 
	 * @param toSignDocuments a list of {@link DSSDocument}s to be timestamped
	 * @param parameters {@link JAdESSignatureParameters}
	 * @return content {@link TimestampToken}
	 */
	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, JAdESSignatureParameters parameters) {
		if (tspSource == null) {
			throw new DSSException("A TSPSource is required!");
		}
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("Original documents must be provided to generate a content timestamp!");
		}
		
		byte[] messageImprint = DSSUtils.EMPTY_BYTE_ARRAY;

		if (SigDMechanism.HTTP_HEADERS.equals(parameters.getSigDMechanism())) {
			HttpHeadersPayloadBuilder httpHeadersPayloadBuilder = new HttpHeadersPayloadBuilder(toSignDocuments, true);
			messageImprint = httpHeadersPayloadBuilder.build();
		} else {
			messageImprint = DSSJsonUtils.concatenateDSSDocuments(toSignDocuments);
			if (parameters.isBase64UrlEncodedPayload()) {
				messageImprint = DSSJsonUtils.toBase64Url(messageImprint).getBytes();
			}
		}

		DigestAlgorithm digestAlgorithm = parameters.getContentTimestampParameters().getDigestAlgorithm();
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm,
				DSSUtils.digest(digestAlgorithm, messageImprint));
		try {
			return new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
		} catch (TSPException | IOException | CMSException e) {
			throw new DSSException("Cannot create a content TimestampToken", e);
		}
	}

	@Override
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, JAdESSignatureParameters parameters) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		
		assertSigningDateInCertificateValidityRange(parameters);
		
		JAdESBuilder jadesBuilder = getJAdESBuilder(parameters, Collections.singletonList(toSignDocument));
		return jadesBuilder.buildDataToBeSigned();
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, JAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		
		assertMultiDocumentsAllowed(toSignDocuments, parameters);
		assertSigningDateInCertificateValidityRange(parameters);

		JAdESBuilder jadesBuilder = getJAdESBuilder(parameters, toSignDocuments);
		return jadesBuilder.buildDataToBeSigned();
	}

	/**
	 * Only DETACHED signatures are allowed
	 *
	 * @param toSignDocuments list of {@link DSSDocument}s
	 * @param parameters {@link JAdESSignatureParameters}
	 */
	private void assertMultiDocumentsAllowed(List<DSSDocument> toSignDocuments, JAdESSignatureParameters parameters) {
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("The documents to sign must be provided!");
		}
		SignaturePackaging signaturePackaging = parameters.getSignaturePackaging();
		if (!SignaturePackaging.DETACHED.equals(signaturePackaging) && toSignDocuments.size() > 1) {
			throw new DSSException("Not supported operation (only DETACHED are allowed for multiple document signing)!");
		}
		if (SignaturePackaging.DETACHED.equals(signaturePackaging) && SigDMechanism.NO_SIG_D.equals(parameters.getSigDMechanism()) 
				&& toSignDocuments.size() > 1) {
			throw new DSSException("NO_SIG_D mechanism is not allowed for multiple documents!");
		}
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, JAdESSignatureParameters parameters,
			SignatureValue signatureValue) {
		return signDocument(Collections.singletonList(toSignDocument), parameters, signatureValue);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, JAdESSignatureParameters parameters,
			SignatureValue signatureValue) {
		JAdESBuilder jadesBuilder = getJAdESBuilder(parameters, toSignDocuments);

		DSSDocument signedDocument = jadesBuilder.build(signatureValue);
		SignatureExtension<JAdESSignatureParameters> signatureExtension = getExtensionProfile(parameters);
		if (signatureExtension != null) {
			if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging()) && Utils.isCollectionEmpty(parameters.getDetachedContents())) {
				parameters.setDetachedContents(toSignDocuments);
			}
			signedDocument = signatureExtension.extendSignatures(signedDocument, parameters);
		}
		signedDocument.setName(getFinalFileName(toSignDocuments.iterator().next(), SigningOperation.SIGN,
				parameters.getSignatureLevel()));
		signedDocument.setMimeType(jadesBuilder.getMimeType());
		return signedDocument;
	}

	/**
	 * Returns the JAdESBuilder to be used
	 *
	 * @param parameters {@link JAdESSignatureParameters}
	 * @param documentsToSign a list of {@link DSSDocument}s
	 * @return {@link JAdESBuilder}
	 */
	protected JAdESBuilder getJAdESBuilder(JAdESSignatureParameters parameters, List<DSSDocument> documentsToSign) {
		JWSJsonSerializationObject jwsJsonSerializationObject = getJWSJsonSerializationObjectToSign(documentsToSign);
		if (containsSignatures(jwsJsonSerializationObject)) {
			if (!jwsJsonSerializationObject.isValid()) {
				throw new DSSException(String.format(
						"Parallel signing is not supported for invalid RFC 7515 signatures. Reason(s) : %s",
						jwsJsonSerializationObject.getStructuralValidationErrors()));
			}
			// return a builder for parallel signing
			return new JAdESSerializationBuilder(certificateVerifier, parameters, jwsJsonSerializationObject);
		}

		switch (parameters.getJwsSerializationType()) {
			case COMPACT_SERIALIZATION:
				return new JAdESCompactBuilder(certificateVerifier, parameters, documentsToSign);
			case JSON_SERIALIZATION:
			case FLATTENED_JSON_SERIALIZATION:
				return new JAdESSerializationBuilder(certificateVerifier, parameters, documentsToSign);

			default:
				throw new DSSException(String.format("The requested JWS Serialization Type '%s' is not supported!",
						parameters.getJwsSerializationType()));
		}
	}

	private JWSJsonSerializationObject getJWSJsonSerializationObjectToSign(List<DSSDocument> documentsToSign) {
		if (Utils.isCollectionNotEmpty(documentsToSign) && documentsToSign.size() == 1) {
			DSSDocument document = documentsToSign.get(0);
			JAdESDocumentValidatorFactory documentValidatorFactory = new JAdESDocumentValidatorFactory();
			if (documentValidatorFactory.isSupported(document)) {
				AbstractJWSDocumentValidator documentValidator = documentValidatorFactory.create(document);
				return documentValidator.getJwsJsonSerializationObject();
			}
		}
		return null;
	}

	private boolean containsSignatures(JWSJsonSerializationObject jwsJsonSerializationObject) {
		return jwsJsonSerializationObject != null &&
				Utils.isCollectionNotEmpty(jwsJsonSerializationObject.getSignatures());
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, JAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");
		Objects.requireNonNull(parameters.getSignatureLevel(), "SignatureLevel must be defined!");
		assertExtensionPossible(parameters);

		final SignatureExtension<JAdESSignatureParameters> extension = getExtensionProfile(parameters);
		if (extension != null) {
			final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
			dssDocument.setName(
					getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
			dssDocument.setMimeType(MimeType.JOSE_JSON);
			return dssDocument;
		}
		throw new DSSException("Cannot extend to " + parameters.getSignatureLevel());
	}

	private void assertExtensionPossible(JAdESSignatureParameters parameters) {
		if (!JWSSerializationType.JSON_SERIALIZATION.equals(parameters.getJwsSerializationType()) &&
				!JWSSerializationType.FLATTENED_JSON_SERIALIZATION.equals(parameters.getJwsSerializationType())) {
			throw new DSSException(String.format("The type '%s' does not support signature extension!",
					parameters.getJwsSerializationType()));
		}
	}

	private SignatureExtension<JAdESSignatureParameters> getExtensionProfile(JAdESSignatureParameters parameters) {
		switch (parameters.getSignatureLevel()) {
		case JAdES_BASELINE_B:
			return null;
		case JAdES_BASELINE_T:
			final JAdESLevelBaselineT extensionT = new JAdESLevelBaselineT(certificateVerifier);
			extensionT.setTspSource(tspSource);
			return extensionT;
		case JAdES_BASELINE_LT:
			final JAdESLevelBaselineLT extensionLT = new JAdESLevelBaselineLT(certificateVerifier);
			extensionLT.setTspSource(tspSource);
			return extensionLT;
		case JAdES_BASELINE_LTA:
			final JAdESLevelBaselineLTA extensionLTA = new JAdESLevelBaselineLTA(certificateVerifier);
			extensionLTA.setTspSource(tspSource);
			return extensionLTA;
		default:
			throw new DSSException("Unsupported signature format " + parameters.getSignatureLevel());
		}
	}

	@Override
	public DSSDocument timestamp(List<DSSDocument> toTimestampDocuments, JAdESTimestampParameters parameters) {
		throw new UnsupportedOperationException("Unsupported operation for this file format");
	}

	/**
	 * Incorporates a Signature Policy Store as a base64Url-encoded unsigned property into the JAdES Signature
	 * 
	 * @param document             {@link DSSDocument} containing a JAdES Signature to add a SignaturePolicyStore to
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} JAdESSignature with an incorporates SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore) {
		return addSignaturePolicyStore(document, signaturePolicyStore, true);
	}

	/**
	 * Incorporates a Signature Policy Store as an unsigned property into the JAdES Signature
	 * 
	 * @param document             {@link DSSDocument} containing a JAdES Signature to add a SignaturePolicyStore to
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @param base64UrlInstance    defines if the SignaturePolicyStore shall be incorporated in its corresponding base64Url
	 *                             representation, otherwise if FALSE incorporates in the clear JSON representation
	 * @return {@link DSSDocument} JAdESSignature with an incorporates SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore,
			boolean base64UrlInstance) {
		Objects.requireNonNull(document, "The document cannot be null");
		Objects.requireNonNull(signaturePolicyStore, "The signaturePolicyStore cannot be null");
		
		JAdESSignaturePolicyStoreBuilder builder = new JAdESSignaturePolicyStoreBuilder();
		DSSDocument signatureWithPolicyStore = builder.addSignaturePolicyStore(document, signaturePolicyStore, base64UrlInstance);
		signatureWithPolicyStore.setName(getFinalFileName(document, SigningOperation.ADD_SIG_POLICY_STORE));
		signatureWithPolicyStore.setMimeType(document.getMimeType());
		return signatureWithPolicyStore;
	}

	@Override
	public ToBeSigned getDataToBeCounterSigned(DSSDocument signatureDocument, JAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		verifyAndSetCounterSignatureParameters(parameters);
		
		JAdESCounterSignatureBuilder counterSignatureBuilder = new JAdESCounterSignatureBuilder();
		DSSDocument signatureValueToSign = counterSignatureBuilder.getSignatureValueToBeSigned(signatureDocument, parameters);
		
		return getDataToSign(signatureValueToSign, parameters);
	}

	@Override
	public DSSDocument counterSignSignature(DSSDocument signatureDocument, JAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
		verifyAndSetCounterSignatureParameters(parameters);

		JAdESCounterSignatureBuilder counterSignatureBuilder = new JAdESCounterSignatureBuilder();
		DSSDocument signatureValueToSign = counterSignatureBuilder.getSignatureValueToBeSigned(signatureDocument, parameters);
		
		DSSDocument counterSignature = signDocument(signatureValueToSign, parameters, signatureValue);
		
		DSSDocument counterSigned = counterSignatureBuilder.buildEmbeddedCounterSignature(signatureDocument, counterSignature, parameters);
		
		counterSigned.setName(getFinalFileName(signatureDocument, SigningOperation.COUNTER_SIGN,
				parameters.getSignatureLevel()));
		counterSigned.setMimeType(signatureDocument.getMimeType());
		
		return counterSigned;
	}
	
	private void verifyAndSetCounterSignatureParameters(JAdESCounterSignatureParameters parameters) {
		if (parameters.getSignaturePackaging() == null) {
			// attached counter signature is created by default
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		}

		switch (parameters.getSignaturePackaging()) {
			case ENVELOPING:
				break;
			case DETACHED:
				if (parameters.getSigDMechanism() == null) {
					parameters.setSigDMechanism(SigDMechanism.NO_SIG_D);
				} else if (!SigDMechanism.NO_SIG_D.equals(parameters.getSigDMechanism())) {
					throw new IllegalArgumentException(String.format("The SigDMechanism '%s' is not supported by JAdES Counter Signature!",
							parameters.getSigDMechanism()));
				}
				break;
			default:
				throw new IllegalArgumentException(
						String.format("The SignaturePackaging '%s' is not supported by JAdES Counter Signature!",
						parameters.getSignaturePackaging()));
		}

		
		if (JWSSerializationType.JSON_SERIALIZATION.equals(parameters.getJwsSerializationType())) {
			throw new IllegalArgumentException("The JWSSerializationType.JSON_SERIALIZATION parameter " +
					"is not supported for a JAdES Counter Signature!");
		}
	}

}
