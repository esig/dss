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

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.AbstractJWSDocumentValidator;
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The builder used to incorporate a {@code SignaturePolicyStore} to a
 * JAdESSignature document
 *
 */
public class JAdESSignaturePolicyStoreBuilder extends JAdESExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignaturePolicyStoreBuilder.class);

	/**
	 * Adds {@code signaturePolicyStore} to all signatures inside the {@code document}
	 * matching the given {@code SignaturePolicyStore}.
	 * 
	 * @param document             {@link DSSDocument} containing JAdES signatures to extend with
	 *                             a {@link SignaturePolicyStore}
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to incorporate
	 * @param base64UrlInstance    TRUE if the signature policy store shall be incorporated as a
	 *                             base64url-encoded component of the 'etsiU' header, FALSE if it will be
	 *                             incorporated in its clear JSON representation
	 * @return {@link DSSDocument} containing signatures with {@code signaturePolicyStore}
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore,
											   boolean base64UrlInstance) {
		Objects.requireNonNull(document, "Signature document must be provided!");
		assertConfigurationValid(signaturePolicyStore);

		final AbstractJWSDocumentValidator documentValidator = getDocumentValidator(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = documentValidator.getJwsJsonSerializationObject();
		assertJSONSerializationObjectMayBeExtended(jwsJsonSerializationObject);

		List<AdvancedSignature> signatures = documentValidator.getSignatures();

		boolean signaturePolicyStoreAdded = false;
		for (AdvancedSignature signature : signatures) {
			boolean added = addSignaturePolicyStoreIfDigestMatch((JAdESSignature) signature, signaturePolicyStore,
					base64UrlInstance, documentValidator);
			signaturePolicyStoreAdded = signaturePolicyStoreAdded || added;
		}
		if (!signaturePolicyStoreAdded) {
			throw new IllegalInputException("The process did not find a signature to add SignaturePolicyStore!");
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				jwsJsonSerializationObject.getJWSSerializationType());
		return generator.generate();
	}

	/**
	 * Adds {@code signaturePolicyStore} to a signature inside the {@code document}
	 * with the given {@code signatureId}
	 *
	 * @param document             {@link DSSDocument} containing JAdES signatures to extend with
	 *                             a {@link SignaturePolicyStore}
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to incorporate
	 * @param base64UrlInstance    TRUE if the signature policy store shall be incorporated as a
	 *                             base64url-encoded component of the 'etsiU' header, FALSE if it will be
	 *                             incorporated in its clear JSON representation
	 * @param signatureId          {@link String} id of a signature to add SignaturePolicyStore for
	 * @return {@link DSSDocument} containing signatures with {@code signaturePolicyStore}
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore,
											   boolean base64UrlInstance, String signatureId) {
		Objects.requireNonNull(document, "Signature document must be provided!");
		assertConfigurationValid(signaturePolicyStore);

		final AbstractJWSDocumentValidator documentValidator = getDocumentValidator(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = documentValidator.getJwsJsonSerializationObject();
		assertJSONSerializationObjectMayBeExtended(jwsJsonSerializationObject);

		AdvancedSignature signature = documentValidator.getSignatureById(signatureId);
		if (signature == null) {
			throw new IllegalInputException(String.format("Unable to find a signature with Id : %s!", signatureId));
		}

		boolean added = addSignaturePolicyStoreIfDigestMatch((JAdESSignature) signature, signaturePolicyStore,
				base64UrlInstance, documentValidator);
		if (!added) {
			throw new IllegalInputException(String.format(
					"The process was not able to add SignaturePolicyStore to a signature with Id : %s!", signatureId));
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				jwsJsonSerializationObject.getJWSSerializationType());
		return generator.generate();
	}

	/**
	 * This method adds {@code SignaturePolicyStore} to a {@code jadesSignature} if required
	 *
	 * @param jadesSignature       {@link JAdESSignature} signature to add {@link SignaturePolicyStore}
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to be added
	 * @param base64UrlInstance    defines whether {@code SignaturePolicyStore} shall be incorporated
	 *                             as a base64url-encoded 'etsiU' component
	 * @param documentValidator    {@link SignedDocumentValidator} used to extract the signature
	 * @return TRUE if the signaturePolicyStore has been added for the particular signature, FALSE otherwise
	 */
	protected boolean addSignaturePolicyStoreIfDigestMatch(JAdESSignature jadesSignature, SignaturePolicyStore signaturePolicyStore,
								 boolean base64UrlInstance, SignedDocumentValidator documentValidator) {
		assertEtsiUComponentsConsistent(jadesSignature.getJws(), base64UrlInstance);

		if (checkDigest(jadesSignature, signaturePolicyStore, documentValidator)) {
			Map<String, Object> sigPolicyStoreParams = new LinkedHashMap<>();

			DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
			if (signaturePolicyContent != null) {
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SIG_POL_DOC,
						Utils.toBase64(DSSUtils.toByteArray(signaturePolicyContent)));
			}

			String sigPolDocLocalURI = signaturePolicyStore.getSigPolDocLocalURI();
			if (Utils.isStringNotEmpty(sigPolDocLocalURI)) {
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SIG_POL_LOCAL_URI, sigPolDocLocalURI);
			}

			SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
			JsonObject oidObject = DSSJsonUtils.getOidObject(spDocSpecification.getId(),
					spDocSpecification.getDescription(), spDocSpecification.getDocumentationReferences());
			sigPolicyStoreParams.put(JAdESHeaderParameterNames.SP_DSPEC, oidObject);

			JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
			etsiUHeader.addComponent(JAdESHeaderParameterNames.SIG_PST,
					sigPolicyStoreParams, base64UrlInstance);

			return true;
		}

		return false;
	}

	/**
	 * This method verifies if the digests computed in the provided {@code SignaturePolicyStore} match
	 * the digest defined in the incorporated signature policy identifier
	 *
	 * @param jadesSignature       {@link JAdESSignature} to check signature policy identifier
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to be incorporated
	 * @param documentValidator    {@link eu.europa.esig.dss.validation.SignedDocumentValidator}
	 *                             JWS document validator used to extract the signature
	 * @return TRUE if the digest match and {@link SignaturePolicyStore} can be embedded, FALSE otherwise
	 */
	protected boolean checkDigest(JAdESSignature jadesSignature, SignaturePolicyStore signaturePolicyStore,
								  SignedDocumentValidator documentValidator) {
		final SignaturePolicy signaturePolicy = jadesSignature.getSignaturePolicy();
		if (signaturePolicy == null) {
			LOG.warn("No defined SignaturePolicyIdentifier for signature with Id : {}", jadesSignature.getId());
			return false;
		}
		final Digest expectedDigest = signaturePolicy.getDigest();
		if (expectedDigest == null) {
			LOG.warn("No defined digest for signature with Id : {}", jadesSignature.getId());
			return false;
		}

		DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
		if (signaturePolicyContent == null) {
			LOG.info("No policy document has been provided. Digests are not checked!");
			return true;
		}
		signaturePolicy.setPolicyContent(signaturePolicyContent);

		SignaturePolicyValidator validator = documentValidator.getSignaturePolicyValidatorLoader().loadValidator(signaturePolicy);
		Digest computedDigest = validator.getComputedDigest(signaturePolicyContent, expectedDigest.getAlgorithm());

		boolean digestMatch = expectedDigest.equals(computedDigest);
		if (!digestMatch) {
			LOG.warn("Signature policy's digest {} doesn't match the digest extracted from document {} for signature with Id : {}",
					computedDigest, expectedDigest, jadesSignature.getId());
		}
		return digestMatch;
	}

	private AbstractJWSDocumentValidator getDocumentValidator(DSSDocument document) {
		JAdESDocumentValidatorFactory documentValidatorFactory = new JAdESDocumentValidatorFactory();
		return documentValidatorFactory.create(document);
	}

	private void assertConfigurationValid(SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");

		boolean signaturePolicyContentPresent = signaturePolicyStore.getSignaturePolicyContent() != null;
		boolean sigPolDocLocalURIPresent = signaturePolicyStore.getSigPolDocLocalURI() != null;
		if (!(signaturePolicyContentPresent ^ sigPolDocLocalURIPresent)) {
			throw new IllegalArgumentException("SignaturePolicyStore shall contain either " +
					"SignaturePolicyContent document or sigPolDocLocalURI!");
		}
	}

}
