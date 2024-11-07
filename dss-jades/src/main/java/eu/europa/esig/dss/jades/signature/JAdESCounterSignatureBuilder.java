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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.AbstractJWSDocumentAnalyzer;
import eu.europa.esig.dss.jades.validation.EtsiUComponent;
import eu.europa.esig.dss.jades.validation.JWSDocumentAnalyzerFactory;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

import java.util.List;
import java.util.Objects;

/**
 * Creates a JAdES Counter signature
 */
public class JAdESCounterSignatureBuilder extends JAdESExtensionBuilder {

	/**
	 * Default constructor
	 */
	public JAdESCounterSignatureBuilder() {
		// empty
	}
	
	/**
	 * Extract SignatureValue binaries from the provided JAdES signature
	 * 
	 * @param signatureDocument {@link DSSDocument} to be counter-signed
	 * @param parameters {@link JAdESCounterSignatureParameters}
	 * @return {@link DSSDocument} extracted SignatureValue
	 */
	public DSSDocument getSignatureValueToBeSigned(DSSDocument signatureDocument, JAdESCounterSignatureParameters parameters) {

		JWSDocumentAnalyzerFactory documentValidatorFactory = new JWSDocumentAnalyzerFactory();
		AbstractJWSDocumentAnalyzer documentValidator = documentValidatorFactory.create(signatureDocument);

		JWSJsonSerializationObject jwsJsonSerializationObject = documentValidator.getJwsJsonSerializationObject();
		assertJSONSerializationObjectMayBeExtended(jwsJsonSerializationObject);

		List<AdvancedSignature> signatures = documentValidator.getSignatures();

		JAdESSignature jadesSignature = (JAdESSignature) extractSignatureById(signatures, parameters.getSignatureIdToCounterSign());
		return new InMemoryDocument(jadesSignature.getSignatureValue());
	}
	
	/**
	 * Embeds and returns the embedded counter signature into the original JAdES signature
	 * 
	 * @param signatureDocument {@link DSSDocument} the original document containing the signature to be counter signed
	 * @param counterSignature {@link DSSDocument} the counter signature
	 * @param parameters {@link JAdESCounterSignatureParameters}
	 * @return {@link DSSDocument} original signature enveloping the {@code counterSignature} in an unprotected header
	 */
	public DSSDocument buildEmbeddedCounterSignature(DSSDocument signatureDocument, DSSDocument counterSignature, 
			JAdESCounterSignatureParameters parameters) {

		JWSDocumentAnalyzerFactory documentValidatorFactory = new JWSDocumentAnalyzerFactory();
		AbstractJWSDocumentAnalyzer documentValidator = documentValidatorFactory.create(signatureDocument);

		JWSJsonSerializationObject jwsJsonSerializationObject = documentValidator.getJwsJsonSerializationObject();
		assertJSONSerializationObjectMayBeExtended(jwsJsonSerializationObject);

		List<AdvancedSignature> signatures = documentValidator.getSignatures();

		JAdESSignature jadesSignature = (JAdESSignature) extractSignatureById(signatures, parameters.getSignatureIdToCounterSign());
		assertEtsiUComponentsConsistent(jadesSignature.getJws(), parameters.isBase64UrlEncodedEtsiUComponents());

		Object cSig = getCSig(counterSignature, parameters.getJwsSerializationType());
		
		JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
		etsiUHeader.addComponent(JAdESHeaderParameterNames.C_SIG, cSig, parameters.isBase64UrlEncodedEtsiUComponents());
		
		updateMasterSignatureRecursively(jadesSignature);

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject, 
				jwsJsonSerializationObject.getJWSSerializationType());
		return generator.generate();
	}
	
	private void updateMasterSignatureRecursively(JAdESSignature jadesSignature) {
		JAdESSignature masterSignature = (JAdESSignature) jadesSignature.getMasterSignature();
		if (masterSignature != null) {
			EtsiUComponent masterCSigAttribute = jadesSignature.getMasterCSigComponent();

			JWSJsonSerializationObject jwsJsonSerializationObject = jadesSignature.getJws()
					.getJwsJsonSerializationObject();
			JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
					jwsJsonSerializationObject.getJWSSerializationType());

			Object cSig = getCSig(generator.generate(), jwsJsonSerializationObject.getJWSSerializationType());
			EtsiUComponent updatedCSigAttribute = EtsiUComponent.build(JAdESHeaderParameterNames.C_SIG, cSig,
					masterCSigAttribute.isBase64UrlEncoded(), masterCSigAttribute.getIdentifier());
			replaceCSigComponent(jadesSignature, updatedCSigAttribute);

			updateMasterSignatureRecursively(masterSignature);
		}
	}

	private Object getCSig(DSSDocument counterSignature, JWSSerializationType jwsSerializationType) {
		String signatureString = new String(DSSUtils.toByteArray(counterSignature));
		Object cSig;
		switch (jwsSerializationType) {
			case COMPACT_SERIALIZATION:
				cSig = signatureString;
				break;
			case FLATTENED_JSON_SERIALIZATION:
				try {
					cSig = new JsonObject(JsonUtil.parseJson(signatureString));
				} catch (JoseException e) {
					throw new IllegalInputException(String.format("Unable to parse a counter signature. Reason : %s", e.getMessage()), e);
				}
				break;
			default:
				throw new UnsupportedOperationException(String.format("The JWSSerializarionType '%s' is not supported for a Counter Signature!",
						jwsSerializationType));
		}
		return cSig;
	}

	private void replaceCSigComponent(JAdESSignature jadesSignature, EtsiUComponent cSigAttribute) {
		JAdESSignature masterSignature = (JAdESSignature) jadesSignature.getMasterSignature();
		JAdESEtsiUHeader etsiUHeader = masterSignature.getEtsiUHeader();
		etsiUHeader.replaceComponent(cSigAttribute);

		jadesSignature.setMasterCSigComponent(cSigAttribute);
	}
	
	private AdvancedSignature extractSignatureById(List<AdvancedSignature> signatures, String signatureId) {
		Objects.requireNonNull(signatureId, "The Id of a signature to be counter signed shall be defined! "
				+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");

		if (Utils.isCollectionEmpty(signatures)) {
			throw new IllegalArgumentException("The provided signatureDocument does not contain JAdES Signatures!");
		}
		for (AdvancedSignature signature : signatures) {
			AdvancedSignature signatureById = getSignatureOrItsCounterSignature((JAdESSignature) signature, signatureId);
			if (signatureById != null) {
				return signatureById;
			}
		}
		throw new IllegalArgumentException(String.format("The requested JAdES Signature with id '%s' has not been found in the provided file!", signatureId));
	}

	private JAdESSignature getSignatureOrItsCounterSignature(JAdESSignature signature, String signatureId) {
		if (signatureId == null || signatureId.equals(signature.getId())) {
			return signature;
		}

		List<EtsiUComponent> cSigComponents = DSSJsonUtils.getUnsignedPropertiesWithHeaderName(
				signature.getEtsiUHeader(), JAdESHeaderParameterNames.C_SIG);

		if (Utils.isCollectionNotEmpty(cSigComponents)) {
			for (EtsiUComponent cSigComponent : cSigComponents) {
				
				// check timestamp before incorporating a new property
				if (signature.getTimestampSource().isTimestamped(signatureId, TimestampedObjectType.SIGNATURE)) {
					throw new IllegalInputException(String.format("Unable to counter sign a signature with Id '%s'. "
							+ "The signature is timestamped by a master signature!", signatureId));
				}
				
				JAdESSignature counterSignature = DSSJsonUtils.extractJAdESCounterSignature(cSigComponent, signature);
				JAdESSignature signatureById = getSignatureOrItsCounterSignature(counterSignature, signatureId);
				if (signatureById != null) {
					if (cSigComponent.getValue() instanceof String) {
						throw new IllegalInputException("Unable to extend a Compact JAdES Signature with id '" + signatureId + "'");
					}
					return signatureById;
				}
				
			}
		}
		
		return null;
	}

}
