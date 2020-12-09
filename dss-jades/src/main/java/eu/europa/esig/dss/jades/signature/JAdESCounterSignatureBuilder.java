package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.EtsiUComponent;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

import java.util.List;

/**
 * Creates a JAdES Counter signature
 */
public class JAdESCounterSignatureBuilder extends JAdESExtensionBuilder {
	
	/**
	 * Extract SignatureValue binaries from the provided JAdES signature
	 * 
	 * @param signatureDocument {@link DSSDocument} to be counter-signed
	 * @param parameters {@link JAdESCounterSignatureParameters}
	 * @return {@link DSSDocument} extracted SignatureValue
	 */
	public DSSDocument getSignatureValueToBeSigned(DSSDocument signatureDocument, JAdESCounterSignatureParameters parameters) {
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(signatureDocument);
		JWSJsonSerializationObject jwsJsonSerializationObject = jwsJsonSerializationParser.parse();
		
		JAdESSignature jadesSignature = (JAdESSignature) extractSignatureById(jwsJsonSerializationObject,
				parameters.getSignatureIdToCounterSign());
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
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(signatureDocument);
		JWSJsonSerializationObject jwsJsonSerializationObject = jwsJsonSerializationParser.parse();
		
		JAdESSignature jadesSignature = (JAdESSignature) extractSignatureById(jwsJsonSerializationObject,
				parameters.getSignatureIdToCounterSign());
		assertEtsiUComponentsConsistent(jadesSignature.getJws(), parameters.isBase64UrlEncodedEtsiUComponents());

		Object cSig = getCSig(counterSignature, parameters.getJwsSerializationType());
		
		JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
		etsiUHeader.addComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.C_SIG, cSig,
				parameters.isBase64UrlEncodedEtsiUComponents());
		
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
			masterCSigAttribute.overwriteValue(cSig);

			JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
			etsiUHeader.replaceComponent(masterSignature.getJws(), masterCSigAttribute);

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
					throw new DSSException(String.format("An error occurred during a Counter Signature creation. Reason : %s", e.getMessage()), e);
				}
				break;
			default:
				throw new DSSException(String.format("The JWSSerializarionType '%s' is not supported for a Counter Signature!", 
						jwsSerializationType));
		}
		return cSig;
	}
	
	private AdvancedSignature extractSignatureById(JWSJsonSerializationObject jwsJsonSerializationObject,
			String signatureId) {
		if (!jwsJsonSerializationObject.isValid()) {
			throw new DSSException(String.format("Counter signature is not supported for invalid RFC 7515 files "
					+ "(shall be a Serializable JAdES signature). Reason(s) : %s",
					jwsJsonSerializationObject.getStructuralValidationErrors()));
		}
		if (Utils.isStringEmpty(signatureId)) {
			throw new DSSException("The Id of a signature to be counter signed shall be defined! "
					+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");
		}
		
		List<JWS> jwsSignatures = jwsJsonSerializationObject.getSignatures();
		if (Utils.isCollectionEmpty(jwsSignatures)) {
			throw new DSSException("The provided signatureDocument does not contain JAdES Signatures!");
		}
		for (JWS jws : jwsSignatures) {
			JAdESSignature jadesSignature = new JAdESSignature(jws);
			AdvancedSignature signatureById = getSignatureOrItsCounterSignature(jadesSignature, signatureId);
			if (signatureById != null) {
				return signatureById;
			}
		}
		throw new DSSException(String.format("The requested JAdES Signature with id '%s' has not been found in the provided file!", signatureId));
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
					throw new DSSException(String.format("Unable to counter sign a signature with Id '%s'. "
							+ "The signature is timestamped by a master signature!", signatureId));
				}
				
				JAdESSignature counterSignature = DSSJsonUtils.extractJAdESCounterSignature(cSigComponent, signature);
				JAdESSignature signatureById = getSignatureOrItsCounterSignature(counterSignature, signatureId);
				if (signatureById != null) {
					if (cSigComponent.getValue() instanceof String) {
						throw new DSSException("Unable to extend a Compact JAdES Signature with id '" + signatureId + "'");
					}
					return signatureById;
				}
				
			}
		}
		
		return null;
	}

}
