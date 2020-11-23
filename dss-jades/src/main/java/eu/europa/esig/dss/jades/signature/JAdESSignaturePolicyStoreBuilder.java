package eu.europa.esig.dss.jades.signature;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jose4j.json.internal.json_simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidatorLoader;

public class JAdESSignaturePolicyStoreBuilder extends JAdESExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignaturePolicyStoreBuilder.class);

	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSignaturePolicyContent(), "Signature policy content must be provided");

		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = parser.parse();

		if (jwsJsonSerializationObject == null || Utils.isCollectionEmpty(jwsJsonSerializationObject.getSignatures())) {
			throw new DSSException("There is no signature to extend!");
		}

		for (JWS signature : jwsJsonSerializationObject.getSignatures()) {
			JAdESSignature jadesSignature = new JAdESSignature(signature);
			extendSignature(jadesSignature, signaturePolicyStore);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				jwsJsonSerializationObject.getJWSSerializationType());
		return new InMemoryDocument(generator.generate());
	}

	private void extendSignature(JAdESSignature jadesSignature, SignaturePolicyStore signaturePolicyStore) {
		SignaturePolicy policyId = jadesSignature.getSignaturePolicy();
		if (policyId != null && policyId.getDigest() != null) {
			Digest expectedDigest = policyId.getDigest();
			policyId.setPolicyContent(signaturePolicyStore.getSignaturePolicyContent());
			
			SignaturePolicyValidator validator = new SignaturePolicyValidatorLoader(policyId).loadValidator();
			Digest computedDigest = validator.getComputedDigest(expectedDigest.getAlgorithm());
			if (expectedDigest.equals(computedDigest)) {

				List<Object> unsignedProperties = getUnsignedProperties(jadesSignature);

				Map<String, Object> sigPolicyStoreParams = new LinkedHashMap<>();
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SIG_POL_DOC,
						Utils.toBase64(DSSUtils.toByteArray(signaturePolicyStore.getSignaturePolicyContent())));

				SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
				JsonObject oidObject = DSSJsonUtils.getOidObject(spDocSpecification.getId(), spDocSpecification.getDescription(), 
						spDocSpecification.getDocumentationReferences());
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SP_DSPEC, oidObject);

				Map<String, Object> sigPolicyStoreMap = new HashMap<>();
				sigPolicyStoreMap.put(JAdESHeaderParameterNames.SIG_PST, sigPolicyStoreParams);

				JSONObject sigPolicyStoreItem = new JSONObject(sigPolicyStoreMap);
				unsignedProperties.add(sigPolicyStoreItem);
			} else {
				LOG.warn("Signature policy's digest doesn't match the document {} for signature {}", expectedDigest, jadesSignature.getId());
			}
		} else {
			LOG.warn("No SignaturePolicyIdentifier '{}' found for a signature with id '{}'!",
					JAdESHeaderParameterNames.SIG_PID, jadesSignature.getId());
		}
	}

}
