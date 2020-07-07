package eu.europa.esig.dss.jades.signature;

import java.util.Objects;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class JAdESLevelBaselineLT extends JAdESLevelBaselineT {

	public JAdESLevelBaselineLT(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	@Override
	public DSSDocument extendSignatures(DSSDocument document, JAdESSignatureParameters params) throws DSSException {
		Objects.requireNonNull(document, "The document cannot be null");
		Objects.requireNonNull(tspSource, "The TSPSource cannot be null");

		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = parser.parse();

		if (jwsJsonSerializationObject == null || Utils.isCollectionEmpty(jwsJsonSerializationObject.getSignatures())) {
			throw new DSSException("There is no signature to extend!");
		}

		for (JWS signature : jwsJsonSerializationObject.getSignatures()) {

			JAdESSignature jadesSignature = new JAdESSignature(signature);
			jadesSignature.setDetachedContents(params.getDetachedContents());
			jadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);

			extendSignature(jadesSignature, params);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				params.getJwsSerializationType());
		return new InMemoryDocument(generator.generate());
	}

	private void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {

		assertExtendSignatureToLTPossible(jadesSignature, params);

//		Map<String, Object> unsignedProperties = getUnsignedProperties(jadesSignature);


	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTPossible(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.JAdES_BASELINE_LT.equals(signatureLevel) && jadesSignature.hasLTAProfile()) {
			final String exceptionMessage = "Cannot extend the signature. The signedData is already extended with [%s]!";
			throw new DSSException(String.format(exceptionMessage, "JAdES LTA"));
		} else if (jadesSignature.areAllSelfSignedCertificates()) {
			throw new DSSException(
					"Cannot extend the signature. The signature contains only self-signed certificate chains!");
		}
	}

}
