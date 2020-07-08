package eu.europa.esig.dss.jades.signature;

import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import eu.europa.esig.dss.validation.ValidationDataForInclusionBuilder;

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

	@Override
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {

		super.extendSignature(jadesSignature, params);

		assertExtendSignatureToLTPossible(jadesSignature, params);

		final ValidationContext validationContext = jadesSignature.getSignatureValidationContext(certificateVerifier);

		ValidationDataForInclusionBuilder validationDataForInclusionBuilder = new ValidationDataForInclusionBuilder(
				validationContext, jadesSignature.getCompleteCertificateSource())
						.excludeCertificateTokens(jadesSignature.getCertificateSource().getCertificates())
						.excludeCRLs(jadesSignature.getCRLSource().getAllRevocationBinaries())
						.excludeOCSPs(jadesSignature.getOCSPSource().getAllRevocationBinaries());
		ValidationDataForInclusion validationDataForInclusion = validationDataForInclusionBuilder.build();

		Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
		List<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();


		List<?> unsignedProperties = getUnsignedProperties(jadesSignature);

		addXVals(certificateValuesToAdd, unsignedProperties);
		addRVals(crlsToAdd, ocspsToAdd, unsignedProperties);

	}

	@SuppressWarnings("unchecked")
	private void addXVals(Set<CertificateToken> certificateValuesToAdd, List unsignedProperties) {
		if (Utils.isCollectionEmpty(certificateValuesToAdd)) {
			return;
		}

		JSONArray xVals = new JSONArray();
		for (CertificateToken certificateToken : certificateValuesToAdd) {
			xVals.add(getX509CertObject(certificateToken));
		}

		JSONObject xValsItem = new JSONObject();
		xValsItem.put(JAdESHeaderParameterNames.X_VALS, xVals);
		unsignedProperties.add(xValsItem);
	}

	@SuppressWarnings("unchecked")
	private JSONObject getX509CertObject(CertificateToken certificateToken) {
		JSONObject pkiOb = new JSONObject();
		pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(certificateToken.getEncoded()));

		JSONObject x509Cert = new JSONObject();
		x509Cert.put(JAdESHeaderParameterNames.X509_CERT, pkiOb);
		return x509Cert;
	}

	@SuppressWarnings("unchecked")
	private void addRVals(List<CRLToken> crlsToAdd, List<OCSPToken> ocspsToAdd, List unsignedProperties) {
		if (Utils.isCollectionEmpty(crlsToAdd) && Utils.isCollectionEmpty(ocspsToAdd)) {
			return;
		}

		JSONObject rVals = new JSONObject();
		if (Utils.isCollectionNotEmpty(crlsToAdd)) {
			rVals.put(JAdESHeaderParameterNames.CRL_VALS, getCrlVals(crlsToAdd));
		}
		if (Utils.isCollectionNotEmpty(ocspsToAdd)) {
			rVals.put(JAdESHeaderParameterNames.OCSP_VALS, getOcspVals(ocspsToAdd));
		}

		JSONObject rValsItem = new JSONObject();
		rValsItem.put(JAdESHeaderParameterNames.R_VALS, rVals);
		unsignedProperties.add(rValsItem);
	}


	private JSONArray getCrlVals(List<CRLToken> crlsToAdd) {
		// TODO Auto-generated method stub
		return null;
	}

	private JSONArray getOcspVals(List<OCSPToken> ocspsToAdd) {
		// TODO Auto-generated method stub
		return null;
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
