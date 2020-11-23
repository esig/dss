package eu.europa.esig.dss.jades.signature;

import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import eu.europa.esig.dss.validation.ValidationDataForInclusionBuilder;

public class JAdESLevelBaselineLT extends JAdESLevelBaselineT {

	public JAdESLevelBaselineLT(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	@Override
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {

		super.extendSignature(jadesSignature, params);
		
		if (jadesSignature.hasLTAProfile()) {
			return;
		}
		
		assertExtendSignatureToLTPossible(jadesSignature, params);
		checkSignatureIntegrity(jadesSignature);

		final ValidationContext validationContext = jadesSignature.getSignatureValidationContext(certificateVerifier);

		// Data sources can already be loaded in memory (force reload)
		jadesSignature.resetCertificateSource();
		jadesSignature.resetRevocationSources();
		jadesSignature.resetTimestampSource();

		List<Object> unsignedProperties = getUnsignedProperties(jadesSignature);
		removeOldCertificateValues(unsignedProperties);
		removeOldRevocationValues(unsignedProperties);

		final ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(jadesSignature,
				validationContext);

		Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
		List<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();

		addXVals(certificateValuesToAdd, unsignedProperties);
		addRVals(crlsToAdd, ocspsToAdd, unsignedProperties);

	}
	
	@SuppressWarnings("unchecked")
	private void removeOldCertificateValues(List<Object> unsignedProperties) {
		ListIterator<Object> iterator = unsignedProperties.listIterator(unsignedProperties.size());
		while (iterator.hasPrevious()) {
			Map<String, Object> unsignedProperty = (Map<String, Object>) iterator.previous();
			Object xVals = unsignedProperty.get(JAdESHeaderParameterNames.X_VALS);
			if (xVals != null) {
				iterator.remove();
				return;
			}
		}
	}

	@SuppressWarnings("unchecked")
	private void removeOldRevocationValues(List<Object> unsignedProperties) {
		ListIterator<Object> iterator = unsignedProperties.listIterator(unsignedProperties.size());
		while (iterator.hasPrevious()) {
			Map<String, Object> unsignedProperty = (Map<String, Object>) iterator.previous();
			Object rVals = unsignedProperty.get(JAdESHeaderParameterNames.R_VALS);
			if (rVals != null) {
				iterator.remove();
				return;
			}
		}
	}

	protected ValidationDataForInclusion getValidationDataForInclusion(JAdESSignature jadesSignature, ValidationContext validationContext) {
		ValidationDataForInclusionBuilder validationDataForInclusionBuilder = new ValidationDataForInclusionBuilder(
				validationContext, jadesSignature.getCompleteCertificateSource())
						.excludeCertificateTokens(jadesSignature.getCertificateSource().getCertificates())
						.excludeCRLs(jadesSignature.getCRLSource().getAllRevocationBinaries())
						.excludeOCSPs(jadesSignature.getOCSPSource().getAllRevocationBinaries());
		return validationDataForInclusionBuilder.build();
	}

	@SuppressWarnings("unchecked")
	private void addXVals(Set<CertificateToken> certificateValuesToAdd, List<Object> unsignedProperties) {
		if (Utils.isCollectionEmpty(certificateValuesToAdd)) {
			return;
		}

		JSONArray xVals = getXVals(certificateValuesToAdd);

		JSONObject xValsItem = new JSONObject();
		xValsItem.put(JAdESHeaderParameterNames.X_VALS, xVals);
		unsignedProperties.add(xValsItem);
	}
	
	/**
	 * Builds and returns 'xVals' JSONArray
	 * 
	 * @param certificateValuesToAdd a set of {@link CertificateToken}s to add
	 * @return {@link JSONArray} 'xVals' value
	 */
	@SuppressWarnings("unchecked")
	protected JSONArray getXVals(Set<CertificateToken> certificateValuesToAdd) {
		JSONArray xVals = new JSONArray();
		for (CertificateToken certificateToken : certificateValuesToAdd) {
			xVals.add(getX509CertObject(certificateToken));
		}
		return xVals;
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
	private void addRVals(List<CRLToken> crlsToAdd, List<OCSPToken> ocspsToAdd, List<Object> unsignedProperties) {
		if (Utils.isCollectionEmpty(crlsToAdd) && Utils.isCollectionEmpty(ocspsToAdd)) {
			return;
		}

		JSONObject rVals = getRVals(crlsToAdd, ocspsToAdd);

		JSONObject rValsItem = new JSONObject();
		rValsItem.put(JAdESHeaderParameterNames.R_VALS, rVals);
		unsignedProperties.add(rValsItem);
	}

	/**
	 * Builds and returns 'rVals' JSONObject
	 * 
	 * @param crlsToAdd a list of {@link CRLToken}s to add
	 * @param ocspsToAdd a list of {@link OCSPToken}s to add
	 * @return {@link JSONObject} 'rVals' object
	 */
	@SuppressWarnings("unchecked")
	protected JSONObject getRVals(List<CRLToken> crlsToAdd, List<OCSPToken> ocspsToAdd) {
		JSONObject rVals = new JSONObject();
		if (Utils.isCollectionNotEmpty(crlsToAdd)) {
			rVals.put(JAdESHeaderParameterNames.CRL_VALS, getCrlVals(crlsToAdd));
		}
		if (Utils.isCollectionNotEmpty(ocspsToAdd)) {
			rVals.put(JAdESHeaderParameterNames.OCSP_VALS, getOcspVals(ocspsToAdd));
		}
		return rVals;
	}

	@SuppressWarnings("unchecked")
	private JSONArray getCrlVals(List<CRLToken> crlsToAdd) {
		JSONArray array = new JSONArray();
		for (CRLToken crlToken : crlsToAdd) {
			JSONObject pkiOb = new JSONObject();
			pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(crlToken.getEncoded()));
			array.add(pkiOb);
		}
		return array;
	}

	@SuppressWarnings("unchecked")
	private JSONArray getOcspVals(List<OCSPToken> ocspsToAdd) {
		JSONArray array = new JSONArray();
		for (OCSPToken ocspToken : ocspsToAdd) {
			JSONObject pkiOb = new JSONObject();
			pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(ocspToken.getEncoded()));
			array.add(pkiOb);
		}
		return array;
	}

	/**
	 * This method checks the signature integrity and throws a {@code DSSException} if the signature is broken.
	 *
	 * @param jadesSignature {@link JAdESSignature} to verify
	 * @throws DSSException in case of the cryptographic signature verification fails
	 */
	protected void checkSignatureIntegrity(JAdESSignature jadesSignature) throws DSSException {
		final SignatureCryptographicVerification signatureCryptographicVerification = jadesSignature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureIntact()) {
			final String errorMessage = signatureCryptographicVerification.getErrorMessage();
			throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
		}
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
