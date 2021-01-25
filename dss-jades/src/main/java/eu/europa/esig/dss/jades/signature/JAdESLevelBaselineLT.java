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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
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
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import java.util.List;
import java.util.Set;

/**
 * Creates an LT-level of a JAdES signature
 */
public class JAdESLevelBaselineLT extends JAdESLevelBaselineT {

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public JAdESLevelBaselineLT(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	@Override
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {

		super.extendSignature(jadesSignature, params);
		
		if (jadesSignature.hasLTAProfile()) {
			return;
		}

		// Data sources can already be loaded in memory (force reload)
		jadesSignature.resetCertificateSource();
		jadesSignature.resetRevocationSources();
		jadesSignature.resetTimestampSource();

		assertExtendSignatureToLTPossible(jadesSignature, params);
		JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();

		/**
		 * In all cases the -LT level need to be regenerated.
		 */
		checkSignatureIntegrity(jadesSignature);

		// must be executed before data removing
		final ValidationContext validationContext = jadesSignature.getSignatureValidationContext(certificateVerifier);

		removeOldCertificateValues(jadesSignature, etsiUHeader);
		removeOldRevocationValues(jadesSignature, etsiUHeader);

		final ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(jadesSignature,
				validationContext);

		Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
		if (Utils.isCollectionNotEmpty(certificateValuesToAdd)) {
			JSONArray xVals = getXVals(certificateValuesToAdd);
			etsiUHeader.addComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.X_VALS, xVals,
					params.isBase64UrlEncodedEtsiUComponents());
		}
		List<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();
		if (Utils.isCollectionNotEmpty(crlsToAdd) || Utils.isCollectionNotEmpty(ocspsToAdd)) {
			JsonObject rVals = getRVals(crlsToAdd, ocspsToAdd);
			etsiUHeader.addComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.R_VALS, rVals,
					params.isBase64UrlEncodedEtsiUComponents());
		}
	}

	private void removeOldCertificateValues(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		etsiUHeader.removeComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.X_VALS);
		jadesSignature.resetCertificateSource();
	}

	private void removeOldRevocationValues(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		etsiUHeader.removeComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.R_VALS);
		jadesSignature.resetRevocationSources();
	}

	/**
	 * Gets the validation data to be included into the signature
	 *
	 * @param jadesSignature {@link JAdESSignature} to get validation data to be included for
	 * @param validationContext {@link ValidationContext} used to process the signature
	 * @return {@link ValidationDataForInclusion}
	 */
	protected ValidationDataForInclusion getValidationDataForInclusion(JAdESSignature jadesSignature,
																	   ValidationContext validationContext) {
		ValidationDataForInclusionBuilder validationDataForInclusionBuilder = new ValidationDataForInclusionBuilder(
				validationContext, jadesSignature.getCompleteCertificateSource())
						.excludeCertificateTokens(jadesSignature.getCertificateSource().getCertificates())
						.excludeCRLs(jadesSignature.getCRLSource().getAllRevocationBinaries())
						.excludeOCSPs(jadesSignature.getOCSPSource().getAllRevocationBinaries());
		return validationDataForInclusionBuilder.build();
	}

	/**
	 * Builds and returns 'xVals' JSONArray
	 * 
	 * @param certificateValuesToAdd a set of {@link CertificateToken}s to add
	 * @return {@link JSONArray} 'xVals' JSONArray
	 */
	@SuppressWarnings("unchecked")
	protected JSONArray getXVals(Set<CertificateToken> certificateValuesToAdd) {
		JSONArray xValsArray = new JSONArray();
		for (CertificateToken certificateToken : certificateValuesToAdd) {
			xValsArray.add(getX509CertObject(certificateToken));
		}
		return xValsArray;
	}

	@SuppressWarnings("unchecked")
	private JSONObject getX509CertObject(CertificateToken certificateToken) {
		JSONObject pkiOb = new JSONObject();
		pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(certificateToken.getEncoded()));

		JSONObject x509Cert = new JSONObject();
		x509Cert.put(JAdESHeaderParameterNames.X509_CERT, pkiOb);
		return x509Cert;
	}

	/**
	 * Builds and returns 'rVals' JsonObject
	 * 
	 * @param crlsToAdd  a list of {@link CRLToken}s to add
	 * @param ocspsToAdd a list of {@link OCSPToken}s to add
	 * @return {@link JsonObject} 'rVals' object
	 */
	protected JsonObject getRVals(List<CRLToken> crlsToAdd, List<OCSPToken> ocspsToAdd) {
		JsonObject rValsObject = new JsonObject();
		if (Utils.isCollectionNotEmpty(crlsToAdd)) {
			rValsObject.put(JAdESHeaderParameterNames.CRL_VALS, getCrlVals(crlsToAdd));
		}
		if (Utils.isCollectionNotEmpty(ocspsToAdd)) {
			rValsObject.put(JAdESHeaderParameterNames.OCSP_VALS, getOcspVals(ocspsToAdd));
		}
		return rValsObject;
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
