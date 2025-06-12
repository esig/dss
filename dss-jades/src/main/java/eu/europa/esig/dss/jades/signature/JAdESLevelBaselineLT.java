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

import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static eu.europa.esig.dss.enumerations.SignatureLevel.JAdES_BASELINE_LT;

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
	protected void extendSignatures(List<AdvancedSignature> signatures, JAdESSignatureParameters params) {
		super.extendSignatures(signatures, params);

		final List<AdvancedSignature> signaturesToExtend = getExtendToLTLevelSignatures(signatures, params);
		if (Utils.isCollectionEmpty(signaturesToExtend)) {
			return;
		}

		// Reset sources
		for (AdvancedSignature signature : signaturesToExtend) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;

			// Data sources can already be loaded in memory (force reload)
			jadesSignature.resetCertificateSource();
			jadesSignature.resetRevocationSources();
			jadesSignature.resetTimestampSource();
		}

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker(params);
		if (JAdES_BASELINE_LT.equals(params.getSignatureLevel())) {
			signatureRequirementsChecker.assertExtendToLTLevelPossible(signaturesToExtend);
		}
		signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
		signatureRequirementsChecker.assertCertificateChainValidForLTLevel(signaturesToExtend);

		// Perform signature validation
		ValidationDataContainer validationDataContainer = documentValidator.getValidationData(signatures);

		// Append ValidationData
		for (AdvancedSignature signature : signaturesToExtend) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;
			if (jadesSignature.hasLTAProfile()) {
				continue;
			}

			assertEtsiUComponentsConsistent(jadesSignature.getJws(), params.isBase64UrlEncodedEtsiUComponents());

			JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();

			removeOldCertificateValues(jadesSignature, etsiUHeader);
			removeOldRevocationValues(jadesSignature, etsiUHeader);
			removeLastTimestampAndAnyValidationData(jadesSignature, etsiUHeader);

			ValidationData includedValidationData = incorporateValidationDataForSignature(validationDataContainer, signature, etsiUHeader, params);
			incorporateValidationDataForTimestamps(validationDataContainer, signature, etsiUHeader, params, includedValidationData);
		}
	}

	private void removeOldCertificateValues(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		etsiUHeader.removeComponent(JAdESHeaderParameterNames.X_VALS);
		jadesSignature.resetCertificateSource();
	}

	private void removeOldRevocationValues(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		etsiUHeader.removeComponent(JAdESHeaderParameterNames.R_VALS);
		jadesSignature.resetRevocationSources();
	}

	/**
	 * This method removes the 'tstVd' and 'anyValData' header parameters appearing
	 * in the end of the 'etsiU' unsigned property array.
	 *
	 * @param jadesSignature {@link JAdESSignature}
	 * @param etsiUHeader {@link JAdESEtsiUHeader}
	 */
	protected void removeLastTimestampAndAnyValidationData(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		boolean resetSources = false;
		while (etsiUHeader.removeLastComponent(JAdESHeaderParameterNames.TST_VD, JAdESHeaderParameterNames.ANY_VAL_DATA)) {
			resetSources = true;
		}
		if (resetSources) {
			jadesSignature.resetCertificateSource();
			jadesSignature.resetRevocationSources();
		}
	}

	/**
	 * Incorporates the validation data for the signature validation,
	 * according to the chosen validation data encapsulation mechanism
	 *
	 * @param validationDataContainer {@link ValidationDataContainer}
	 * @param signature {@link AdvancedSignature}
	 * @param etsiUHeader {@link JAdESEtsiUHeader}
	 * @param signatureParameters {@link JAdESSignatureParameters}
	 * @return {@link ValidationData} incorporated validation data
	 */
	private ValidationData incorporateValidationDataForSignature(ValidationDataContainer validationDataContainer,
																 AdvancedSignature signature, JAdESEtsiUHeader etsiUHeader,
																 JAdESSignatureParameters signatureParameters) {
		ValidationData validationDataForInclusion;
		ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy = signatureParameters.getValidationDataEncapsulationStrategy();
		switch (validationDataEncapsulationStrategy) {
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
			case ANY_VALIDATION_DATA_ONLY:
				validationDataForInclusion = validationDataContainer.getAllValidationDataForSignatureForInclusion(signature);
				break;

			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
			case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
				validationDataForInclusion = validationDataContainer.getValidationDataForSignatureForInclusion(signature);
				validationDataForInclusion.addValidationData(validationDataContainer.getValidationDataForCounterSignaturesForInclusion(signature));
				break;

			default:
				throw new UnsupportedOperationException(String.format(
						"The ValidationDataEncapsulationStrategy '%s' is not supported!", validationDataEncapsulationStrategy));
		}

		Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
		Set<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
		Set<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();

		switch (validationDataEncapsulationStrategy) {
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
			case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
				incorporateXVals(etsiUHeader, certificateValuesToAdd, signatureParameters.isBase64UrlEncodedEtsiUComponents());
				incorporateRVals(etsiUHeader, crlsToAdd, ocspsToAdd, signatureParameters.isBase64UrlEncodedEtsiUComponents());
				break;

			case ANY_VALIDATION_DATA_ONLY:
				incorporateAnyValidationData(etsiUHeader, validationDataForInclusion, signatureParameters.isBase64UrlEncodedEtsiUComponents());
				break;

			default:
				throw new UnsupportedOperationException(String.format(
						"The ValidationDataEncapsulationStrategy '%s' is not supported!", validationDataEncapsulationStrategy));
		}
		return validationDataForInclusion;
	}

	/**
	 * Incorporates the validation data for the signature timestamps validation,
	 * according to the chosen validation data encapsulation mechanism
	 *
	 * @param validationDataContainer {@link ValidationDataContainer}
	 * @param signature {@link AdvancedSignature}
	 * @param etsiUHeader {@link JAdESEtsiUHeader}
	 * @param signatureParameters {@link JAdESSignatureParameters}
	 * @param validationDataToExclude {@link ValidationData} to be excluded from incorporation to avoid duplicates
	 */
	private void incorporateValidationDataForTimestamps(ValidationDataContainer validationDataContainer,
			AdvancedSignature signature, JAdESEtsiUHeader etsiUHeader, JAdESSignatureParameters signatureParameters,
			ValidationData validationDataToExclude) {
		ValidationData validationData;
		ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy = signatureParameters.getValidationDataEncapsulationStrategy();
		switch (validationDataEncapsulationStrategy) {
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
				validationData = validationDataContainer.getValidationDataForSignatureTimestampsForInclusion(signature);
				validationData.addValidationData(validationDataContainer.getValidationDataForCounterSignatureTimestampsForInclusion(signature));
				validationData.excludeValidationData(validationDataToExclude);
				incorporateTstValidationData(etsiUHeader, validationData, signatureParameters.isBase64UrlEncodedEtsiUComponents());
				break;

			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
				validationData = validationDataContainer.getValidationDataForSignatureTimestampsForInclusion(signature);
				validationData.excludeValidationData(validationDataToExclude);
				incorporateTstValidationData(etsiUHeader, validationData, signatureParameters.isBase64UrlEncodedEtsiUComponents());

				// incorporate validation data for counter-signature timestamps within AnyValidationData element
				ValidationData counterSigTstValidationData = validationDataContainer.getValidationDataForCounterSignatureTimestampsForInclusion(signature);
				counterSigTstValidationData.excludeValidationData(validationData);
				counterSigTstValidationData.excludeValidationData(validationDataToExclude);
				incorporateAnyValidationData(etsiUHeader, counterSigTstValidationData, signatureParameters.isBase64UrlEncodedEtsiUComponents());
				break;

			case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
				validationData = validationDataContainer.getValidationDataForSignatureTimestampsForInclusion(signature);
				validationData.addValidationData(validationDataContainer.getValidationDataForCounterSignatureTimestampsForInclusion(signature));
				validationData.excludeValidationData(validationDataToExclude);
				incorporateAnyValidationData(etsiUHeader, validationData, signatureParameters.isBase64UrlEncodedEtsiUComponents());
				break;

			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
			case ANY_VALIDATION_DATA_ONLY:
				// skip
				break;

			default:
				throw new UnsupportedOperationException(String.format(
						"The ValidationDataEncapsulationStrategy '%s' is not supported!", validationDataEncapsulationStrategy));
		}
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
	 * Incorporates the provided set of certificates into {@code etsiUHeader}
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} to update
	 * @param certificateValuesToAdd a set of {@link CertificateToken}s to add
	 * @param base64UrlEncoded if members of the etsiU array shall be base64UrlEncoded
	 */
	protected void incorporateXVals(JAdESEtsiUHeader etsiUHeader, Set<CertificateToken> certificateValuesToAdd, boolean base64UrlEncoded) {
		if (Utils.isCollectionNotEmpty(certificateValuesToAdd)) {
			JSONArray xVals = getXVals(certificateValuesToAdd);
			etsiUHeader.addComponent(JAdESHeaderParameterNames.X_VALS, xVals, base64UrlEncoded);
		}
	}

	/**
	 * Builds and returns 'rVals' JsonObject
	 * 
	 * @param crlsToAdd  a set of {@link CRLToken}s to add
	 * @param ocspsToAdd a set of {@link OCSPToken}s to add
	 * @return {@link JsonObject} 'rVals' object
	 */
	protected JsonObject getRVals(Set<CRLToken> crlsToAdd, Set<OCSPToken> ocspsToAdd) {
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
	private JSONArray getCrlVals(Set<CRLToken> crlsToAdd) {
		JSONArray array = new JSONArray();
		for (CRLToken crlToken : crlsToAdd) {
			JSONObject pkiOb = new JSONObject();
			pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(crlToken.getEncoded()));
			array.add(pkiOb);
		}
		return array;
	}

	@SuppressWarnings("unchecked")
	private JSONArray getOcspVals(Set<OCSPToken> ocspsToAdd) {
		JSONArray array = new JSONArray();
		for (OCSPToken ocspToken : ocspsToAdd) {
			JSONObject pkiOb = new JSONObject();
			pkiOb.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(ocspToken.getEncoded()));
			array.add(pkiOb);
		}
		return array;
	}

	/**
	 * Incorporates the provided set of certificates into {@code etsiUHeader}
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} to update
	 * @param crlsToAdd a set of {@link CRLToken}s to add
	 * @param ocspsToAdd a set of {@link OCSPToken}s to add
	 * @param base64UrlEncoded if members of the etsiU array shall be base64UrlEncoded
	 */
	protected void incorporateRVals(JAdESEtsiUHeader etsiUHeader, Set<CRLToken> crlsToAdd,
									Set<OCSPToken> ocspsToAdd, boolean base64UrlEncoded) {
		if (Utils.isCollectionNotEmpty(crlsToAdd) || Utils.isCollectionNotEmpty(ocspsToAdd)) {
			JsonObject rVals = getRVals(crlsToAdd, ocspsToAdd);
			etsiUHeader.addComponent(JAdESHeaderParameterNames.R_VALS, rVals, base64UrlEncoded);
		}
	}

	/**
	 * This method incorporates the 'tstVD' dictionary in the signature
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} containing the unsigned properties list
	 * @param validationDataForInclusion {@link ValidationData} to be included into the signature
	 * @param base64UrlEncoded boolean value whether the etsiUHeader shall be base64url encoded or not
	 */
	protected void incorporateTstValidationData(JAdESEtsiUHeader etsiUHeader, ValidationData validationDataForInclusion, boolean base64UrlEncoded) {
		incorporateValidationData(etsiUHeader, validationDataForInclusion, JAdESHeaderParameterNames.TST_VD, base64UrlEncoded);
	}

	/**
	 * This method incorporates the 'anyValData' dictionary in the signature
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} containing the unsigned properties list
	 * @param validationDataForInclusion {@link ValidationData} to be included into the signature
	 * @param base64UrlEncoded boolean value whether the etsiUHeader shall be base64url encoded or not
	 */
	protected void incorporateAnyValidationData(JAdESEtsiUHeader etsiUHeader, ValidationData validationDataForInclusion, boolean base64UrlEncoded) {
		incorporateValidationData(etsiUHeader, validationDataForInclusion, JAdESHeaderParameterNames.ANY_VAL_DATA, base64UrlEncoded);
	}

	/**
	 * This method incorporates the validation data container in the signature
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} containing the unsigned properties list
	 * @param validationDataForInclusion {@link ValidationData} to be included into the signature
	 * @param headerName {@link String} the name of the property to be incorporated
	 * @param base64UrlEncoded boolean value whether the etsiUHeader shall be base64url encoded or not
	 */
	protected void incorporateValidationData(JAdESEtsiUHeader etsiUHeader, ValidationData validationDataForInclusion,
											 String headerName, boolean base64UrlEncoded) {
		if (!validationDataForInclusion.isEmpty()) {
			JsonObject tstVd = getTstVd(validationDataForInclusion);
			etsiUHeader.addComponent(headerName, tstVd, base64UrlEncoded);
		}
	}

	private JsonObject getTstVd(final ValidationData validationDataForInclusion) {
		Set<CertificateToken> certificateTokens = validationDataForInclusion.getCertificateTokens();
		Set<CRLToken> crlTokens = validationDataForInclusion.getCrlTokens();
		Set<OCSPToken> ocspTokens = validationDataForInclusion.getOcspTokens();

		JsonObject tstVd = new JsonObject();
		if (Utils.isCollectionNotEmpty(certificateTokens)) {
			JSONArray xVals = getXVals(certificateTokens);
			tstVd.put(JAdESHeaderParameterNames.X_VALS, xVals);
		}
		if (Utils.isCollectionNotEmpty(crlTokens) || Utils.isCollectionNotEmpty(ocspTokens)) {
			JsonObject rVals = getRVals(crlTokens, ocspTokens);
			tstVd.put(JAdESHeaderParameterNames.R_VALS, rVals);
		}
		return tstVd;
	}

	private List<AdvancedSignature> getExtendToLTLevelSignatures(List<AdvancedSignature> signatures, JAdESSignatureParameters parameters) {
		final List<AdvancedSignature> toBeExtended = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			if (ltLevelExtensionRequired(signature, parameters)) {
				toBeExtended.add(signature);
			}
		}
		return toBeExtended;
	}

	private boolean ltLevelExtensionRequired(AdvancedSignature signature, JAdESSignatureParameters parameters) {
		return JAdES_BASELINE_LT.equals(parameters.getSignatureLevel()) || !signature.hasLTAProfile();
	}

}
