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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import org.jose4j.json.internal.json_simple.JSONArray;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Creates an LTA-level of a JAdES signature
 */
public class JAdESLevelBaselineLTA extends JAdESLevelBaselineLT {

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public JAdESLevelBaselineLTA(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}
	
	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures, JAdESSignatureParameters params) {
		super.extendSignatures(signatures, params);

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker(params);
		signatureRequirementsChecker.assertSignaturesValid(signatures);

		boolean addTimestampValidationData = false;

		for (AdvancedSignature signature : signatures) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;
			assertEtsiUComponentsConsistent(jadesSignature.getJws(), params.isBase64UrlEncodedEtsiUComponents());
			assertExtendSignatureToLTAPossible(jadesSignature, params);

			if (jadesSignature.hasLTAProfile()) {
				addTimestampValidationData = true;
			}
		}

		// Perform signature validation
		ValidationDataContainer validationDataContainer = null;
		if (addTimestampValidationData) {
			validationDataContainer = documentValidator.getValidationData(signatures);
		}

		for (AdvancedSignature signature : signatures) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;
			JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();

			if (jadesSignature.hasLTAProfile() && addTimestampValidationData) {
				removeLastTimestampValidationData(jadesSignature, etsiUHeader);

				final ValidationData validationDataForInclusion = validationDataContainer.getCompleteValidationDataForSignature(signature);
				if (!validationDataForInclusion.isEmpty()) {
					JsonObject tstVd = getTstVd(validationDataForInclusion);
					etsiUHeader.addComponent(JAdESHeaderParameterNames.TST_VD, tstVd, params.isBase64UrlEncodedEtsiUComponents());
				}
			}

			TimestampBinary timestampBinary = getArchiveTimestamp(jadesSignature, params);
			JsonObject arcTst = DSSJsonUtils.getTstContainer(Collections.singletonList(timestampBinary),
					params.getArchiveTimestampParameters().getCanonicalizationMethod());
			etsiUHeader.addComponent(JAdESHeaderParameterNames.ARC_TST, arcTst,
					params.isBase64UrlEncodedEtsiUComponents());
		}
	}

	private void removeLastTimestampValidationData(JAdESSignature jadesSignature, JAdESEtsiUHeader etsiUHeader) {
		etsiUHeader.removeLastComponent(JAdESHeaderParameterNames.TST_VD);
		jadesSignature.resetCertificateSource();
		jadesSignature.resetRevocationSources();
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
	
	private TimestampBinary getArchiveTimestamp(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		JAdESTimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
		DigestAlgorithm digestAlgorithmForTimestampRequest = archiveTimestampParameters.getDigestAlgorithm();
		// TODO : Support canonicalization
		String canonicalizationMethod = archiveTimestampParameters.getCanonicalizationMethod();

		final DSSMessageDigest messageDigest = jadesSignature.getTimestampSource().getArchiveTimestampData(
				digestAlgorithmForTimestampRequest, canonicalizationMethod);
		return tspSource.getTimeStampResponse(digestAlgorithmForTimestampRequest, messageDigest.getValue());
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTAPossible(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		checkArchiveTimestampParameters(params);
		assertDetachedDocumentsContainBinaries(params);
		checkEtsiUContentUnicity(jadesSignature);
	}
	
	private void checkArchiveTimestampParameters(JAdESSignatureParameters params) {
		JAdESTimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
		if (!params.isBase64UrlEncodedEtsiUComponents()
				&& Utils.isStringEmpty(archiveTimestampParameters.getCanonicalizationMethod())) {
			throw new IllegalInputException(
					"Unable to extend JAdES-LTA level. Clear 'etsiU' incorporation requires a canonicalization method!");
		}
	}

	private void assertDetachedDocumentsContainBinaries(JAdESSignatureParameters params) {
		List<DSSDocument> detachedContents = params.getDetachedContents();
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			for (DSSDocument detachedDocument : detachedContents) {
				if (detachedDocument instanceof DigestDocument) {
					throw new IllegalArgumentException("JAdES-LTA with All data Timestamp requires complete binaries of signed documents! "
							+ "Extension with a DigestDocument is not possible.");
				}
			}
		}
	}
	
	private void checkEtsiUContentUnicity(JAdESSignature jadesSignature) {
		List<Object> etsiU = DSSJsonUtils.getEtsiU(jadesSignature.getJws());
		if (!DSSJsonUtils.checkComponentsUnicity(etsiU)) {
			throw new IllegalInputException("Unsupported 'etsiU' container structure! Extension is not possible.");
		}
	}

}
