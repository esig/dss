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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
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
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		super.extendSignature(jadesSignature, params);
		
		assertExtendSignatureToLTAPossible(jadesSignature, params);
		checkSignatureIntegrity(jadesSignature);
		
		JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
		if (jadesSignature.hasLTAProfile()) {
			// must be executed before data removing
			final ValidationContext validationContext = jadesSignature.getSignatureValidationContext(certificateVerifier);
			etsiUHeader.removeLastComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.TST_VD);
			
			final ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(jadesSignature, validationContext);
			if (!validationDataForInclusion.isEmpty()) {
				JsonObject tstVd = getTstVd(validationDataForInclusion);
				etsiUHeader.addComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.TST_VD, tstVd,
						params.isBase64UrlEncodedEtsiUComponents());
			}
		}
		
		TimestampBinary timestampBinary = getArchiveTimestamp(jadesSignature, params);
		JsonObject arcTst = DSSJsonUtils.getTstContainer(Collections.singletonList(timestampBinary),
				params.getArchiveTimestampParameters().getCanonicalizationMethod());
		etsiUHeader.addComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.ARC_TST, arcTst,
				params.isBase64UrlEncodedEtsiUComponents());
		
	}

	private JsonObject getTstVd(final ValidationDataForInclusion validationDataForInclusion) {
		Set<CertificateToken> certificateTokens = validationDataForInclusion.getCertificateTokens();
		List<CRLToken> crlTokens = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspTokens = validationDataForInclusion.getOcspTokens();
		
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
		byte[] messageImprint = jadesSignature.getTimestampSource().getArchiveTimestampData(canonicalizationMethod);
		
		byte[] digest = DSSUtils.digest(digestAlgorithmForTimestampRequest, messageImprint);
		return tspSource.getTimeStampResponse(digestAlgorithmForTimestampRequest, digest);
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
			throw new DSSException(
					"Unable to extend JAdES-LTA level. Clear 'etsiU' incorporation requires a canonicalization method!");
		}
	}

	private void assertDetachedDocumentsContainBinaries(JAdESSignatureParameters params) {
		List<DSSDocument> detachedContents = params.getDetachedContents();
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			for (DSSDocument detachedDocument : detachedContents) {
				if (detachedDocument instanceof DigestDocument) {
					throw new DSSException("JAdES-LTA with All data Timestamp requires complete binaries of signed documents! "
							+ "Extension with a DigestDocument is not possible.");
				}
			}
		}
	}
	
	private void checkEtsiUContentUnicity(JAdESSignature jadesSignature) {
		List<Object> etsiU = DSSJsonUtils.getEtsiU(jadesSignature.getJws());
		if (!DSSJsonUtils.checkComponentsUnicity(etsiU)) {
			throw new DSSException("Unsupported 'etsiU' container structure! Extension is not possible.");
		}
	}

}
