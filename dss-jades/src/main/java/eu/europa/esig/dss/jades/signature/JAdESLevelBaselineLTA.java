package eu.europa.esig.dss.jades.signature;

import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JsonObject;
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

public class JAdESLevelBaselineLTA extends JAdESLevelBaselineLT {

	public JAdESLevelBaselineLTA(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}
	
	@Override
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		super.extendSignature(jadesSignature, params);
		
		assertExtendSignatureToLTAPossible(jadesSignature, params);
		checkSignatureIntegrity(jadesSignature);
		
		List<Object> unsignedProperties = getUnsignedProperties(jadesSignature);
		
		if (jadesSignature.hasLTAProfile()) {
			// must be executed before data removing
			final ValidationContext validationContext = jadesSignature.getSignatureValidationContext(certificateVerifier);
			removeLastTimestampValidationData(unsignedProperties);
			
			final ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(jadesSignature, validationContext);
			addTstVd(validationDataForInclusion, unsignedProperties);
		}
		
		TimestampBinary timestampBinary = getArchiveTimestamp(jadesSignature, params);
		addArcTst(timestampBinary, unsignedProperties, params.getArchiveTimestampParameters());
		
	}
	@SuppressWarnings("unchecked")
	private void removeLastTimestampValidationData(List<Object> unsignedProperties) {
		ListIterator<Object> iterator = unsignedProperties.listIterator(unsignedProperties.size());
		while (iterator.hasPrevious()) {
			Map<String, Object> unsignedProperty = (Map<String, Object>) iterator.previous();
			Object tstVd = unsignedProperty.get(JAdESHeaderParameterNames.TST_VD);
			if (tstVd != null) {
				iterator.remove();
				return;
			}
		}
	}

	@SuppressWarnings("unchecked")
	protected void addTstVd(final ValidationDataForInclusion validationDataForInclusion, List<Object> unsignedProperties) {
		Set<CertificateToken> certificateTokens = validationDataForInclusion.getCertificateTokens();
		List<CRLToken> crlTokens = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspTokens = validationDataForInclusion.getOcspTokens();
		
		if (Utils.isCollectionEmpty(certificateTokens) && Utils.isCollectionEmpty(crlTokens) && Utils.isCollectionEmpty(ocspTokens)) {
			// nothing to add
			return;
		}
		
		JSONObject tstVd = new JSONObject();
		
		if (Utils.isCollectionNotEmpty(certificateTokens)) {
			JSONArray xVals = getXVals(certificateTokens);
			tstVd.put(JAdESHeaderParameterNames.X_VALS, xVals);
		}
		
		if (Utils.isCollectionNotEmpty(crlTokens) || Utils.isCollectionNotEmpty(ocspTokens)) {
			JSONObject rVals = getRVals(crlTokens, ocspTokens);
			tstVd.put(JAdESHeaderParameterNames.R_VALS, rVals);
		}
		
		// Content tst'data is included on LT-level, therefore should not be included on LTA
		
		JSONObject tstVdItem = new JSONObject();
		tstVdItem.put(JAdESHeaderParameterNames.TST_VD, tstVd);
		
		unsignedProperties.add(tstVdItem);
		
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

	@SuppressWarnings("unchecked")
	protected void addArcTst(TimestampBinary timestampBinary, List<Object> unsignedProperties, JAdESTimestampParameters params) {
		JSONObject arcTst = new JSONObject();
		
		String canonicalizationMethod = params.getCanonicalizationMethod();
		JsonObject tstContainer = DSSJsonUtils.getTstContainer(Collections.singletonList(timestampBinary), canonicalizationMethod);
		arcTst.put(JAdESHeaderParameterNames.ARC_TST, tstContainer);
		
		unsignedProperties.add(arcTst);
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTAPossible(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		assertDetachedDocumentsContainBinaries(params);
		checkEtsiUContentUnicity(jadesSignature);
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
		String errorMessage = "Unsupported 'etsiU' container structure! Extension is not possible.";
		
		Boolean base64UrlEncoded = null;
		List<Object> etsiU = DSSJsonUtils.getEtsiU(jadesSignature.getJws());
		for (Object unsignedProperty : etsiU) {
			boolean currentObjectBase64UrlEncoded = false;
			
			if (!(unsignedProperty instanceof Map<?, ?>)) {
				throw new DSSException(errorMessage);
			}
			Map<?, ?> propertyMap = (Map<?, ?>) unsignedProperty;
			if (propertyMap.size() != 1) {
				throw new DSSException(errorMessage);
			}
			Object propertyValue = propertyMap.values().iterator().next();
			if (propertyValue instanceof String && DSSJsonUtils.isBase64UrlEncoded((String)propertyValue)) {
				currentObjectBase64UrlEncoded = true;
			}
			if (base64UrlEncoded == null) {
				base64UrlEncoded = currentObjectBase64UrlEncoded;
			}
			if (base64UrlEncoded != currentObjectBase64UrlEncoded) {
				throw new DSSException(errorMessage);
			}
		}
	}

}
