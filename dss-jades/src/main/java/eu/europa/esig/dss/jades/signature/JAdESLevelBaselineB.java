package eu.europa.esig.dss.jades.signature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.X509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

/**
 * The class builds a JOSE header according to EN 119-182
 *
 */
public class JAdESLevelBaselineB {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESLevelBaselineB.class);
	
	private final CertificateVerifier certificateVerifier;
	private final JAdESSignatureParameters parameters;
	private final DSSDocument signingDocument;
	
	/* JOSE Header map representation */
	private Map<String, Object> signedProperties = new LinkedHashMap<>();
	
	/* Contains all critical header names that will be incorporated into the signature */
	private List<String> criticalHeaderNames = new ArrayList<>();
	
	public JAdESLevelBaselineB(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, final DSSDocument signingDocument) {
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
		this.signingDocument = signingDocument;
	}
	
	public Map<String, Object> getSignedProperties() {
		// RFC 7515 headers
		incorporateSignatureAlgorithm();
		incorporateContentType();
		incorporateKeyIdentifier();
		incorporateSigningCertificateUri();
		incorporateSigningCertificate();
		incorporateCertificateChain();
		incorporateType();
		
		// EN 119-182 headers
		incorporateSigningTime();
		incorporateSignerCommitment();
		incorporateSignatureProductionPlace();
		incorporateSignerRoles();
		incorporateContentTimestamps();
		incorporateSignaturePolicy();
		incorporateDetachedContents();
		
		// must be executed the last
		incorporateCritical();
		
		return signedProperties;
	}

	/**
	 * Incorporates 5.1.2 The alg (X.509 URL) header parameter
	 */
	private void incorporateSignatureAlgorithm() {
		addHeader(HeaderParameterNames.ALGORITHM, parameters.getSignatureAlgorithm().getJWAId());
	}

	/**
	 * Incorporates 5.1.3 The cty (content type) header parameter
	 */
	private void incorporateContentType() {
		if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			// not applicable for detached signatures (see EN 119-182 ch.5.1.3)
			return;
		}
		MimeType mimeType = signingDocument.getMimeType();
		if (mimeType != null) {
			String mimeTypeString = getRFC7515ConformantMimeTypeString(mimeType);
			addHeader(HeaderParameterNames.CONTENT_TYPE, mimeTypeString);
		}
	}
	
	private String getRFC7515ConformantMimeTypeString(MimeType mimeType) {
		/*
		 * RFC 7515 :
		 * To keep messages compact in common situations, it is RECOMMENDED that
		 * producers omit an "application/" prefix of a media type value in a
		 * "cty" Header Parameter when no other '/' appears in the media type
		 * value.
		 */
		String mimeTypeString = mimeType.getMimeTypeString();
		String shortMimeTypeString = DSSUtils.stripFirstLeadingOccurance(mimeTypeString, JAdESUtils.MIME_TYPE_APPLICATION_PREFIX);
		if (!shortMimeTypeString.contains("/")) {
			return shortMimeTypeString;
		} else {
			// return original if contains other '/'
			return mimeTypeString;
		}
	}

	/**
	 * Incorporates 5.1.4 The kid (key identifier) header parameter
	 */
	protected void incorporateKeyIdentifier() {
		if (parameters.getSigningCertificate() == null) {
			return;
		}
		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(parameters.getSigningCertificate());
		String issuerBase64 = Utils.toBase64(DSSASN1Utils.getDEREncoded(issuerSerial));
		addHeader(HeaderParameterNames.KEY_ID, issuerBase64);
	}

	/**
	 * Incorporates 5.1.5 The x5u (X.509 URL) header parameter
	 */
	protected void incorporateSigningCertificateUri() {
		// not supported
	}
	
	/**
	 * Incorporates 5.1.7 The x5t#S256 (X.509 Certificate SHA-256 Thumbprint) header parameter
	 * or 5.2.2	The x5t#o (X509 certificate digest) header parameter
	 */
	protected void incorporateSigningCertificate() {
		if (parameters.getSigningCertificate() == null) {
			return;
		}
		
		DigestAlgorithm signingCertificateDigestMethod = parameters.getSigningCertificateDigestMethod();
		if (DigestAlgorithm.SHA256.equals(signingCertificateDigestMethod)) {
			incorporateSiginingCertificateSha256Thumbprint(parameters.getSigningCertificate());
			
		} else {
			List<CertificateToken> certificates = Arrays.asList(parameters.getSigningCertificate());
			incorporateSigningCertificateOtherDigestReferences(certificates, signingCertificateDigestMethod);
		}
	}

	
	/**
	 * Incorporates 5.1.7 The x5t#S256 (X.509 Certificate SHA-256 Thumbprint) header parameter
	 */
	protected void incorporateSiginingCertificateSha256Thumbprint(CertificateToken signingCertificate) {
		String x5tS256 = X509Util.x5tS256(signingCertificate.getCertificate());
		addHeader(HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT, x5tS256);
	}

	/**
	 * Incorporates 5.2.2 The x5t#o (X509 certificate digest) header parameter
	 */
	protected void incorporateSigningCertificateOtherDigestReferences(List<CertificateToken> certificates, DigestAlgorithm digestAlgorithm) {
		List<JSONObject> digAndValues = new ArrayList<>();
		for (CertificateToken certificateToken : certificates) {
			byte[] digestValue = certificateToken.getDigest(digestAlgorithm);
			JSONObject digAndVal = JAdESUtils.getDigAlgValObject(digestValue, digestAlgorithm);
			digAndValues.add(digAndVal);
		}
		addCriticalHeader(JAdESHeaderParameterNames.X5T_O, new JSONArray(digAndValues));
	}
	
	/**
	 * Incorporates 5.1.8 The x5c (X.509 Certificate Chain) header parameter
	 */
	protected void incorporateCertificateChain() {
		if (!parameters.isIncludeCertificateChain() || parameters.getSigningCertificate() == null) {
			return;
		}
		
		BaselineBCertificateSelector certificateSelector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = certificateSelector.getCertificates();
		
		List<String> base64Certificates = new ArrayList<>();
		for (CertificateToken certificateToken : certificates) {
			base64Certificates.add(Utils.toBase64(certificateToken.getEncoded()));
		}
		addHeader(HeaderParameterNames.X509_CERTIFICATE_CHAIN, new JSONArray(base64Certificates));
	}
	
	/**
	 * Incorporates 5.1.9 The crit (critical) header parameter
	 */
	private void incorporateCritical() {
		addHeader(HeaderParameterNames.CRITICAL, new JSONArray(criticalHeaderNames));
	}

	/**
	 * Incorporates RFC 7515 : 4.1.9. "typ" (Type) Header Parameter
	 */
	private void incorporateType() {
		if (parameters.isIncludeSignatureType()) {
			// TODO : add a support for JSON Serialization signature type
			MimeType signatureMimeType = MimeType.JOSE;
			String type = getRFC7515ConformantMimeTypeString(signatureMimeType);
			addHeader(HeaderParameterNames.TYPE, type);
		}
	}
	
	/**
	 * Incorporates 5.2.1 The sigT (claimed signing time) header parameter
	 */
	private void incorporateSigningTime() {
		final Date signingDate = parameters.bLevel().getSigningDate();
		final String stringSigningTime = DSSUtils.formatDateToRFC(signingDate);
		
		addCriticalHeader(JAdESHeaderParameterNames.SIG_T, stringSigningTime);
	}

	/**
	 * Incorporates 5.2.3 The srCm (signer commitment) header parameter
	 */
	protected void incorporateSignerCommitment() {
		if (Utils.isCollectionEmpty(parameters.bLevel().getCommitmentTypeIndications())) {
			return;
		}
		// TODO : is only one allowed ?
		if (parameters.bLevel().getCommitmentTypeIndications().size() > 1) {
			LOG.warn("The current version supports only one CommitmentType indication. "
					+ "All indications except the first one are omitted.");
		}
		CommitmentType commitmentType = parameters.bLevel().getCommitmentTypeIndications().iterator().next();
		JSONObject oidObject = JAdESUtils.getOidObject(commitmentType.getOid()); // Only simple Oid form is supported
		
		Map<String, Object> srCmParams = new HashMap<>();
		srCmParams.put(JAdESHeaderParameterNames.COMM_ID, oidObject);
		// TODO : Qualifiers are not supported
		// srCmParams.put(JAdESHeaderParameterNames.COMM_QUALS, quals);
		
		JSONObject srCmParamsObject = new JSONObject(srCmParams);
		
		addCriticalHeader(JAdESHeaderParameterNames.SR_CM, srCmParamsObject);
	}

	/**
	 * Incorporates 5.2.4 The sigPl (signature production place) header parameter
	 */
	private void incorporateSignatureProductionPlace() {
		SignerLocation signerProductionPlace = parameters.bLevel().getSignerLocation();
		if (signerProductionPlace != null) {
			
			String city = signerProductionPlace.getLocality();
			String streetAddress = signerProductionPlace.getStreet();
			String stateOrProvince = signerProductionPlace.getStateOrProvince();
			String postalCode = signerProductionPlace.getPostalCode();
			String country = signerProductionPlace.getCountry();
			
			// sigPlace must have at least one property
			if (Utils.isAtLeastOneStringNotEmpty(city, streetAddress, stateOrProvince, postalCode, country)) {
				Map<String, Object> sigPlaceMap = new HashMap<>();
				
				if (city != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.CITY, city);
				}
				if (streetAddress != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.STR_ADDR, streetAddress);
				}
				if (stateOrProvince != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.STAT_PROV, stateOrProvince);
				}
				if (postalCode != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.POST_CODE, postalCode);
				}
				if (country != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.COUNTRY, country);
				}
				
				addCriticalHeader(JAdESHeaderParameterNames.SIG_PL, new JSONObject(sigPlaceMap));
				
			} else {
				LOG.warn("SignerLocation is defined, but does not contain any properties! 'SigPlace' attribute requires at least one property!");
				
			}
		}
	}

	/**
	 * Incorporates 5.2.5 The srAts (signer attributes) header parameter
	 */
	private void incorporateSignerRoles() {
		if (Utils.isCollectionEmpty(parameters.bLevel().getClaimedSignerRoles())) {
			return;
		}
		List<String> claimedSignerRoles = parameters.bLevel().getClaimedSignerRoles();
		// TODO : is base64 required ?
		List<String> base64Values = toBase64Strings(claimedSignerRoles);
		
		JSONArray claimed = new JSONArray(base64Values);
		
		Map<String, Object> srAtsParams = new HashMap<>();
		srAtsParams.put(JAdESHeaderParameterNames.CLAIMED, claimed);
		// TODO : certified and signedAssertions are not supported
		// srAtsParams.put(JAdESHeaderParameterNames.CERTIFIED, certified);
		// srAtsParams.put(JAdESHeaderParameterNames.SIGNED_ASSERTIONS, signedAssertions);
		JSONObject srAtsParamsObject = new JSONObject(srAtsParams);
		
		addCriticalHeader(JAdESHeaderParameterNames.SR_ATS, srAtsParamsObject);
	}
	
	private List<String> toBase64Strings(List<String> strings) {
		List<String> base64Strings = new ArrayList<>();
		for (String str : strings) {
			if (str != null) {
				base64Strings.add(Utils.toBase64(str.getBytes()));
			}
		}
		return base64Strings;
	}

	/**
	 * Incorporates 5.2.6 The adoTst (signed data time-stamp) header parameter
	 */
	private void incorporateContentTimestamps() {
		if (Utils.isCollectionEmpty(parameters.getContentTimestamps())) {
			return;
		}
		
		// canonicalization shall be null for content timestamps (see 5.2.6)
		JSONObject tstContainer = JAdESUtils.getTstContainer(parameters.getContentTimestamps(), null); 
		addCriticalHeader(JAdESHeaderParameterNames.ADO_TST, tstContainer);
	}

	/**
	 * Incorporates 5.2.7 The sigPId (signature policy identifier) header parameter
	 */
	private void incorporateSignaturePolicy() {
		Policy signaturePolicy = parameters.bLevel().getSignaturePolicy();
		if (signaturePolicy != null) {
			String signaturePolicyId = signaturePolicy.getId();
			if (Utils.isStringEmpty(signaturePolicyId)) {
				// see EN 119-182 ch. 5.2.7.1 Semantics and syntax ('id' is required)
				LOG.warn("Implicit policy is not allowed in JAdES! The signaturePolicyId attribute is required!");
				return;
			}
			
			Map<String, Object> sigPIdParams = new HashMap<>();
			
			JSONObject oid = JAdESUtils.getOidObject(signaturePolicyId, signaturePolicy.getDescription(), null);
			sigPIdParams.put(JAdESHeaderParameterNames.ID, oid);
			
			if ((signaturePolicy.getDigestValue() != null) && (signaturePolicy.getDigestAlgorithm() != null)) {
				JSONObject digAlgVal = JAdESUtils.getDigAlgValObject(signaturePolicy.getDigestValue(), signaturePolicy.getDigestAlgorithm());
				sigPIdParams.put(JAdESHeaderParameterNames.HASH_AV, digAlgVal);
			}

			// TODO : sigPIdParams.put(JAdESHeaderParameterNames.HASH_PSP, value) // 'hashPSp' the specification is not clear
			
			List<JSONObject> signaturePolicyQualifiers = getSignaturePolicyQualifiers(signaturePolicy);
			if (Utils.isCollectionNotEmpty(signaturePolicyQualifiers)) {
				sigPIdParams.put(JAdESHeaderParameterNames.SIG_PQUALS, signaturePolicyQualifiers);
			}
			
			addCriticalHeader(JAdESHeaderParameterNames.SIG_PID, new JSONObject(sigPIdParams));
		}
	}

	// TODO : refactor Qualifiers to follow the schema (as well as in XAdES)
	private List<JSONObject> getSignaturePolicyQualifiers(Policy signaturePolicy) {
		// TODO : 'sigPQuals' specification is not clear
		List<JSONObject> sigPQualifiers = new ArrayList<>();

		String spuri = signaturePolicy.getSpuri();
		if (Utils.isStringNotEmpty(spuri)) {
			/* 
			 * Intermediate object is created in order to allow multiple instances of the same qualifiers
			 * 
			 * EN 119-182 ch. 5.2.7.1 Semantics and syntax:
			 * The sigPQuals member may contain one or more qualifiers of the same type.
			 */
			Map<String, Object> spURI = new HashMap<>();
			spURI.put(JAdESHeaderParameterNames.SP_URI, spuri);
			sigPQualifiers.add(new JSONObject(spURI));
		}
		
		// TODO : other policy qualifiers are not supported
		
		return sigPQualifiers;
	}

	/**
	 * Incorporates 5.2.8 The sigD header parameter
	 */
	private void incorporateDetachedContents() {
		// TODO : the standard is not clear
	}
	
	/**
	 * Adds a new critical header property
	 * 
	 * @param headerName {@link String} name of a header to incorporate
	 * @param value of the header property
	 */
	protected void addCriticalHeader(String headerName, Object value) {
		addHeader(headerName, value);
		criticalHeaderNames.add(headerName);
	}
	
	/**
	 * Adds a new header to the {@code signedProperties} map
	 * 
	 * @param headerName {@link String} name of the header
	 * @param value {@link Object} to add
	 */
	protected void addHeader(String headerName, Object value) {
		signedProperties.put(headerName, value);
	}

}
