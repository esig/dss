package eu.europa.esig.dss.jades.signature;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.X509Util;

import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * The class builds a JOSE header according to EN 119-182
 *
 */
public class JAdESLevelBaselineB {
	
	private final CertificateVerifier certificateVerifier;
	private final JAdESSignatureParameters parameters;
	private final List<DSSDocument> documentsToSign;
	
	/* JOSE Header map representation */
	private Map<String, Object> signedProperties = new LinkedHashMap<>();
	
	public JAdESLevelBaselineB(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, final List<DSSDocument> documentsToSign) {
		Objects.requireNonNull(certificateVerifier, "certificateVerifier must not be null!");
		Objects.requireNonNull(certificateVerifier, "signatureParameters must be defined!");
		if (Utils.isCollectionEmpty(documentsToSign)) {
			throw new DSSException("Documents to sign must be provided!");
		}
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
		this.documentsToSign = documentsToSign;
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
		
		// RFC 7797
		incorporateB64();
		
		// EN 119-182 headers
		incorporateSigningTime();
		incorporateX509CertificateDigests();
		incorporateSignerCommitments();
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
		String id = parameters.getSignatureAlgorithm().getJWAId();
		if (Utils.isStringNotEmpty(id)) {
			addHeader(HeaderParameterNames.ALGORITHM, id);
		} else {
			throw new DSSException(String.format("The defined signature algorithm '%s' is not supported!", parameters.getSignatureAlgorithm()));
		}
	}

	/**
	 * Incorporates 5.1.3 The cty (content type) header parameter
	 */
	private void incorporateContentType() {
		if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			// not applicable for detached signatures (see EN 119-182 ch.5.1.3)
			return;
		}
		MimeType mimeType = documentsToSign.get(0).getMimeType();
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
		String shortMimeTypeString = DSSUtils.stripFirstLeadingOccurance(mimeTypeString, DSSJsonUtils.MIME_TYPE_APPLICATION_PREFIX);
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
		addHeader(HeaderParameterNames.KEY_ID, DSSJsonUtils.generateKid(parameters.getSigningCertificate()));
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
		CertificateToken signingCertificate = parameters.getSigningCertificate();
		if (signingCertificate == null) {
			return;
		}
		
		DigestAlgorithm signingCertificateDigestMethod = parameters.getSigningCertificateDigestMethod();
		if (DigestAlgorithm.SHA256.equals(signingCertificateDigestMethod)) {
			incorporateSiginingCertificateSha256Thumbprint(signingCertificate);
		} else {
			incorporateSigningCertificateOtherDigestReference(signingCertificate, signingCertificateDigestMethod);
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
		/*
		 * RFC 7515 : "4.1.11.  "crit" (Critical) Header Parameter"
		 * 
		 * Producers MUST NOT include Header Parameter names defined by this specification
		 * or [JWA] for use with JWS, duplicate names, or names that do not
		 * occur as Header Parameter names within the JOSE Header in the "crit"
		 * list. Producers MUST NOT use the empty list "[]" as the "crit" value.
		 */
		Set<String> criticalHeaderExceptions = DSSJsonUtils.getCriticalHeaderExceptions();
		
		List<String> criticalHeaderNames = new ArrayList<>();
		for (String header : signedProperties.keySet()) {
			if (!criticalHeaderExceptions.contains(header)) {
				criticalHeaderNames.add(header);
			}
		}
		if (Utils.isCollectionNotEmpty(criticalHeaderNames)) {
			addHeader(HeaderParameterNames.CRITICAL, new JSONArray(criticalHeaderNames));
		}
	}

	/**
	 * Incorporates RFC 7515 : 4.1.9. "typ" (Type) Header Parameter
	 */
	private void incorporateType() {
		if (parameters.isIncludeSignatureType()) {
			
			/*
			 * RFC 7515 : 4.1.9. "typ" (Type) Header Parameter
			 * 
			 * The "typ" value "JOSE" can be used by applications to indicate that
			 * this object is a JWS or JWE using the JWS Compact Serialization or
			 * the JWE Compact Serialization.  The "typ" value "JOSE+JSON" can be
			 * used by applications to indicate that this object is a JWS or JWE
			 * using the JWS JSON Serialization or the JWE JSON Serialization.
			 */
			
			MimeType signatureMimeType;
			switch (parameters.getJwsSerializationType()) {
				case COMPACT_SERIALIZATION:
					signatureMimeType = MimeType.JOSE;
					break;
				case JSON_SERIALIZATION:
				case FLATTENED_JSON_SERIALIZATION:
					signatureMimeType = MimeType.JOSE_JSON;
					break;
				default:
					throw new DSSException(String.format("The given JWS serialization type '%s' is not supported!", 
							parameters.getJwsSerializationType()));
			}
			
			String type = getRFC7515ConformantMimeTypeString(signatureMimeType);
			addHeader(HeaderParameterNames.TYPE, type);
		}
	}
	
	/**
	 * Incorporates RFC 7797 Unencoded Payload Option
	 */
	protected void incorporateB64() {
		// incorporate only with FALSE value
		if (!parameters.isBase64UrlEncodedPayload()) {
			byte[] payloadBytes = getPayloadBytes();
			// see RFC 7797 (only for compact format not detached payload shall be uri-safe)
			if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging()) &&
					JWSSerializationType.COMPACT_SERIALIZATION.equals(parameters.getJwsSerializationType()) &&
					Utils.isArrayNotEmpty(payloadBytes) && !DSSJsonUtils.isUrlSafePayload(new String(payloadBytes))) {
				throw new DSSException("The payload contains not URL-safe characters! "
						+ "With Unencoded Payload ('b64' = false) only ASCII characters in ranges %x20-2D and %x2F-7E are allowed!");
			}
			addHeader(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
		}
	}
	
	/**
	 * Incorporates 5.2.1 The sigT (claimed signing time) header parameter
	 */
	protected void incorporateSigningTime() {
		final Date signingDate = parameters.bLevel().getSigningDate();
		final String stringSigningTime = DSSUtils.formatDateToRFC(signingDate);
		
		addHeader(JAdESHeaderParameterNames.SIG_T, stringSigningTime);
	}

	/**
	 * Incorporates 5.2.2.2 The x5t#o (X509 certificate digest) header parameter
	 */
	protected void incorporateSigningCertificateOtherDigestReference(CertificateToken signingCertificate,
			DigestAlgorithm digestAlgorithm) {
		byte[] digestValue = signingCertificate.getDigest(digestAlgorithm);
		JsonObject digAndVal = DSSJsonUtils.getDigAlgValObject(digestValue, digestAlgorithm);

		addHeader(JAdESHeaderParameterNames.X5T_O, digAndVal);
	}

	/**
	 * Incorporates 5.2.2.3 The sigX5ts (X509 certificates digests)
	 */
	protected void incorporateX509CertificateDigests() {
		// addition of multiple signing certificate references are not supported in DSS
	}

	/**
	 * Incorporates 5.2.3 The srCms (signer commitments) header parameter
	 */
	protected void incorporateSignerCommitments() {
		if (Utils.isCollectionEmpty(parameters.bLevel().getCommitmentTypeIndications())) {
			return;
		}
		
		List<JsonObject> srCms = new ArrayList<>();
		
		for (CommitmentType commitmentType : parameters.bLevel().getCommitmentTypeIndications()) {
			JsonObject oidObject = DSSJsonUtils.getOidObject(commitmentType); // Only simple Oid form is supported

			Map<String, Object> srCmParams = new LinkedHashMap<>();
			srCmParams.put(JAdESHeaderParameterNames.COMM_ID, oidObject);

			// Qualifiers are not supported
			// srCmParams.put(JAdESHeaderParameterNames.COMM_QUALS, quals);

			srCms.add(new JsonObject(srCmParams));
		}
		
		addHeader(JAdESHeaderParameterNames.SR_CMS, new JSONArray(srCms));
	}

	/**
	 * Incorporates 5.2.4 The sigPl (signature production place) header parameter
	 */
	private void incorporateSignatureProductionPlace() {
		SignerLocation signerProductionPlace = parameters.bLevel().getSignerLocation();
		if (signerProductionPlace != null && !signerProductionPlace.isEmpty()) {
			
			String city = signerProductionPlace.getLocality();
			String streetAddress = signerProductionPlace.getStreetAddress();
			String stateOrProvince = signerProductionPlace.getStateOrProvince();
			String postOfficeBoxNumber = signerProductionPlace.getPostOfficeBoxNumber();
			String postalCode = signerProductionPlace.getPostalCode();
			String country = signerProductionPlace.getCountry();

			Map<String, Object> sigPlaceMap = new LinkedHashMap<>();

			if (country != null) {
				sigPlaceMap.put(JAdESHeaderParameterNames.ADDRESS_COUNTRY, country);
			}
			if (city != null) {
				sigPlaceMap.put(JAdESHeaderParameterNames.ADDRESS_LOCALITY, city);
			}
			if (stateOrProvince != null) {
				sigPlaceMap.put(JAdESHeaderParameterNames.ADDRESS_REGION, stateOrProvince);
			}
			if (postOfficeBoxNumber != null) {
				sigPlaceMap.put(JAdESHeaderParameterNames.POST_OFFICE_BOX_NUMBER, postOfficeBoxNumber);
			}
			if (postalCode != null) {
				sigPlaceMap.put(JAdESHeaderParameterNames.POSTAL_CODE, postalCode);
			}
			if (streetAddress != null) {
				sigPlaceMap.put(JAdESHeaderParameterNames.STREET_ADDRESS, streetAddress);
			}

			addHeader(JAdESHeaderParameterNames.SIG_PL, new JsonObject(sigPlaceMap));
		}
	}

	/**
	 * Incorporates 5.2.5 The srAts (signer attributes) header parameter
	 */
	private void incorporateSignerRoles() {
		Map<String, Object> srAtsParams = new LinkedHashMap<>();

		// TODO : certified are not supported
		// srAtsParams.put(JAdESHeaderParameterNames.CERTIFIED, new JSONArray(certifiedList));

		List<String> claimedSignerRoles = parameters.bLevel().getClaimedSignerRoles();
		if (Utils.isCollectionNotEmpty(claimedSignerRoles)) {
			srAtsParams.put(JAdESHeaderParameterNames.CLAIMED, getQArray(claimedSignerRoles));
		}

		List<String> signedAssertions = parameters.bLevel().getSignedAssertions();
		if (Utils.isCollectionNotEmpty(signedAssertions)) {
			srAtsParams.put(JAdESHeaderParameterNames.SIGNED_ASSERTIONS, getQArray(signedAssertions));
		}

		if (Utils.isMapNotEmpty(srAtsParams)) {
			JsonObject srAtsParamsObject = new JsonObject(srAtsParams);
			addHeader(JAdESHeaderParameterNames.SR_ATS, srAtsParamsObject);
		}
	}

	private JSONArray getQArray(List<String> qArrayVals) {

		// TODO : in 0.0.4 both "qArrays" and "vals" inside are arrays.
		// Could be change in the future

		List<JsonObject> qArrays = new ArrayList<>();

		/*
		 * Each instance of this type shall be a JSON array whose elements are JSON
		 * objects. Each JSON object shall contain three members, namely:
		 */
		Map<String, Object> qArrayMap = new LinkedHashMap<>();
		
		/*
		 * a) The mediaType member, which shall contain a string identifying the type of
		 * the signed assertions or the claimed attributes present in vals member, and
		 * shall meet the requirements specified in clause 8.4 of
		 * draft-handrews-json-schema-validation-02: "JSON Schema Validation: A
		 * Vocabulary for Structural Validation of JSON" [21].
		 */

		/*
		 * RFC 2046 "4.1.3. Plain Subtype"
		 * 
		 * The simplest and most important subtype of "text" is "plain". This indicates
		 * plain text that does not contain any formatting commands or directives. Plain
		 * text is intended to be displayed "as-is", that is, no interpretation of
		 * embedded formatting commands, font attribute specifications, processing
		 * instructions, interpretation directives, or content markup should be
		 * necessary for proper display.
		 */
		qArrayMap.put(JAdESHeaderParameterNames.MEDIA_TYPE, MimeType.TEXT.getMimeTypeString());

		/*
		 * b) The encoding member, which shall contain a string identifying the encoding
		 * of the signed assertions or the claimed attributes present in vals member,
		 * and shall meet the requirements specified in clause 8.3 of
		 * draft-handrews-json-schema-validation-02: "JSON Schema Validation: A
		 * Vocabulary for Structural Validation of JSON" [21].
		 */

		/*
		 * RFC 2045 "2.9. Binary Data"
		 * 
		 * "Binary data" refers to data where any sequence of octets whatsoever is
		 * allowed.
		 */
		qArrayMap.put(JAdESHeaderParameterNames.ENCODING, DSSJsonUtils.CONTENT_ENCODING_BINARY);

		/*
		 * c) The vals member, which shall be a JSON array of at least one item. The
		 * elements of vals JSON array shall be the values of the signed assertions or
		 * the claimed attributes encoded as indicated within the encoding member.
		 */
		qArrayMap.put(JAdESHeaderParameterNames.VALS, new JSONArray(qArrayVals));

		JsonObject qArray = new JsonObject(qArrayMap);
		qArrays.add(qArray);

		return new JSONArray(qArrays);
	}

	/**
	 * Incorporates 5.2.6 The adoTst (signed data time-stamp) header parameter
	 */
	private void incorporateContentTimestamps() {
		if (Utils.isCollectionEmpty(parameters.getContentTimestamps())) {
			return;
		}
		
		// canonicalization shall be null for content timestamps (see 5.2.6)
		List<TimestampBinary> contentTimestampBinaries = toTimestampBinaries(parameters.getContentTimestamps());
		JsonObject tstContainer = DSSJsonUtils.getTstContainer(contentTimestampBinaries, null); 
		addHeader(JAdESHeaderParameterNames.ADO_TST, tstContainer);
	}
	
	private List<TimestampBinary> toTimestampBinaries(List<TimestampToken> timestampTokens) {
		if (Utils.isCollectionEmpty(timestampTokens)) {
			return Collections.emptyList();
		}
		List<TimestampBinary> timestampBinaries = new ArrayList<>();
		for (TimestampToken timestampToken : timestampTokens) {
			TimestampBinary timestampBinary = new TimestampBinary(timestampToken.getEncoded());
			timestampBinaries.add(timestampBinary);
		}
		return timestampBinaries;
	}

	/**
	 * Incorporates 5.2.7 The sigPId (signature policy identifier) header parameter
	 */
	private void incorporateSignaturePolicy() {
		Policy signaturePolicy = parameters.bLevel().getSignaturePolicy();
		if (signaturePolicy != null && !signaturePolicy.isEmpty()) {
			String signaturePolicyId = signaturePolicy.getId();
			if (Utils.isStringEmpty(signaturePolicyId)) {
				// see EN 119-182 ch. 5.2.7.1 Semantics and syntax ('id' is required)
				throw new DSSException("Implicit policy is not allowed in JAdES! The signaturePolicyId attribute is required!");
			}
			
			Map<String, Object> sigPIdParams = new LinkedHashMap<>();
			
			JsonObject oid = DSSJsonUtils.getOidObject(signaturePolicyId, signaturePolicy.getDescription(), signaturePolicy.getDocumentationReferences());
			sigPIdParams.put(JAdESHeaderParameterNames.ID, oid);
			
			if ((signaturePolicy.getDigestValue() != null) && (signaturePolicy.getDigestAlgorithm() != null)) {
				JsonObject digAlgVal = DSSJsonUtils.getDigAlgValObject(signaturePolicy.getDigestValue(), signaturePolicy.getDigestAlgorithm());
				sigPIdParams.put(JAdESHeaderParameterNames.HASH_AV, digAlgVal);
			}

			// hashPSp is not added and treated as FALSE, because qualifier 'spDSpec' is not supported
			// sigPIdParams.put(JAdESHeaderParameterNames.HASH_PSP, value)
			
			List<JsonObject> signaturePolicyQualifiers = getSignaturePolicyQualifiers(signaturePolicy);
			if (Utils.isCollectionNotEmpty(signaturePolicyQualifiers)) {
				sigPIdParams.put(JAdESHeaderParameterNames.SIG_PQUALS, signaturePolicyQualifiers);
			}
			
			addHeader(JAdESHeaderParameterNames.SIG_PID, new JsonObject(sigPIdParams));
		}
	}

	// TODO : refactor Qualifiers to follow the schema (as well as in XAdES)
	private List<JsonObject> getSignaturePolicyQualifiers(Policy signaturePolicy) {
		List<JsonObject> sigPQualifiers = new ArrayList<>();

		String spuri = signaturePolicy.getSpuri();
		if (Utils.isStringNotEmpty(spuri)) {
			/* 
			 * Intermediate object is created in order to allow multiple instances of the same qualifiers
			 * 
			 * EN 119-182 ch. 5.2.7.1 Semantics and syntax:
			 * The sigPQuals member may contain one or more qualifiers of the same type.
			 */
			Map<String, Object> spURI = new LinkedHashMap<>();
			spURI.put(JAdESHeaderParameterNames.SP_URI, spuri);
			sigPQualifiers.add(new JsonObject(spURI));
		}
		
		// other policy qualifiers are not supported
		
		return sigPQualifiers;
	}

	/**
	 * Incorporates 5.2.8 The sigD header parameter
	 */
	private void incorporateDetachedContents() {
		if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			assertDetachedContentValid();
			
			Map<String, Object> sigDParams;
			switch (parameters.getSigDMechanism()) {
				case HTTP_HEADERS:
					sigDParams = getSigDForHttpHeadersMechanism(documentsToSign);
					break;
				case OBJECT_ID_BY_URI:
					// The 5.2.8.3 Mechanism ObjectIdByURI implementation
					sigDParams = getSigDForObjectIdByUriMechanism(documentsToSign);
					break;
				case OBJECT_ID_BY_URI_HASH:
					// The 5.2.8.4 Mechanism ObjectIdByURIHash implementation
					sigDParams = getSigDForObjectIdByUriHashMechanism(documentsToSign);
					break;
				case NO_SIG_D:
					// do not incorporate the SigD
					return;
				default:
					throw new DSSException(String.format("The 'sigD' mechanism '%s' is not supported!", parameters.getSigDMechanism()));
			}
			
			addHeader(JAdESHeaderParameterNames.SIG_D, new JsonObject(sigDParams));
		}
	}
	
	private void assertDetachedContentValid() {
		if (parameters.getSigDMechanism() == null) {
			throw new DSSException("The SigDMechanism is not defined for a detached signature! "
					+ "Please use JAdESSignatureParameters.setSigDMechanism(sigDMechanism) method.");
		}
		if (!SigDMechanism.NO_SIG_D.equals(parameters.getSigDMechanism())) {
			for (DSSDocument document : documentsToSign) {
				if (Utils.isStringEmpty(document.getName())) {
					throw new DSSException("The signed document must have names for a detached signature!");
				}
			}
		}
	}
	
	private Map<String, Object> getSigDForObjectIdByUriMechanism(List<DSSDocument> detachedContents) {
		Map<String, Object> sigDParams = new LinkedHashMap<>();
		
		sigDParams.put(JAdESHeaderParameterNames.M_ID, SigDMechanism.OBJECT_ID_BY_URI.getUri());
		sigDParams.put(JAdESHeaderParameterNames.PARS, getSignedDataReferences(detachedContents));

		sigDParams.put(JAdESHeaderParameterNames.CTYS, getSignedDataMimeTypesIfPresent(detachedContents));
		
		return sigDParams;
	}
	
	private Map<String, Object> getSigDForObjectIdByUriHashMechanism(List<DSSDocument> detachedContents) {
		Map<String, Object> sigDParams = new LinkedHashMap<>();
		
		sigDParams.put(JAdESHeaderParameterNames.M_ID, SigDMechanism.OBJECT_ID_BY_URI_HASH.getUri());
		sigDParams.put(JAdESHeaderParameterNames.PARS, getSignedDataReferences(detachedContents));
		
		DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault();
		sigDParams.put(JAdESHeaderParameterNames.HASH_M, digestAlgorithm.getUri());
		sigDParams.put(JAdESHeaderParameterNames.HASH_V, getSignedDataDigests(detachedContents, digestAlgorithm));
		
		sigDParams.put(JAdESHeaderParameterNames.CTYS, getSignedDataMimeTypesIfPresent(detachedContents));
		
		return sigDParams;
	}
	
	private Map<String, Object> getSigDForHttpHeadersMechanism(List<DSSDocument> detachedContents) {
		Map<String, Object> sigDParams = new LinkedHashMap<>();

		sigDParams.put(JAdESHeaderParameterNames.M_ID, SigDMechanism.HTTP_HEADERS.getUri());
		sigDParams.put(JAdESHeaderParameterNames.PARS, getHttpHeaderNames());
		
		return sigDParams;
	}
	
	private JSONArray getSignedDataReferences(List<DSSDocument> detachedContents) {
		List<String> references = new ArrayList<>();
		for (DSSDocument document : detachedContents) {
			references.add(DSSUtils.encodeURI(document.getName()));
		}
		return new JSONArray(references);
	}
	
	private DigestAlgorithm getReferenceDigestAlgorithmOrDefault() {
		return parameters.getReferenceDigestAlgorithm() != null ? parameters.getReferenceDigestAlgorithm() : parameters.getDigestAlgorithm();
	}
	
	private JSONArray getSignedDataDigests(List<DSSDocument> detachedContents, DigestAlgorithm digestAlgorithm) {
		List<String> digests = new ArrayList<>();
		for (DSSDocument document : detachedContents) {
			String base64Digest = document.getDigest(digestAlgorithm);
			digests.add(DSSJsonUtils.toBase64Url(Utils.fromBase64(base64Digest))); // base64Url digest
		}
		return new JSONArray(digests);
	}
	
	/**
	 * Returns a 'ctys' array for given documents
	 * 
	 * @param detachedContents a list of {@link DSSDocument} to be signed
	 * @return 'ctys' {@link JSONArray}
	 */
	private JSONArray getSignedDataMimeTypesIfPresent(List<DSSDocument> detachedContents) {
		List<String> mimeTypes = new ArrayList<>();
		for (DSSDocument document : detachedContents) {
			MimeType mimeType = document.getMimeType();
			if (mimeType == null) {
				mimeType = MimeType.BINARY;
			}
			String rfc7515MimeType = getRFC7515ConformantMimeTypeString(mimeType);
			mimeTypes.add(rfc7515MimeType);
		}
		return new JSONArray(mimeTypes);
	}
	
	/**
	 * Returns a list of HTTP message field names being included into 'sigD' for HttpHeaders mechanism
	 * 
	 * @param httpMessage {@link HTTPHeader} to extract field names from
	 * @return a set of HTTP message field names
	 */
	private Collection<String> getHttpHeaderNames() {
		/*
		 * TS 119 182-1 "5.2.8.2 Mechanism HttpHeaders" : 
		 * 
		 * For this referencing mechanism, the contents of the pars member 
		 * shall be an array of lowercased names of HTTP header fields, each one 
		 * with the semantics and syntax specified in clause 
		 * 2.1.3 of draft-cavage-http-signatures-10: "Signing HTTP Messages" [17].
		 */
		List<String> httpHeaderNames = new ArrayList<>();
		
		for (DSSDocument document : documentsToSign) {
			if (document instanceof HTTPHeader) {
				String headerName = Utils.lowerCase(document.getName());
				if (!httpHeaderNames.contains(headerName)) {
					httpHeaderNames.add(headerName);
				}
				
			}
		}
		
		return httpHeaderNames;
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
	
	/**
	 * Returns JWS payload for the given signature parameters
	 * 
	 * @return payload byte array
	 */
	public byte[] getPayloadBytes() {
		if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging()) ||
				SigDMechanism.NO_SIG_D.equals(parameters.getSigDMechanism())) {
			return DSSUtils.toByteArray(documentsToSign.get(0));
		} else if (SigDMechanism.HTTP_HEADERS.equals(parameters.getSigDMechanism())) {
			return getPayloadForHttpHeadersMechanism();
		} else if (SigDMechanism.OBJECT_ID_BY_URI.equals(parameters.getSigDMechanism())) {
			return getPayloadForObjectIdByUriMechanism();
		} else if (SigDMechanism.OBJECT_ID_BY_URI_HASH.equals(parameters.getSigDMechanism())) {
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
		throw new DSSException("The configured signature format is not supported!");
	}
	
	private byte[] getPayloadForHttpHeadersMechanism() {
		HttpHeadersPayloadBuilder httpHeadersPayloadBuilder = new HttpHeadersPayloadBuilder(documentsToSign);
		return httpHeadersPayloadBuilder.build();
	}
	
	private byte[] getPayloadForObjectIdByUriMechanism() {
		// NOTE: b64 encoding is processed by JWS
		return DSSJsonUtils.concatenateDSSDocuments(documentsToSign);
	}

}
