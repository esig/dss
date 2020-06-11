package eu.europa.esig.dss.jades;

import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.ADO_TST;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_D;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PID;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PL;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_T;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_ATS;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_CM;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.X5T_O;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class JAdESUtils {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESUtils.class);
	
    /**
     * This is a copy of the STANDARD_ENCODE_TABLE above, but with + and / changed
     * to - and _ to make the encoded Base64 results more URL-SAFE. This table is
     * only used when the Base64's mode is set to URL-SAFE.
     */
    public static final Byte[] BASE64_URL_SAFE_ENCODE_TABLE = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
            'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0',
            '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_' };
    
    public final static List<Byte> BASE64_URL_BINARIES = Arrays.asList(BASE64_URL_SAFE_ENCODE_TABLE);
	
	public static final String MIME_TYPE_APPLICATION_PREFIX = "application/";
	
	/**
	 * Contains header names that are supported to be present in the critical attribute
	 */
	private static final Set<String> criticalHeaders;
	
	static {
		// JAdES EN 119-812 constraints
		criticalHeaders = Stream.of(SIG_T, X5T_O, SR_CM, SIG_PL, SR_ATS, ADO_TST, SIG_PID, SIG_D)
				.collect(Collectors.toSet());
		criticalHeaders.add(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD); // b64 #RFC7797
	}
	
	/**
	 * Returns ASCII-encoded array
	 * 
	 * @param str {@link String} to encode to ASCII
	 * @return byte array
	 */
	public static byte[] getAsciiBytes(String str) {
		return StringUtil.getBytesAscii(str);
	}
	
	/**
	 * Returns a base64Url encoded string
	 * 
	 * @param binary a byte array to encode
	 * @return base64Url encoded {@link String}
	 */
	public static String toBase64Url(byte[] binary) {
		return Base64Url.encode(binary);
	}
	
	/**
	 * Returns the decoded binary for a base64url encoded string
	 * 
	 * @param base64UrlEncoded the tring to decoded
	 * @return the decoded binary
	 */
	public static byte[] fromBase64Url(String base64UrlEncoded) {
		return Base64Url.decode(base64UrlEncoded);
	}
	
	/**
	 * Checks if the payload is JWS URL safe
	 * See RFC 7797 : 5.2. Unencoded JWS Compact Serialization Payload
	 * 
	 * @param payloadString {@link String} representing a payload
	 * @return TRUE if the payload is URL safe, FALSE otherwise
	 */
	public static boolean isUrlSafePayload(String payloadString) {
		/*
		 * When using the JWS Compact Serialization, unencoded non-detached
		 * payloads using period ('.') characters would cause parsing errors;
		 * such payloads MUST NOT be used with the JWS Compact Serialization.
		 * ...
		 * The ASCII space character and all printable ASCII characters
		 * other than period ('.') (those characters in the ranges %x20-2D and
		 * %x2F-7E) MAY be included in a non-detached payload using the JWS
		 * Compact Serialization, provided that the application can transmit the
		 * resulting JWS without modification.
		 */
		return payloadString.matches("[^\\P{Print}.]*");
	}
	
	/**
	 * Checks if the given byte is url safe
	 * See RFC 7797 : 5.2. Unencoded JWS Compact Serialization Payload
	 * 
	 * @param b a byte to check
	 * @return TRUE if the byte is url-safe, FALSE otherwise
	 */
	public static boolean isUrlSafe(byte b) {
		return 0x1f < b && b < 0x2e || 0x2e < b && b < 0x7f;
	}

	/**
	 * Concatenates the given strings with a '.' (dot) between.
	 * 
	 * Example: "xxx", "yyy", "zzz" to "xxx.yyy.zzz"
	 * 
	 * @param strings a list of {@link String}s to concatenate
	 * @return a concatenation string result
	 */
	public static String concatenate(String... strings) {
		return CompactSerializer.serialize(strings);
	}
	
	/**
	 * Returns array of supported critical headers
	 * 
	 * @return array of supported critical header strings
	 */	
	public static String[] getSupportedCriticalHeaders() {
		return criticalHeaders.toArray(new String[criticalHeaders.size()]);
	}
	
	/**
	 * Creates a 'DigAlgVal' JSONObject from the given values
	 * 
	 * @param digestValue a byte array representing a hash value
	 * @param digestAlgorithm {@link DigestAlgorithm} has been used to generate the value
	 * @return 'DigAlgVal' {@link JSONObject}
	 */
	public static JSONObject getDigAlgValObject(byte[] digestValue, DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestValue, "digestValue must be defined!");
		Objects.requireNonNull(digestAlgorithm, "digestAlgorithm must be defined!");
		
		Map<String, Object> digAlgValParams = new HashMap<>();
		digAlgValParams.put(JAdESHeaderParameterNames.DIG_ALG, digestAlgorithm.getUri());
		digAlgValParams.put(JAdESHeaderParameterNames.DIG_VAL, Utils.toBase64(digestValue));
		
		return new JSONObject(digAlgValParams);
	}

	/**
	 * Creates a {@link Digest} object from a JSON structure
	 * 
	 * @param digestValueAndAlgo a Map with digAlg and digVal values
	 * @return an instance of Digest or null
	 */
	public static Digest getDigest(Map<?, ?> digestValueAndAlgo) {
		String digestAlgoURI = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_ALG);
		String digestValueBase64 = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_VAL);
		if (Utils.isStringNotEmpty(digestAlgoURI) && Utils.isStringNotEmpty(digestValueBase64)) {
			return new Digest(DigestAlgorithm.forXML(digestAlgoURI), Utils.fromBase64(digestValueBase64));
		} else {
			return null;
		}
	}

	/**
	 * Creates an 'oid' JSONObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param uri {@link String} URI defining the object.
	 * @return 'oid' {@link JSONObject}
	 */
	public static JSONObject getOidObject(String uri) {
		return getOidObject(uri, null, null);
	}
	
	/**
	 * Returns URI if present, otherwise URN encoded OID (see RFC 3061)
	 * Returns NULL if non of them is present
	 * 
	 * @param objectIdentifier {@link ObjectIdentifier} used to build an object of 'oid' type
	 * @return {@link String} URI
	 */
	public static String getUriOrUrnOid(ObjectIdentifier objectIdentifier) {
		/*
		 * TS 119 182-1 : 5.4.1 The oId data type
		 * If both an OID and a URI exist identifying one object, the URI value should be used in the id member.
		 */
		String uri = objectIdentifier.getUri();
		if (uri == null && objectIdentifier.getOid() != null) {
			uri = DSSUtils.toUrnOid(objectIdentifier.getOid());
		}
		return uri;
	}

	/**
	 * Creates an 'oid' JSONObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param objectIdentifier {@link ObjectIdentifier} to create an 'oid' from
	 * @return 'oid' {@link JSONObject}
	 */
	public static JSONObject getOidObject(ObjectIdentifier objectIdentifier) {
		return getOidObject(getUriOrUrnOid(objectIdentifier), objectIdentifier.getDescription(), 
				Arrays.asList(objectIdentifier.getDocumentationReferences()));
	}

	/**
	 * Creates an 'oid' JSONObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param uri {@link String} URI defining the object. The property is REQUIRED.
	 * @param desc {@link String} the object description. The property is OPTIONAL.
	 * @param docRefs a list of {@link String} URIs containing any other additional information about the object. 
	 * 				The property is OPTIONAL.
	 * @return 'oid' {@link JSONObject}
	 */
	public static JSONObject getOidObject(String uri, String desc, List<String> docRefs) {
		Objects.requireNonNull(uri, "uri must be defined!");
		
		Map<String, Object> oidParams = new HashMap<>();
		oidParams.put(JAdESHeaderParameterNames.ID, uri);
		if (Utils.isStringNotEmpty(desc)) {
			oidParams.put(JAdESHeaderParameterNames.DESC, desc);
		}
		if (Utils.isCollectionNotEmpty(docRefs)) {
			oidParams.put(JAdESHeaderParameterNames.DOC_REFS, new JSONArray(docRefs));
		}
		
		return new JSONObject(oidParams);
	}
	
	/**
	 * Creates a 'tstContainer' JSONObject according to EN 119-182 ch. 5.4.3.3 The tstContainer type
	 * 
	 * @param timestampTokens a list of {@link TimestampToken}s to incorporate
	 * @param canonicalizationMethodUri a canonicalization method (OPTIONAL, e.g. shall not be present for content timestamps)
	 * @return 'tstContainer' {@link JSONObject}
	 */
	public static JSONObject getTstContainer(List<TimestampToken> timestampTokens, String canonicalizationMethodUri) {
		if (Utils.isCollectionEmpty(timestampTokens)) {
			throw new DSSException("Impossible to create 'tstContainer'. TimestampTokens cannot be null or empty!");
		}

		Map<String, Object> tstContainerParams = new HashMap<>();
		if (canonicalizationMethodUri != null) {
			tstContainerParams.put(JAdESHeaderParameterNames.CANON_ALG, canonicalizationMethodUri);
		}
		List<JSONObject> tsTokens = new ArrayList<>();
		for (TimestampToken timestampToken : timestampTokens) {
			JSONObject tstToken = getTstToken(timestampToken);
			tsTokens.add(tstToken);
		}
		JSONArray tsTokensArray = new JSONArray(tsTokens);
		tstContainerParams.put(JAdESHeaderParameterNames.TST_TOKENS, tsTokensArray);
		
		return new JSONObject(tstContainerParams);
	}
	
	/**
	 * Creates a 'tstToken' JSONObject according to EN 119-182 ch. 5.4.3.3 The tstContainer type
	 * 
	 * @param timestampToken {@link TimestampToken}s to incorporate
	 * @return 'tstToken' {@link JSONObject}
	 */
	private static JSONObject getTstToken(TimestampToken timestampToken) {
		Objects.requireNonNull(timestampToken, "timestampToken cannot be null!");
		
		Map<String, Object> tstTokenParams = new HashMap<>();
		// only RFC 3161 TimestampTokens are supported
		// 'type', 'encoding' and 'specRef' params are not need to be defined (see EN 119-182 ch. 5.4.3.3)
		tstTokenParams.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(timestampToken.getEncoded())); // DER-encoded value
		
		return new JSONObject(tstTokenParams);
	}
	
	/**
	 * Concatenates document octets to a single byte array
	 * 
	 * @param documents a list of {@link DSSDocument}s to concatenate
	 * @return a byte array of document octets
	 * @throws IOException if an exception occurs
	 */
	public static byte[] concatenateDSSDocuments(List<DSSDocument> documents) throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			for (DSSDocument document : documents) {
				baos.write(DSSUtils.toByteArray(document));
			}
			return baos.toByteArray();
		}
	}
	
	/**
	 * Casts a list of {@link DSSDocument}s to a list of {@code HTTPHeaderDocument}s
	 * 
	 * @param dssDocuments a list of {@link DSSDocument}s to be casted to {@link HTTPHeaderDocument}s
	 * @return a list of {@link HTTPHeaderDocument}s
	 * @throws IllegalArgumentException if a document of not {@link HTTPHeaderDocument} class found
	 */
	public static List<HTTPHeaderDocument> toHTTPHeaderDocuments(List<DSSDocument> dssDocuments) throws IllegalArgumentException {
		List<HTTPHeaderDocument> httpHeaderDocuments = new ArrayList<>();
		for (DSSDocument document : dssDocuments) {
			if (document instanceof HTTPHeaderDocument) {
				HTTPHeaderDocument httpHeaderDocument = (HTTPHeaderDocument) document;
				httpHeaderDocuments.add(httpHeaderDocument);
			} else {
				throw new IllegalArgumentException(String.format("The document with name '%s' is not of type HTTPHeaderDocument!"));
			}
		}
		return httpHeaderDocuments;
	}
	
	/**
	 * Checks if the provided document is JSON document
	 * 
	 * @param document {@link DSSDocument} to check
	 * @return TRUE of the document is JSON, FALSE otherwise
	 */
	public static boolean isJsonDocument(DSSDocument document) {
		try (InputStream is = document.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			int firstChar = is.read();
			if (firstChar == '{') {
				baos.write(firstChar);
				Utils.copy(is, baos);
				if (baos.size() < 2) {
					return false;
				}
				Map<String, Object> json = JsonUtil.parseJson(baos.toString());
				return json != null;
			}
		} catch (JoseException e) {
			LOG.warn("Unable to parse content as JSON : {}", e.getMessage());
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read the document. Reason : %s", e.getMessage()), e);
		}
		return false;
	}

}
