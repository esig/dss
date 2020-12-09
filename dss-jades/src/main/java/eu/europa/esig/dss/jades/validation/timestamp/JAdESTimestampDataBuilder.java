package eu.europa.esig.dss.jades.validation.timestamp;

import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.signature.HttpHeadersPayloadBuilder;
import eu.europa.esig.dss.jades.validation.EtsiUComponent;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.jose4j.json.internal.json_simple.JSONValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Builds the message-imprint for JAdES timestamps
 */
public class JAdESTimestampDataBuilder implements TimestampDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESTimestampDataBuilder.class);

	/** The signature */
	private final JAdESSignature signature;

	/**
	 * Default constructor
	 *
	 * @param signature {@link JAdESSignature}
	 */
	public JAdESTimestampDataBuilder(JAdESSignature signature) {
		this.signature = signature;
	}

	@Override
	public DSSDocument getContentTimestampData(TimestampToken timestampToken) {
		byte[] signedDataBinaries = getSignedDataBinaries();
		if (Utils.isArrayNotEmpty(signedDataBinaries)) {
			return new InMemoryDocument(signedDataBinaries);
		}
		return null;
	}
	
	private byte[] getSignedDataBinaries() {
		SigDMechanism sigDMechanism = signature.getSigDMechanism();
		if (sigDMechanism != null) {
			return getSigDReferencedOctets(sigDMechanism);
		} else {
			return getJWSPayloadValue();
		}
	}
	
	private byte[] getJWSPayloadValue() {
		if (signature.getJws().isRfc7797UnencodedPayload()) {
			return signature.getJws().getUnverifiedPayloadBytes();
		} else {
			return signature.getJws().getEncodedPayload().getBytes();
		}
	}
	
	private byte[] getSigDReferencedOctets(SigDMechanism sigDMechanism) {
		byte[] sigDOctets = null;
		List<DSSDocument> documentList = null;

		switch (sigDMechanism) {
			case HTTP_HEADERS:
				documentList = signature.getSignedDocumentsByUri(false);
				HttpHeadersPayloadBuilder httpHeadersPayloadBuilder = new HttpHeadersPayloadBuilder(documentList, true);
				sigDOctets = httpHeadersPayloadBuilder.build();
				break;
			case OBJECT_ID_BY_URI:
			case OBJECT_ID_BY_URI_HASH:
				documentList = signature.getSignedDocumentsByUri(true);
				sigDOctets = DSSJsonUtils.concatenateDSSDocuments(documentList);
				if (Utils.isArrayNotEmpty(sigDOctets) && !signature.getJws().isRfc7797UnencodedPayload()) {
					sigDOctets = DSSJsonUtils.toBase64Url(sigDOctets).getBytes();
				}
				break;
			default:
				LOG.warn("Unsupported SigDMechanism '{}' has been found!", sigDMechanism);
		}

		return sigDOctets;
	}

	@Override
	public DSSDocument getSignatureTimestampData(TimestampToken timestampToken) {
		return new InMemoryDocument(signature.getSignatureValue());
	}

	@Override
	public DSSDocument getTimestampX1Data(TimestampToken timestampToken) {
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("--->Get SigAndRefs timestamp data");
		}
		String canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : null;
		
		JWS jws = signature.getJws();
		/*
		 * A.1.5.1	The sigRTst JSON object
		 * 
		 * The message imprint computation input shall be the concatenation of the components, 
		 * in the order they are listed below.
		 */
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			
			/*
			 * 1) The value of the base64url-encoded JWS Signature Value.
			 */
			baos.write(jws.getEncodedSignature().getBytes());
			
			/*
			 * 2) The character '.'.
			 */
			baos.write('.');
			
			/*
			 * 3) Those among the following components that appear before sigRTst, in their
			 * order of appearance within the etsiU array, base64url-encoded:
			 * 
			 * NOTE: there is a difference in processing base64url encoded values and clear
			 * incorporation
			 */
			List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
			if (DSSJsonUtils.checkComponentsUnicity(etsiU)) {
				/*
				 * - sigTst if it is present.
				 * - xRefs if it is present.
				 * - rRefs if it is present.
				 * - axRefs if it is present. And
				 * - arRefs if it is present.
				 */
				JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
				for (EtsiUComponent etsiUComponent : etsiUHeader.getAttributes()) {

					if (timestampToken != null && timestampToken.getHashCode() == etsiUComponent.hashCode()) {
						// the current timestamp is found, stop the iteration
						break;
					}

					if (isAllowedTypeEntry(etsiUComponent, JAdESHeaderParameterNames.SIG_TST,
							JAdESHeaderParameterNames.X_REFS, JAdESHeaderParameterNames.R_REFS,
							JAdESHeaderParameterNames.AX_REFS, JAdESHeaderParameterNames.AR_REFS)) {

						baos.write(getEtsiUComponentValue(etsiUComponent, canonicalizationMethod));
					}

				}

			} else {
				LOG.warn("Unable to process 'etsiU' entries for a 'sigRTst' timestamp. "
						+ "The 'etsiU' components shall have a common format (Strings or Objects)!");
			}

			byte[] messageImprint = baos.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("The SigAndRefs timestamp message-imprint : {}", new String(messageImprint));
			}
			
			return new InMemoryDocument(messageImprint);
			
		} catch (IOException e) {
			throw new DSSException("An error occurred during building of a message imprint");
		}
		
	}
	
	private boolean isAllowedTypeEntry(EtsiUComponent etsiUComponent, String... allowedTypes) {
		return Arrays.stream(allowedTypes).anyMatch(etsiUComponent.getHeaderName()::equals);
	}

	@Override
	public DSSDocument getTimestampX2Data(TimestampToken timestampToken) {
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("--->Get RefsOnly timestamp data");
		}
		String canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : null;
		
		JWS jws = signature.getJws();
		
		/*
		 * A.1.5.2.2 The rfsTst JSON object
		 * 
		 * The message imprint computation input shall be the concatenation of the components, 
		 * in the order they are listed below.
		 */
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			
			/*
			 * The message imprint computation input shall be the concatenation of the
			 * components listed below, base64url encoded, in their order of appearance within the etsiU array:
			 * - xRefs if it is present.
			 * - rRefs if it is present.
			 * - axRefs if it is present. And
			 * - arRefs if it is present.
			 * 
			 * NOTE: there is a difference in processing base64url encoded values and clear
			 * incorporation
			 */
			List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
			if (DSSJsonUtils.checkComponentsUnicity(etsiU)) {

				JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
				for (EtsiUComponent etsiUComponent : etsiUHeader.getAttributes()) {

					if (isAllowedTypeEntry(etsiUComponent, JAdESHeaderParameterNames.X_REFS,
							JAdESHeaderParameterNames.R_REFS, JAdESHeaderParameterNames.AX_REFS,
							JAdESHeaderParameterNames.AR_REFS)) {

						baos.write(getEtsiUComponentValue(etsiUComponent, canonicalizationMethod));
					}

				}
				
			} else {
				LOG.warn("Unable to process 'etsiU' entries for an 'rfsTst' timestamp. "
						+ "The 'etsiU' components shall have a common format (Strings or Objects)!");
			}

			byte[] messageImprint = baos.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("The Refs timestamp message-imprint : {}", new String(messageImprint));
			}
			
			return new InMemoryDocument(messageImprint);
			
		} catch (IOException e) {
			throw new DSSException("An error occurred during building of a message imprint");
		}
		
	}

	@Override
	public DSSDocument getArchiveTimestampData(TimestampToken timestampToken) {
		try {
			byte[] archiveTimestampData = getArchiveTimestampData(timestampToken, null);
			return new InMemoryDocument(archiveTimestampData);
		} catch (DSSException e) {
			LOG.error("Unable to get data for TimestampToken with Id '{}'. Reason : {}", timestampToken.getDSSIdAsString(), e.getMessage(), e);
			return null;
		}
	}
	
	/**
	 * Returns ArchiveTimestamp Data for a new Timestamp
	 * 
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return byte array timestamp data
	 */
	public byte[] getArchiveTimestampData(final String canonicalizationMethod) {
		// timestamp creation
		return getArchiveTimestampData(null, canonicalizationMethod);
	}

	/**
	 * Returns the message-imprint computed for the archive {@code timestampToken}
	 *
	 * @param timestampToken {@link TimestampToken} archive timestamp token
	 * @param canonicalizationMethod {@link String} if defined
	 * @return message-imprint byte array
	 */
	protected byte[] getArchiveTimestampData(TimestampToken timestampToken, String canonicalizationMethod) {
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("--->Get archive timestamp data : {}", (timestampToken == null ? "--> CREATION" : "--> VALIDATION"));
		}
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
				
		JWS jws = signature.getJws();
		
		/*
		 * 5.3.6.3.1 Processing (5.3.6.3 Computation of message-imprint)
		 * 
		 * If the value of timeStamped is equal to "all" or it is absent, and the etsiU
		 * array contains base64url encoded unsigned JSON values, then the message
		 * imprint computation input shall be the concatenation of the components in the
		 * order they are listed below:
		 */
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			
			/*
			 * 1) If the sigD header parameter is absent then:
			 * a) If the b64 header parameter specified in clause 3 of IETF RFC 7797 [15] is present
			 * and set to "false" then concatenate the JWS Payload value.
			 * b) If the b64 header parameter specified in clause 3 of IETF RFC 7797 [15] is present
			 * and set to "true", OR it is absent, then concatenate the base64url-encoded JWS Payload.
			 * 
			 * 2) If the sigD header parameter is present: a) If the value of its mId member
			 * is "http://uri.etsi.org/19182/HttpHeaders" then concatenate the bytes
			 * resulting from processing the contents of its pars member as specified in
			 * clause 5.2.8.2 of the present document except the "Digest" string element.
			 * The processing of the "Digest" string element in the pars array shall consist
			 * in retrieving the bytes of the body of the HTTP message.
			 * 
			 */
			baos.write(getSignedDataBinaries());
			
			/*
			 * 3) The character '.'.
			 */
			baos.write('.');
			
			/*
			 * 4) The value of the JWS Protected Header, base64url encoded, followed by the
			 * character '.'.
			 */
			baos.write(jws.getEncodedHeader().getBytes());
			baos.write('.');
			
			/*
			 * 5) The value of the JAdES Signature Value, base64url encoded.
			 */
			baos.write(jws.getEncodedSignature().getBytes());
			
			/*
			 * 6) If the elements of the etsiU array appear as the base64url encodings of
			 * the unsigned components, then proceed as specified in clause 5.3.6.3.1.1 of
			 * the present document. If the elements of the etsiU array appear as clear
			 * instances of unsigned components, then proceed as specified in clause
			 * 5.3.6.3.1.2 of the present document.
			 */
			List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
			if (DSSJsonUtils.checkComponentsUnicity(etsiU)) {

				JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
				for (EtsiUComponent etsiUComponent : etsiUHeader.getAttributes()) {

					if (timestampToken != null && timestampToken.getHashCode() == etsiUComponent.hashCode()) {
						// the timestamp is reached, stop the iteration
						break;
					}

					baos.write(getEtsiUComponentValue(etsiUComponent, canonicalizationMethod));
				}

			} else {
				LOG.warn("Unable to process 'etsiU' entries for an archive timestamp. "
						+ "The 'etsiU' components shall have a common format (Strings or Objects)!");
			}

			byte[] messageImprint = baos.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("The 'arcTst' timestamp message-imprint : {}", new String(messageImprint));
			}
			
			return messageImprint;
			
			
		} catch (IOException e) {
			throw new DSSException("An error occurred during building of a message imprint");
		}
	}
	
	private byte[] getEtsiUComponentValue(EtsiUComponent etsiUComponent, String canonicalizationMethod) {
		Object component = etsiUComponent.getComponent();
		if (etsiUComponent.isBase64UrlEncoded()) {
			return ((String) component).getBytes();
		} else {
			return getCanonicalizedValue(etsiUComponent.getValue(), canonicalizationMethod);
		}
	}
	
	private byte[] getCanonicalizedValue(Object jsonObject, String canonicalizationMethod) {
		// TODO: canonicalization is not supported yet
		LOG.warn("Canonicalization is not supported in the current version. "
				+ "The message imprint computation can lead to an unexpected result");
		// temporary solution
		String jsonString = JSONValue.toJSONString(jsonObject);
		return jsonString.getBytes();
	}

}
