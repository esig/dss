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
package eu.europa.esig.dss.jades.validation.timestamp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.signature.HttpHeadersPayloadBuilder;
import eu.europa.esig.dss.jades.validation.EtsiUComponent;
import eu.europa.esig.dss.jades.validation.JAdESAttribute;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.timestamp.TimestampMessageDigestBuilder;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.jose4j.json.internal.json_simple.JSONValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Builds the message-imprint digest for JAdES timestamps
 *
 */
public class JAdESTimestampMessageDigestBuilder implements TimestampMessageDigestBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESTimestampMessageDigestBuilder.class);

	/** The error message to be thrown in case of a message-imprint build error */
	private static final String MESSAGE_IMPRINT_ERROR = "Unable to compute message-imprint for TimestampToken. Reason : %s";

	/** The error message to be thrown in case of a message-imprint build error for a timestamp */
	private static final String MESSAGE_IMPRINT_ERROR_WITH_ID = "Unable to compute message-imprint for TimestampToken with Id '%s'. Reason : %s";

	/** String used to print the computed message-imprint */
	private static final String MESSAGE_IMPRINT_MESSAGE = "The '{}' timestamp message-imprint : {}";

	/** The signature */
	private final JAdESSignature signature;

	/** The digest algorithm to be used for message-imprint digest computation */
	private DigestAlgorithm digestAlgorithm;

	/** Timestamp token to compute message-digest for */
	private TimestampToken timestampToken;

	/** The canonicalization algorithm to be used for message-imprint computation */
	private String canonicalizationAlgorithm;

	/** The signature element containing the time-stamp token */
	private JAdESAttribute timestampAttribute;

	/**
	 * The constructor to compute message-imprint for timestamps related to the {@code signature}
	 *
	 * @param signature {@link JAdESSignature} to create timestamps for
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-imprint digest computation
	 */
	public JAdESTimestampMessageDigestBuilder(final JAdESSignature signature, final DigestAlgorithm digestAlgorithm) {
		this(signature);
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * The constructor to compute message-imprint for timestamps related to the {@code signature}
	 *
	 * @param signature {@link JAdESSignature} containing timestamps
	 * @param timestampToken {@link TimestampToken} to compute message-digest for
	 */
	public JAdESTimestampMessageDigestBuilder(final JAdESSignature signature, final TimestampToken timestampToken) {
		this(signature);
		Objects.requireNonNull(timestampToken, "TimestampToken cannot be null!");
		this.timestampToken = timestampToken;
		this.digestAlgorithm = timestampToken.getDigestAlgorithm();
		this.canonicalizationAlgorithm = timestampToken.getCanonicalizationMethod();
	}

	/**
	 * Default constructor
	 *
	 * @param signature {@link JAdESSignature}
	 */
	private JAdESTimestampMessageDigestBuilder(final JAdESSignature signature) {
		Objects.requireNonNull(signature, "Signature cannot be null!");
		this.signature = signature;
	}

	/**
	 * Sets the canonicalization algorithm to be used for message-digest computation
	 *
	 * @param canonicalizationAlgorithm {@link String}
	 * @return this {@code JAdESTimestampMessageDigestBuilder}
	 */
	public JAdESTimestampMessageDigestBuilder setCanonicalizationAlgorithm(String canonicalizationAlgorithm) {
		this.canonicalizationAlgorithm = canonicalizationAlgorithm;
		return this;
	}

	/**
	 * Sets a signature attribute identifying the time-stamp token
	 *
	 * @param timestampAttribute {@link JAdESAttribute}
	 * @return this {@code JAdESTimestampMessageDigestBuilder}
	 */
	public JAdESTimestampMessageDigestBuilder setTimestampAttribute(JAdESAttribute timestampAttribute) {
		this.timestampAttribute = timestampAttribute;
		return this;
	}

	@Override
	public DSSMessageDigest getContentTimestampMessageDigest() {
		try {
			DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
			writeSignedDataBinaries(digestCalculator);
			return digestCalculator.getMessageDigest(digestAlgorithm);

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}
	
	private void writeSignedDataBinaries(DSSMessageDigestCalculator digestCalculator) {
		SigDMechanism sigDMechanism = signature.getSigDMechanism();
		if (sigDMechanism != null) {
			writeSigDReferencedOctets(digestCalculator, sigDMechanism);
		} else {
			writeJWSPayloadValue(digestCalculator);
		}
	}
	
	private void writeJWSPayloadValue(DSSMessageDigestCalculator digestCalculator) {
		byte[] payload;
		if (signature.getJws().isRfc7797UnencodedPayload()) {
			payload = signature.getJws().getUnverifiedPayloadBytes();
		} else {
			payload = signature.getJws().getEncodedPayload().getBytes();
		}
		if (Utils.isArrayEmpty(payload)) {
			throw new DSSException("Unable to extract JWS payload!");
		}
		digestCalculator.update(payload);
	}
	
	private void writeSigDReferencedOctets(DSSMessageDigestCalculator digestCalculator, SigDMechanism sigDMechanism) {
		List<DSSDocument> documentList;
		switch (sigDMechanism) {
			case HTTP_HEADERS:
				documentList = signature.getSignedDocumentsByHTTPHeaderName();
				HttpHeadersPayloadBuilder httpHeadersPayloadBuilder = new HttpHeadersPayloadBuilder(documentList, true);
				byte[] sigDOctets = httpHeadersPayloadBuilder.build();
				digestCalculator.update(sigDOctets);
				break;
			case OBJECT_ID_BY_URI:
			case OBJECT_ID_BY_URI_HASH:
				documentList = signature.getSignedDocumentsForObjectIdByUriMechanism();
				DSSJsonUtils.writeDocumentsDigest(documentList, !signature.getJws().isRfc7797UnencodedPayload(), digestCalculator);
				break;
			default:
				LOG.warn("Unsupported SigDMechanism '{}' has been found!", sigDMechanism);
		}
	}

	@Override
	public DSSMessageDigest getSignatureTimestampMessageDigest() {
		try {
			/*
			 * 5.3.4	The sigTst JSON object
			 *
			 * The input of the message imprint computation for the time-stamp tokens encapsulated
			 * by sigTst JSON object shall be the base64url-encoded JWS Signature Value.
			 */
			byte[] signatureTimestampData = getBase64UrlEncodedSignatureValue();
			return new DSSMessageDigest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, signatureTimestampData));

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}

	@Override
	public DSSMessageDigest getTimestampX1MessageDigest() {
		try {
			if (LOG.isTraceEnabled()) {
				LOG.trace("--->Get '{}' timestamp data", JAdESHeaderParameterNames.SIG_R_TST);
			}

			final JWS jws = signature.getJws();

			/*
			 * A.1.5.1	The sigRTst JSON object
			 *
			 * The message imprint computation input shall be the concatenation of the components,
			 * in the order they are listed below.
			 */
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

			/*
			 * 1) The value of the base64url-encoded JWS Signature Value.
			 */
			digestCalculator.update(getBase64UrlEncodedSignatureValue());

			/*
			 * 2) The character '.'.
			 */
			digestCalculator.update((byte) '.');

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

					if (timestampAttribute != null && timestampAttribute.equals(etsiUComponent)) {
						// the current timestamp is found, stop the iteration
						break;
					}

					if (isAllowedTypeEntry(etsiUComponent, JAdESHeaderParameterNames.SIG_TST,
							JAdESHeaderParameterNames.X_REFS, JAdESHeaderParameterNames.R_REFS,
							JAdESHeaderParameterNames.AX_REFS, JAdESHeaderParameterNames.AR_REFS)) {

						digestCalculator.update(getEtsiUComponentValue(etsiUComponent, canonicalizationAlgorithm));
					}

				}

			} else {
				LOG.warn("Unable to process 'etsiU' entries for a '{}' timestamp. "
						+ "The 'etsiU' components shall have a common format (Strings or Objects)!", JAdESHeaderParameterNames.SIG_R_TST);
			}

			final DSSMessageDigest messageDigest = digestCalculator.getMessageDigest(digestAlgorithm);
			if (LOG.isTraceEnabled()) {
				LOG.trace(MESSAGE_IMPRINT_MESSAGE, JAdESHeaderParameterNames.SIG_R_TST, messageDigest);
			}
			return messageDigest;

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}
	
	private boolean isAllowedTypeEntry(EtsiUComponent etsiUComponent, String... allowedTypes) {
		return Arrays.asList(allowedTypes).contains(etsiUComponent.getHeaderName());
	}

	@Override
	public DSSMessageDigest getTimestampX2MessageDigest() {
		try {
			if (LOG.isTraceEnabled()) {
				LOG.trace("--->Get '{}' timestamp data", JAdESHeaderParameterNames.RFS_TST);
			}

			JWS jws = signature.getJws();

			/*
			 * A.1.5.2.2 The rfsTst JSON object
			 *
			 * The message imprint computation input shall be the concatenation of the components,
			 * in the order they are listed below.
			 */
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

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
						digestCalculator.update(getEtsiUComponentValue(etsiUComponent, canonicalizationAlgorithm));
					}

				}

			} else {
				LOG.warn("Unable to process 'etsiU' entries for an '{}' timestamp. "
						+ "The 'etsiU' components shall have a common format (Strings or Objects)!", JAdESHeaderParameterNames.RFS_TST);
			}

			final DSSMessageDigest messageDigest = digestCalculator.getMessageDigest(digestAlgorithm);
			if (LOG.isTraceEnabled()) {
				LOG.trace(MESSAGE_IMPRINT_MESSAGE, JAdESHeaderParameterNames.RFS_TST, messageDigest);
			}
			return messageDigest;

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}

	@Override
	public DSSMessageDigest getArchiveTimestampMessageDigest() {
		try {
			if (LOG.isTraceEnabled()) {
				LOG.trace("--->Get '{}' timestamp data : {}", JAdESHeaderParameterNames.ARC_TST,
						(timestampToken == null ? "--> CREATION" : "--> VALIDATION"));
			}

			JWS jws = signature.getJws();

			/*
			 * 5.3.6.3.1 Processing (5.3.6.3 Computation of message-imprint)
			 *
			 * If the value of timeStamped is equal to "all" or it is absent, and the etsiU
			 * array contains base64url encoded unsigned JSON values, then the message
			 * imprint computation input shall be the concatenation of the components in the
			 * order they are listed below:
			 */
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

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
			writeSignedDataBinaries(digestCalculator);

			/*
			 * 3) The character '.'.
			 */
			digestCalculator.update((byte) '.');

			/*
			 * 4) The value of the JWS Protected Header, base64url encoded, followed by the
			 * character '.'.
			 */
			digestCalculator.update(jws.getEncodedHeader().getBytes());
			digestCalculator.update((byte) '.');

			/*
			 * 5) The value of the JAdES Signature Value, base64url encoded.
			 */
			digestCalculator.update(getBase64UrlEncodedSignatureValue());

			/*
			 * 6) The character '.'.
			 */
			digestCalculator.update((byte) '.');

			/*
			 * 7) If the elements of the etsiU array appear as the base64url encodings of
			 * the unsigned components, then proceed as specified in clause 5.3.6.3.1.1 of
			 * the present document. If the elements of the etsiU array appear as clear
			 * instances of unsigned components, then proceed as specified in clause
			 * 5.3.6.3.1.2 of the present document.
			 */
			List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
			if (DSSJsonUtils.checkComponentsUnicity(etsiU)) {

				JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
				for (EtsiUComponent etsiUComponent : etsiUHeader.getAttributes()) {

					if (timestampAttribute != null && timestampAttribute.equals(etsiUComponent)) {
						// the timestamp is reached, stop the iteration
						break;
					}

					digestCalculator.update(getEtsiUComponentValue(etsiUComponent, canonicalizationAlgorithm));
				}

			} else {
				LOG.warn("Unable to process 'etsiU' entries for an '{}' timestamp. "
						+ "The 'etsiU' components shall have a common format (Strings or Objects)!", JAdESHeaderParameterNames.ARC_TST);
			}

			final DSSMessageDigest messageDigest = digestCalculator.getMessageDigest(digestAlgorithm);
			if (LOG.isTraceEnabled()) {
				LOG.trace(MESSAGE_IMPRINT_MESSAGE, JAdESHeaderParameterNames.ARC_TST, messageDigest);
			}
			return messageDigest;

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}

	private byte[] getBase64UrlEncodedSignatureValue() {
		String messageImprint = signature.getJws().getEncodedSignature();
		if (LOG.isTraceEnabled()) {
			LOG.trace(MESSAGE_IMPRINT_MESSAGE, JAdESHeaderParameterNames.SIG_TST, messageImprint);
		}
		return messageImprint.getBytes();
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
