package eu.europa.esig.dss.jades.signature;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class JAdESService extends AbstractSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESService.class);

	/**
	 * This is the constructor to create an instance of the {@code JAdESService}. A
	 * certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information
	 *                            on the sources to be used in the validation
	 *                            process in the context of a signature.
	 */
	public JAdESService(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ JAdESService created");
	}
	
	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, JAdESSignatureParameters parameters) {
		return getContentTimestamp(Arrays.asList(toSignDocument), parameters);
	}
	
	/**
	 * This methods allows to create a TimestampToken for a detached JAdES (with a 'sigD' parameter).
	 * NOTE: The toSignDocuments must be present in the same order they will be passed to signature computation process
	 * 
	 * @param toSignDocuments a list of {@link DSSDocument}s to be timestamped
	 * @param parameters {@link JAdESSignatureParameters}
	 * @return content {@link TimestampToken}
	 */
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, JAdESSignatureParameters parameters) {
		if (tspSource == null) {
			throw new DSSException("A TSPSource is required !");
		}
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("Original documents must be provided to generate a content timestamp!");
		}
		
		byte[] concatenationResult = DSSUtils.EMPTY_BYTE_ARRAY;
		for (DSSDocument document : toSignDocuments) {
			byte[] documentBinaries = DSSUtils.toByteArray(document);
			String base64UrlEncodedDoc = JAdESUtils.toBase64Url(documentBinaries);
			concatenationResult = DSSUtils.concatenate(concatenationResult, base64UrlEncodedDoc.getBytes());
		}
		DigestAlgorithm digestAlgorithm = parameters.getContentTimestampParameters().getDigestAlgorithm();
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, concatenationResult));
		try {
			return new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
		} catch (TSPException | IOException | CMSException e) {
			throw new DSSException("Cannot create a content TimestampToken", e);
		}
	}

	@Override
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, JAdESSignatureParameters parameters) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		
		assertSigningDateInCertificateValidityRange(parameters);
		
		JAdESCompactBuilder jadesCompactBuilder = new JAdESCompactBuilder(certificateVerifier, parameters, toSignDocument);
		String dataToBeSignedString = jadesCompactBuilder.buildDataToBeSigned();
		
		// The data to sign by RFC 7515 shall be ASCII-encoded
		byte[] dataToSign = JAdESUtils.getAsciiBytes(dataToBeSignedString);
		
		return new ToBeSigned(dataToSign);
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, JAdESSignatureParameters parameters,
			SignatureValue signatureValue) {
		
		JAdESCompactBuilder jadesCompactBuilder = new JAdESCompactBuilder(certificateVerifier, parameters, toSignDocument);
		String headerAndPayloadString = jadesCompactBuilder.build();
		
		String signatureString = JAdESUtils.concatenate(headerAndPayloadString, JAdESUtils.toBase64Url(signatureValue.getValue()));
		return new InMemoryDocument(signatureString.getBytes(),
				getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()), MimeType.JOSE);
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, JAdESSignatureParameters parameters) {
		throw new UnsupportedOperationException("Extension is not supported with JAdES");
	}

}
