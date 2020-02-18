package eu.europa.esig.dss.jades.signature;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.SigningOperation;
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
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, JAdESSignatureParameters parameters) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		
		assertSigningDateInCertificateValidityRange(parameters);
		
		JAdESLevelBaselineB jadesLevelBaselineB = new JAdESLevelBaselineB(certificateVerifier);
		byte[] dataToSign = jadesLevelBaselineB.getDataToSign(toSignDocument, parameters);
		
		return new ToBeSigned(dataToSign);
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, JAdESSignatureParameters parameters,
			SignatureValue signatureValue) {
		
		JAdESLevelBaselineB jadesLevelBaselineB = new JAdESLevelBaselineB(certificateVerifier);
		String dataToSignString = jadesLevelBaselineB.getDataToSignConcatenatedString(toSignDocument, parameters);
		
		String signatureString = JAdESUtils.concatenate(dataToSignString, JAdESUtils.toBase64Url(signatureValue.getValue()));
		return new InMemoryDocument(signatureString.getBytes(),
				getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()), MimeType.JSON);
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, JAdESSignatureParameters parameters) {
		throw new UnsupportedOperationException("Extension is not supported with JAdES");
	}

	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, JAdESSignatureParameters parameters) {
		// TODO Auto-generated method stub
		return null;
	}

}
