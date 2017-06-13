package eu.europa.esig.dss.asic.validation;

import java.io.IOException;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.x509.CertificatePool;

public class TimestampValidator extends CMSDocumentValidator implements ASiCSignatureValidator {

	private final TimeStampToken timestampToken;

	public TimestampValidator(DSSDocument doc) {
		super(doc);

		try {
			this.timestampToken = new TimeStampToken(cmsSignedData);
		} catch (TSPException | IOException e) {
			throw new DSSException("Unable to parse timestamp", e);
		}
	}

	@Override
	public void setValidationCertPool(CertificatePool validationCertPool) {
		this.validationCertPool = validationCertPool;
	}

}
