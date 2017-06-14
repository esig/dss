package eu.europa.esig.dss.asic.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.TimestampValidator;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;

public class CMSTimestampValidator extends CMSDocumentValidator implements TimestampValidator {

	private final TimeStampToken bcToken;
	private final TimestampType type;

	public CMSTimestampValidator(DSSDocument document, TimestampType type, CertificatePool certificatePool) {
		super(document);
		try {
			this.bcToken = new TimeStampToken(cmsSignedData);
			this.type = type;
		} catch (IOException | TSPException e) {
			throw new DSSException("Unable to parse timestamp", e);
		}
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		return Collections.emptyList();
	}

	@Override
	public TimestampToken getTimestamp() {
		return new TimestampToken(bcToken, type, validationCertPool);
	}

	@Override
	public void setCertificateVerifier(CertificateVerifier certVerifier) {
		// TODO Auto-generated method stub

	}

	@Override
	public void setDetachedDocument(DSSDocument timestampedDocument) {
		// TODO Auto-generated method stub

	}

}