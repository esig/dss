package eu.europa.esig.dss.asic.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
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
	private DSSDocument timestampedData;

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
		TimestampToken timestampToken = new TimestampToken(bcToken, type, validationCertPool);
		timestampToken.matchData(DSSUtils.toByteArray(timestampedData));
		return timestampToken;
	}

	@Override
	public void setCertificateVerifier(CertificateVerifier certVerifier) {
		this.certificateVerifier = certVerifier;
	}

	@Override
	public void setDetachedDocument(DSSDocument timestampedData) {
		this.timestampedData = timestampedData;
	}

}