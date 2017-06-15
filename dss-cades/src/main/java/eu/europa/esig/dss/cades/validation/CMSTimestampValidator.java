package eu.europa.esig.dss.cades.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.TimestampValidator;
import eu.europa.esig.dss.x509.TimestampType;

public class CMSTimestampValidator extends CMSDocumentValidator implements TimestampValidator {

	private final TimeStampToken bcToken;
	private final TimestampType type;
	private DSSDocument timestampedData;

	public CMSTimestampValidator(DSSDocument timestamp) {
		this(timestamp, null);
	}

	public CMSTimestampValidator(DSSDocument timestamp, TimestampType type) {
		super(timestamp);
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
	public void setTimestampedData(DSSDocument timestampedData) {
		this.timestampedData = timestampedData;
	}

}