package eu.europa.esig.dss.validation.timestamp;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.validation.CMSCRLSource;

/**
 * CRLSource that retrieves information embedded to a {@link TimeStampToken}
 *
 */
@SuppressWarnings("serial")
public class TimestampCRLSource extends CMSCRLSource {

	TimestampCRLSource(TimeStampToken timeStampToken) {
		super(timeStampToken.toCMSSignedData(), timeStampToken.getUnsignedAttributes());
	}
	
	@Override
	protected RevocationOrigin getRevocationValuesOrigin() {
		return RevocationOrigin.TIMESTAMP_REVOCATION_VALUES;
	}

	@Override
	protected RevocationRefOrigin getCompleteRevocationRefsOrigin() {
		return RevocationRefOrigin.TIMESTAMP_REVOCATION_REFS;
	}

	@Override
	protected RevocationRefOrigin getAttributeRevocationRefsOrigin() {
		return RevocationRefOrigin.TIMESTAMP_REVOCATION_REFS;
	}

}
