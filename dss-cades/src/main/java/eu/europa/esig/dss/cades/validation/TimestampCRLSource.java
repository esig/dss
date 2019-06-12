package eu.europa.esig.dss.cades.validation;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.x509.RevocationOrigin;

/**
 * CRLSource that retrieves information embedded to a {@link TimeStampToken}
 *
 */
@SuppressWarnings("serial")
public class TimestampCRLSource extends CAdESCRLSource {

	TimestampCRLSource(TimeStampToken timeStampToken) {
		super(timeStampToken.toCMSSignedData(), timeStampToken.getUnsignedAttributes());
	}
	
	@Override
	protected RevocationOrigin getInternalRevocationValuesOrigin() {
		return RevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES;
	}

	@Override
	protected RevocationOrigin getCompleteRevocationRefsOrigin() {
		return RevocationOrigin.TIMESTAMP_REVOCATION_REFS;
	}

	@Override
	protected RevocationOrigin getAttributeRevocationRefsOrigin() {
		return RevocationOrigin.TIMESTAMP_REVOCATION_REFS;
	}

}
