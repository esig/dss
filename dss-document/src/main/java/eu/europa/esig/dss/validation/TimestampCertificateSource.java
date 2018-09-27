package eu.europa.esig.dss.validation;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;

@SuppressWarnings("serial")
public class TimestampCertificateSource extends CAdESCertificateSource {

	public TimestampCertificateSource(TimeStampToken timestampToken, CertificatePool certPool) {
		super(timestampToken.toCMSSignedData(), certPool);
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.TIMESTAMP;
	}

}
