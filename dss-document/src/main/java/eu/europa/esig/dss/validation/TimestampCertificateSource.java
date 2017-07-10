package eu.europa.esig.dss.validation;

import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

@SuppressWarnings("serial")
public class TimestampCertificateSource extends CAdESCertificateSource {

	public TimestampCertificateSource(TimeStampToken timestampToken, CertificatePool certPool) {
		super(timestampToken.toCMSSignedData(), certPool);
	}

	@Override
	public List<CertificateToken> getEncapsulatedCertificates() {
		return super.getEncapsulatedCertificates();
	}

	@Override
	public List<CertificateToken> getKeyInfoCertificates() {
		return super.getKeyInfoCertificates();
	}

	@Override
	protected CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.TIMESTAMP;
	}

}
