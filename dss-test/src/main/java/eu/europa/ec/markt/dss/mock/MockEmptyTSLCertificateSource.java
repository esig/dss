package eu.europa.ec.markt.dss.mock;

import java.util.Calendar;

import eu.europa.ec.markt.dss.TSLConstant;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CommonTrustedCertificateSource;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

public class MockEmptyTSLCertificateSource extends CommonTrustedCertificateSource {

	@Override
	protected CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.TRUSTED_STORE;
	}

	/**
	 * This method allows to define (to add) any certificate as trusted. A mock
	 * service information is associated to this certificate.
	 *
	 * @param cert
	 *            the certificate you have to trust
	 * @return the corresponding certificate token
	 */
	@Override
	public CertificateToken addCertificate(CertificateToken cert) {

		final ServiceInfo serviceInfo = getMockServiceInfo();
		final CertificateToken certToken = addCertificate(cert, serviceInfo);
		return certToken;
	}

	/**
	 * This method returns the mock service information. It is used when the
	 * framework user wants to declare a certificate as trusted one.
	 *
	 * @return
	 */
	private ServiceInfo getMockServiceInfo() {

		ServiceInfo serviceInfo = new ServiceInfo();
		serviceInfo.setTspName("DSS, Mock Office DSS-CA");
		serviceInfo.setType(TSLConstant.CA_QC);
		serviceInfo.setServiceName("MockTSPServiceName");
		serviceInfo.setStatus(TSLConstant.SERVICE_STATUS_UNDERSUPERVISION);
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.YEAR, -1);
		serviceInfo.setStatusStartDate(calendar.getTime());
		serviceInfo.setStatusEndDate(null);
		serviceInfo.setTlWellSigned(true);

		return serviceInfo;
	}
}
