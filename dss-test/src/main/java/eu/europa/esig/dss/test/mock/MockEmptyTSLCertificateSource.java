/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.test.mock;

import java.util.Calendar;

import eu.europa.esig.dss.TSLConstant;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;

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
