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
package eu.europa.esig.dss.tsl;

import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSNotApplicableMethodException;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

/**
 * This class allows to extract all the trust anchors defined by the trusted lists. The LOTL is used as the entry point of the process.
 */
public class TrustedListsCertificateSource extends CommonTrustedCertificateSource {

	private static final Logger logger = LoggerFactory.getLogger(TrustedListsCertificateSource.class);

	private KeyStoreCertificateSource dssKeyStore;

	public void setDssKeyStore(KeyStoreCertificateSource dssKeyStore) {
		this.dssKeyStore = dssKeyStore;
	}

	/**
	 * The default constructor.
	 */
	public TrustedListsCertificateSource() {
		super();
		initWithKeyStore();
	}

	private void initWithKeyStore() {
		if (dssKeyStore !=null) {
			List<CertificateToken> certificatesFromKeyStore = dssKeyStore.getCertificatesFromKeyStore();
			if (CollectionUtils.isNotEmpty(certificatesFromKeyStore)) {
				for (CertificateToken certificateToken : certificatesFromKeyStore) {
					super.addCertificate(certificateToken);
				}
			}
		}
	}

	@Override
	protected CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.TRUSTED_LIST;
	}

	/**
	 * This method is not applicable for this kind of certificate source. You should use {@link #addCertificate(java.security.cert.X509Certificate, eu.europa.esig.dss.tsl.ServiceInfo)}
	 *
	 * @param certificate
	 *            the certificate you have to trust
	 * @return the corresponding certificate token
	 */
	@Override
	public CertificateToken addCertificate(final CertificateToken certificate) {
		throw new DSSNotApplicableMethodException(getClass());
	}

	/**
	 * Adds a service entry (current or history) to the list of certificate tokens.
	 *
	 * @param certificate
	 *            the certificate which identifies the trusted service
	 * @param serviceProvider
	 *            Object defining the trusted service provider, must be the parent of the trusted service
	 * @param service
	 *            Object defining the trusted service
	 * @param tlWellSigned
	 *            Indicates if the signature of trusted list is valid
	 */
	public void addCertificate(CertificateToken certificate, TSLServiceProvider serviceProvider, TSLService service, boolean tlWellSigned) {
		ServiceInfo serviceInfo = getServiceInfo(serviceProvider, service, tlWellSigned);
		addCertificate(certificate, serviceInfo);
	}

	public void addCertificate(X500Principal x500Principal, TSLServiceProvider serviceProvider, TSLService service, boolean tlWellSigned) {
		CertificateToken certificateToken = null;
		List<CertificateToken> certificateTokens = certPool.get(x500Principal);
		if (certificateTokens.size() > 0) {
			certificateToken = certificateTokens.get(0);
		} else {
			logger.debug("WARNING: There is currently no certificate with the given X500Principal: '{}' within the certificate pool!", x500Principal);
		}
		if (certificateToken != null) {
			addCertificate(certificateToken, serviceProvider, service,tlWellSigned);
		}
	}

	private ServiceInfo getServiceInfo(TSLServiceProvider serviceProvider, TSLService service, boolean tlWellSigned) {
		ServiceInfo serviceInfo = new ServiceInfo();

		serviceInfo.setTspName(serviceProvider.getName());
		serviceInfo.setTspTradeName(serviceProvider.getTradeName());
		serviceInfo.setTspPostalAddress(serviceProvider.getPostalAddress());
		serviceInfo.setTspElectronicAddress(serviceProvider.getElectronicAddress());

		serviceInfo.setServiceName(service.getName());
		serviceInfo.setType(service.getType());
		serviceInfo.setStatus(service.getStatus());
		serviceInfo.setStatusStartDate(service.getStartDate());
		serviceInfo.setStatusEndDate(service.getEndDate());

		List<TSLServiceExtension> extensions = service.getExtensions();
		if (CollectionUtils.isNotEmpty(extensions)) {
			for (TSLServiceExtension tslServiceExtension : extensions) {
				List<TSLConditionsForQualifiers> conditionsForQualifiers = tslServiceExtension.getConditionsForQualifiers();
				for (TSLConditionsForQualifiers tslConditionsForQualifiers : conditionsForQualifiers) {
					Condition condition = tslConditionsForQualifiers.getCondition();
					for (String qualifier : tslConditionsForQualifiers.getQualifiers()) {
						serviceInfo.addQualifierAndCondition(qualifier, condition);
					}
				}
			}
		}

		//TODO service.setExpiredCertsRevocationInfo(expiredCertsRevocationInfo);

		serviceInfo.setTlWellSigned(tlWellSigned);
		return serviceInfo;
	}

	public int getNumberOfTrustedCertificates() {
		return certPool.getNumberOfCertificates();
	}

}
