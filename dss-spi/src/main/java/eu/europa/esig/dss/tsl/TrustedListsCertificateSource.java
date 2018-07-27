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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;

/**
 * This class allows to inject trusted certificates from Trusted Lists
 */
public class TrustedListsCertificateSource extends CommonTrustedCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(TrustedListsCertificateSource.class);

	private Map<String, TLInfo> tlInfos = new HashMap<String, TLInfo>();

	/**
	 * The default constructor.
	 */
	public TrustedListsCertificateSource() {
		super();
	}

	@Override
	protected CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.TRUSTED_LIST;
	}

	/**
	 * This method is not applicable for this kind of certificate source. You should
	 * use
	 * {@link #addCertificate(eu.europa.esig.dss.x509.CertificateToken, eu.europa.esig.dss.tsl.ServiceInfo)}
	 *
	 * @param certificate
	 *                    the certificate you have to trust
	 * @return the corresponding certificate token
	 */
	@Override
	public CertificateToken addCertificate(CertificateToken certificate) {
		throw new UnsupportedOperationException("Cannot directly add certificate to a TrustedListsCertificateSource");
	}

	public void updateTlInfo(String countryCode, TLInfo info) {
		tlInfos.put(countryCode, info);
	}

	public TLInfo getTlInfo(String countryCode) {
		return tlInfos.get(countryCode);
	}

	public TLInfo getLotlInfo() {
		for (TLInfo tlInfo : tlInfos.values()) {
			if (tlInfo.isLotl()) {
				return tlInfo;
			}
		}
		return null;
	}

	public Map<String, TLInfo> getSummary() {
		return tlInfos;
	}

	public Set<ServiceInfo> getTrustServices(CertificateToken token) {
		return certPool.getRelatedTrustServices(token);
	}

	public List<String> getOCSPUrlsFromServiceSupplyPoint(CertificateToken certificateToken) {
		return getServiceSupplyPoints(certificateToken, "ocsp");
	}

	public List<String> getCRLUrlsFromServiceSupplyPoint(CertificateToken certificateToken) {
		return getServiceSupplyPoints(certificateToken, "crl", "certificateRevocationList");
	}

	private List<String> getServiceSupplyPoints(CertificateToken certificateToken, String... keywords) {
		List<String> urls = new ArrayList<String>();
		CertificateToken trustAnchor = certPool.getTrustAnchor(certificateToken);
		Set<ServiceInfo> trustServices = certPool.getRelatedTrustServices(trustAnchor);

		for (ServiceInfo serviceInfo : trustServices) {
			for (ServiceInfoStatus serviceInfoStatus : serviceInfo.getStatus()) {
				List<String> serviceSupplyPoints = serviceInfoStatus.getServiceSupplyPoints();
				if (Utils.isCollectionNotEmpty(serviceSupplyPoints)) {
					for (String serviceSupplyPoint : serviceSupplyPoints) {
						for (String keyword : keywords) {
							if (serviceSupplyPoint.contains(keyword)) {
								LOG.debug("ServiceSupplyPoints (TL) found for keyword '{}'", keyword);
								urls.add(serviceSupplyPoint);
							}
						}
					}
				}
			}
		}

		return urls;
	}

}
