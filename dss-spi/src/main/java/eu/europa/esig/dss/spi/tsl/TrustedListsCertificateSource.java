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
package eu.europa.esig.dss.spi.tsl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class allows to inject trusted certificates from Trusted Lists
 */
@SuppressWarnings("serial")
public class TrustedListsCertificateSource extends CommonTrustedCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(TrustedListsCertificateSource.class);

	private TLValidationJobSummary summary;

	private Map<String, List<TrustProperties>> trustPropertiesByEntity;

	/**
	 * The default constructor.
	 */
	public TrustedListsCertificateSource() {
		super();
	}

	public TLValidationJobSummary getSummary() {
		return summary;
	}

	public void setSummary(TLValidationJobSummary summary) {
		this.summary = summary;
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.TRUSTED_LIST;
	}

	/**
	 * This method is not applicable for this kind of certificate source. You should
	 * use {@link #setTrustPropertiesByCertificates}
	 *
	 * @param certificate
	 *                    the certificate you have to trust
	 * @return the corresponding certificate token
	 */
	@Override
	public CertificateToken addCertificate(CertificateToken certificate) {
		throw new UnsupportedOperationException("Cannot directly add certificate to a TrustedListsCertificateSource");
	}

	/**
	 * The method allows to fill the CertificateSource
	 * @param trustPropertiesByCerts map between {@link CertificateToken}s and a list of {@link TrustProperties}
	 */
	public synchronized void setTrustPropertiesByCertificates(final Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts) {
		this.trustPropertiesByEntity = new HashMap<String, List<TrustProperties>>(); // reinit the map
		trustPropertiesByCerts.forEach((certificateToken, trustPropertiesList) -> {
			addCertificate(certificateToken, trustPropertiesList);
		});
	}
	
	private void addCertificate(CertificateToken certificateToken, List<TrustProperties> trustPropertiesList) {
		super.addCertificate(certificateToken);
		
		String entityKey = certificateToken.getEntityKey();
		List<TrustProperties> list = trustPropertiesByEntity.get(entityKey);
		if (list == null) {
			list = new ArrayList<TrustProperties>();
			trustPropertiesByEntity.put(entityKey, list);
		}
		for (TrustProperties trustProperties : trustPropertiesList) {
			if (!list.contains(trustProperties)) {
				list.add(trustProperties);
			}
		}
	}

	@Override
	public synchronized List<TrustProperties> getTrustServices(CertificateToken token) {
		List<TrustProperties> currentTrustProperties = trustPropertiesByEntity.get(token.getEntityKey());
		if (currentTrustProperties != null) {
			return currentTrustProperties;
		} else {
			return Collections.emptyList();
		}
	}

	@Override
	public List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor) {
		return getServiceSupplyPoints(trustAnchor, "ocsp");
	}

	@Override
	public List<String> getAlternativeCRLUrls(CertificateToken trustAnchor) {
		return getServiceSupplyPoints(trustAnchor, "crl", "certificateRevocationList");
	}

	private List<String> getServiceSupplyPoints(CertificateToken trustAnchor, String... keywords) {
		List<String> urls = new ArrayList<String>();
		List<TrustProperties> trustPropertiesList = getTrustServices(trustAnchor);
		for (TrustProperties trustProperties : trustPropertiesList) {
			for (TrustServiceStatusAndInformationExtensions statusAndInfo : trustProperties.getTrustService()) {
				List<String> serviceSupplyPoints = statusAndInfo.getServiceSupplyPoints();
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

	public int getNumberOfTrustedPublicKeys() {
		return trustPropertiesByEntity.size();
	}

}
