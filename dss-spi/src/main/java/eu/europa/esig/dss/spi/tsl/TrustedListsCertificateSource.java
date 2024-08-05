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

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustPropertiesCertificateSource;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class allows injection of trusted certificates from Trusted Lists
 */
@SuppressWarnings("serial")
public class TrustedListsCertificateSource extends CommonTrustedCertificateSource implements TrustPropertiesCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(TrustedListsCertificateSource.class);

	/** The TL Validation job summary */
	private TLValidationJobSummary summary;

	/** The map of trust properties by EntityIdentifier (public keys) */
	private Map<EntityIdentifier, List<TrustProperties>> trustPropertiesByEntity = new HashMap<>();

	/** The map of trust time periods by EntityIdentifier */
	private Map<EntityIdentifier, List<CertificateTrustTime>> trustTimeByEntity = new HashMap<>();

	/**
	 * The default constructor.
	 */
	public TrustedListsCertificateSource() {
		super();
	}

	/**
	 * Gets TL Validation job summary
	 *
	 * @return {@link TLValidationJobSummary}
	 */
	public TLValidationJobSummary getSummary() {
		return summary;
	}

	/**
	 * Sets TL Validation job summary
	 *
	 * @param summary {@link TLValidationJobSummary}
	 */
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

	@Override
	public synchronized void setTrustPropertiesByCertificates(final Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts) {
		this.trustPropertiesByEntity = new HashMap<>(); // reinit the map
		super.reset();
		trustPropertiesByCerts.forEach(this::addCertificate);
	}
	
	private void addCertificate(CertificateToken certificateToken, List<TrustProperties> trustPropertiesList) {
		super.addCertificate(certificateToken);
		
		EntityIdentifier entityKey = certificateToken.getEntityKey();
		List<TrustProperties> list = trustPropertiesByEntity.computeIfAbsent(entityKey, k -> new ArrayList<>());
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
	public synchronized void setTrustTimeByCertificates(Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCertificate) {
		this.trustTimeByEntity = new HashMap<>(); // reinit the map
		trustTimeByCertificate.forEach(this::addCertificateTrustTimes);
	}

	private void addCertificateTrustTimes(CertificateToken certificateToken, List<CertificateTrustTime> certificateTrustTimes) {
		super.addCertificate(certificateToken);

		EntityIdentifier entityKey = certificateToken.getEntityKey();
		List<CertificateTrustTime> list = trustTimeByEntity.computeIfAbsent(entityKey, k -> new ArrayList<>());
		for (CertificateTrustTime trustTime : certificateTrustTimes) {
			if (!list.contains(trustTime)) {
				list.add(trustTime);
			}
		}
	}

	@Override
	public synchronized CertificateTrustTime getTrustTime(CertificateToken token) {
		List<CertificateTrustTime> trustTimes = trustTimeByEntity.get(token.getEntityKey());
		if (Utils.isCollectionNotEmpty(trustTimes)) {
			CertificateTrustTime certificateTrustTime = null;
			for (CertificateTrustTime trustTime : trustTimes) {
				if (certificateTrustTime == null) {
					certificateTrustTime = trustTime;
				} else {
					certificateTrustTime = certificateTrustTime.getJointTrustTime(trustTime.getStartDate(), trustTime.getEndDate());
				}
			}
			return certificateTrustTime;
		} else {
			return new CertificateTrustTime(); // no trust anchor expiration time defined
		}
	}

	@Override
	public boolean isTrustedAtTime(CertificateToken certificateToken, Date controlTime) {
		EntityIdentifier entityKey = certificateToken.getEntityKey();
		List<CertificateTrustTime> certificateTrustTimeList = trustTimeByEntity.get(entityKey);
		if (Utils.isCollectionNotEmpty(certificateTrustTimeList)) {
			return certificateTrustTimeList.stream().anyMatch(t -> t.isTrustedAtTime(controlTime));
		}
		return false;
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
		List<String> urls = new ArrayList<>();
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

	/**
	 * Gets the number of trusted public keys
	 *
	 * @return the number of trusted public keys
	 */
	public int getNumberOfTrustedPublicKeys() {
		return trustPropertiesByEntity.size();
	}

}
