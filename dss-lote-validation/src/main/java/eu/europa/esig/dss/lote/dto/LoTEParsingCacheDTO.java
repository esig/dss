/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.lote.dto;

import eu.europa.esig.dss.enumerations.ListType;
import eu.europa.esig.dss.model.lote.OtherListPointer;
import eu.europa.esig.dss.model.lote.TrustedEntity;
import eu.europa.esig.dss.model.lote.TrustedEntityService;
import eu.europa.esig.dss.model.lote.record.LoTEParsingInfoRecord;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.dto.AbstractCacheDTO;
import eu.europa.esig.dss.validation.job.dto.AbstractParsingCacheDTO;

import java.util.Date;
import java.util.List;

/**
 * The parsing record DTO
 */
public class LoTEParsingCacheDTO extends AbstractParsingCacheDTO implements LoTEParsingInfoRecord {
	
	private static final long serialVersionUID = 5464908480606825440L;

	/** The List Type */
	private ListType type;

	/** The LOTL/TL sequence number */
	private Integer sequenceNumber;

	/** LOTL/TL version */
	private Integer version;

	/** The country (territory) */
	private String territory;

	/** The issuance date of the LOTL/TL */
	private Date issueDate;

	/** The next update date */
	private Date nextUpdateDate;

	/** The distribution points urls */
	private List<String> distributionPoints;

	/** List of found trusted entities */
	private List<TrustedEntity> trustedEntities;

	/** Self pointer to teh current list */
	private List<OtherListPointer> currentListPointers;

	/** Pointers to other lists */
	private List<OtherListPointer> otherListPointers;

	/** List of pivot URLs */
	private List<String> pivotUrls;

	/** Signing certificate announcement URL */
	private String signingCertificateAnnouncementUrl;

	/**
	 * Default constructor
	 */
	public LoTEParsingCacheDTO() {
		// empty
	}

	/**
	 * Copies the cache DTO
	 *
	 * @param cacheDTO {@link AbstractCacheDTO}
	 */
	public LoTEParsingCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}

	@Override
	public ListType getType() {
		return type;
	}

	/**
	 * Sets the List Type
	 *
	 * @param type {@link ListType}
	 */
	public void setType(ListType type) {
		this.type = type;
	}

	@Override
	public Integer getSequenceNumber() {
		return sequenceNumber;
	}

	/**
	 * Sets the sequence number
	 *
	 * @param sequenceNumber {@link Integer}
	 */
	public void setSequenceNumber(Integer sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

	@Override
	public Integer getVersion() {
		return version;
	}

	/**
	 * Sets the version
	 *
	 * @param version {@link Integer}
	 */
	public void setVersion(Integer version) {
		this.version = version;
	}

	@Override
	public String getTerritory() {
		return territory;
	}

	/**
	 * Sets the territory
	 *
	 * @param territory {@link String}
	 */
	public void setTerritory(String territory) {
		this.territory = territory;
	}

	@Override
	public Date getIssueDate() {
		return issueDate;
	}

	/**
	 * Sets the issue date
	 *
	 * @param issueDate {@link Date}
	 */
	public void setIssueDate(Date issueDate) {
		this.issueDate = issueDate;
	}

	@Override
	public Date getNextUpdateDate() {
		return nextUpdateDate;
	}

	/**
	 * Sets the next update date
	 *
	 * @param nextUpdateDate {@link Date}
	 */
	public void setNextUpdateDate(Date nextUpdateDate) {
		this.nextUpdateDate = nextUpdateDate;
	}

	@Override
	public List<String> getDistributionPoints() {
		return distributionPoints;
	}

	/**
	 * Sets a list of distribution point urls
	 *
	 * @param distributionPoints a list of {@link String}s
	 */
	public void setDistributionPoints(List<String> distributionPoints) {
		this.distributionPoints = distributionPoints;
	}

	@Override
	public List<TrustedEntity> getTrustedEntities() {
		return trustedEntities;
		}

	/**
	 * Sets trust service providers
	 *
	 * @param trustedEntities a list of {@link TrustedEntity}s
	 */
	public void setTrustedEntities(List<TrustedEntity> trustedEntities) {
		this.trustedEntities = trustedEntities;
	}

	@Override
	public List<OtherListPointer> getCurrentListPointers() {
		return currentListPointers;
	}

	/**
	 * Sets List of Lists other pointers
	 *
	 * @param currentListPointers a list of {@link OtherListPointer}s
	 */
	public void setCurrentListPointers(List<OtherListPointer> currentListPointers) {
		this.currentListPointers = currentListPointers;
	}

	@Override
	public List<OtherListPointer> getOtherListPointers() {
		return otherListPointers;
	}

	/**
	 * Sets Lists other pointers
	 *
	 * @param otherListPointers a list of {@link OtherListPointer}s
	 */
	public void setOtherListPointers(List<OtherListPointer> otherListPointers) {
		this.otherListPointers = otherListPointers;
	}

	@Override
	public List<String> getPivotUrls() {
		return pivotUrls;
	}

	/**
	 * Sets pivot URLs
	 *
	 * @param pivotUrls a list of {@link String}s
	 */
	public void setPivotUrls(List<String> pivotUrls) {
		this.pivotUrls = pivotUrls;
	}

	@Override
	public String getSigningCertificateAnnouncementUrl() {
		return signingCertificateAnnouncementUrl;
	}

	/**
	 * Sets the signing certificate announcement URL
	 *
	 * @param signingCertificateAnnouncementUrl {@link String}
	 */
	public void setSigningCertificateAnnouncementUrl(String signingCertificateAnnouncementUrl) {
		this.signingCertificateAnnouncementUrl = signingCertificateAnnouncementUrl;
	}

	@Override
	public int getTrustedEntitiesNumber() {
		if (Utils.isCollectionNotEmpty(trustedEntities)) {
			return trustedEntities.size();
		}
		return 0;
	}

	@Override
	public int getTrustedServicesNumber() {
		int tsNumber = 0;
		if (Utils.isCollectionNotEmpty(trustedEntities)) {
			for (TrustedEntity tsp : trustedEntities) {
				tsNumber += tsp.getServices().size();
			}
		}
		return tsNumber;
	}

	@Override
	public int getCertNumber() {
		int certNumber = 0;
		if (Utils.isCollectionNotEmpty(trustedEntities)) {
			for (TrustedEntity tsp : trustedEntities) {
				for (TrustedEntityService trustService : tsp.getServices()) {
					certNumber += trustService.getCertificates().size();
				}
			}
		}
		return certNumber;
	}

}
