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
package eu.europa.esig.dss.tsl.dto;

import eu.europa.esig.dss.enumerations.TSLType;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TrustService;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.utils.Utils;

import java.util.Date;
import java.util.List;

/**
 * The parsing record DTO
 */
public class ParsingCacheDTO extends AbstractCacheDTO implements ParsingInfoRecord {
	
	private static final long serialVersionUID = 5464908480606825440L;

	/** The LOTL/TL TSLType */
	private TSLType tslType;

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

	/** List of found trust service providers */
	private List<TrustServiceProvider> trustServiceProviders;

	/** List of LOTL other pointers */
	private List<OtherTSLPointer> lotlOtherPointers;

	/** List of TL other pointers */
	private List<OtherTSLPointer> tlOtherPointers;

	/** List of pivot URLs */
	private List<String> pivotUrls;

	/** Signing certificate announcement URL */
	private String signingCertificateAnnouncementUrl;

	/** A list of error messages occurred during a structure validation */
	protected List<String> structureValidationMessages;

	/**
	 * Default constructor
	 */
	public ParsingCacheDTO() {}

	/**
	 * Copies the cache DTO
	 *
	 * @param cacheDTO {@link AbstractCacheDTO}
	 */
	public ParsingCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}

	@Override
	public TSLType getTSLType() {
		return tslType;
	}

	/**
	 * Sets the TSLType
	 *
	 * @param tslType {@link TSLType}
	 */
	public void setTSLType(TSLType tslType) {
		this.tslType = tslType;
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
	public List<TrustServiceProvider> getTrustServiceProviders() {
		return trustServiceProviders;
	}

	/**
	 * Sets trust service providers
	 *
	 * @param trustServiceProviders a list of {@link TrustServiceProvider}s
	 */
	public void setTrustServiceProviders(List<TrustServiceProvider> trustServiceProviders) {
		this.trustServiceProviders = trustServiceProviders;
	}

	@Override
	public List<OtherTSLPointer> getLotlOtherPointers() {
		return lotlOtherPointers;
	}

	/**
	 * Sets LOTL other pointers
	 *
	 * @param lotlOtherPointers a list of {@link OtherTSLPointer}s
	 */
	public void setLotlOtherPointers(List<OtherTSLPointer> lotlOtherPointers) {
		this.lotlOtherPointers = lotlOtherPointers;
	}

	@Override
	public List<OtherTSLPointer> getTlOtherPointers() {
		return tlOtherPointers;
	}

	/**
	 * Sets TL other pointers
	 *
	 * @param tlOtherPointers a list of {@link OtherTSLPointer}s
	 */
	public void setTlOtherPointers(List<OtherTSLPointer> tlOtherPointers) {
		this.tlOtherPointers = tlOtherPointers;
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
	public int getTSPNumber() {
		if (Utils.isCollectionNotEmpty(trustServiceProviders)) {
			return trustServiceProviders.size();
		}
		return 0;
	}

	@Override
	public int getTSNumber() {
		int tsNumber = 0;
		if (Utils.isCollectionNotEmpty(trustServiceProviders)) {
			for (TrustServiceProvider tsp : trustServiceProviders) {
				tsNumber += tsp.getServices().size();
			}
		}
		return tsNumber;
	}

	@Override
	public int getCertNumber() {
		int certNumber = 0;
		if (Utils.isCollectionNotEmpty(trustServiceProviders)) {
			for (TrustServiceProvider tsp : trustServiceProviders) {
				for (TrustService trustService : tsp.getServices()) {
					certNumber += trustService.getCertificates().size();
				}
			}
		}
		return certNumber;
	}

	@Override
	public List<String> getStructureValidationMessages() {
		return structureValidationMessages;
	}

	/**
	 * Sets the structure validation error messages
	 *
	 * @param structureValidationMessages a list of {@link String} error messages when occurred on the structure validation
	 */
	public void setStructureValidationMessages(List<String> structureValidationMessages) {
		this.structureValidationMessages = structureValidationMessages;
	}

}
