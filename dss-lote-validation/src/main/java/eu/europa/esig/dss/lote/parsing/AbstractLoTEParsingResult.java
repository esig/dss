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
package eu.europa.esig.dss.lote.parsing;

import eu.europa.esig.dss.enumerations.ListType;
import eu.europa.esig.dss.model.lote.TrustedEntity;
import eu.europa.esig.dss.validation.job.parsing.AbstractParsingResult;

import java.util.Date;
import java.util.List;

/**
 * Abstract parsing result
 */
public abstract class AbstractLoTEParsingResult extends AbstractParsingResult {

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

	/** List of found trust service providers */
	private List<TrustedEntity> trustedEntities;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected AbstractLoTEParsingResult() {
		// empty
	}

	/**
	 * Gets the ListType
	 *
	 * @return {@link ListType}
	 */
	public ListType getType() {
		return type;
	}

	/**
	 * Sets the ListType
	 *
	 * @param type {@link String}
	 */
	public void setType(ListType type) {
		this.type = type;
	}

	/**
	 * Gets the sequence number
	 *
	 * @return sequence number
	 */
	public Integer getSequenceNumber() {
		return sequenceNumber;
	}

	/**
	 * Sets the sequence number
	 *
	 * @param sequenceNumber sequence number
	 */
	public void setSequenceNumber(Integer sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

	/**
	 * Gets the version
	 *
	 * @return version
	 */
	public Integer getVersion() {
		return version;
	}

	/**
	 * Sets the version
	 *
	 * @param version version
	 */
	public void setVersion(Integer version) {
		this.version = version;
	}

	/**
	 * Gets the territory (country)
	 *
	 * @return {@link String}
	 */
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

	/**
	 * Gets issuing date
	 *
	 * @return {@link Date}
	 */
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

	/**
	 * Gets next update date
	 *
	 * @return {@link Date}
	 */
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

	/**
	 * Gets distribution points
	 *
	 * @return a list of {@link String}s
	 */
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

	/**
	 * Gets trusted entities
	 *
	 * @return a list of {@link TrustedEntity}s
	 */
	public List<TrustedEntity> getTrustedEntities() {
		return trustedEntities;
	}

	/**
	 * Sets trusted entities
	 *
	 * @param trustedEntities a list of {@link TrustedEntity}s
	 */
	public void setTrustedEntities(List<TrustedEntity> trustedEntities) {
		this.trustedEntities = trustedEntities;
	}

}
