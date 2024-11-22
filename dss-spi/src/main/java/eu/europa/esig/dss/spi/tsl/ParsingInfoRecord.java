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

import eu.europa.esig.dss.enumerations.TSLType;

import java.util.Date;
import java.util.List;

/**
 * Represents a parsing result record
 */
public interface ParsingInfoRecord extends InfoRecord {

	/**
	 * Gets the LOTL/TL TSLType
	 *
	 * @return {@link TSLType}
	 */
	TSLType getTSLType();

	/**
	 * Gets the LOTL/TL sequence number
	 *
	 * @return {@link Integer}
	 */
	Integer getSequenceNumber();

	/**
	 * Gets LOTL/TL version
	 *
	 * @return {@link Integer}
	 */
	Integer getVersion();

	/**
	 * Gets the LOTL/TL territory (country)
	 *
	 * @return {@link String}
	 */
	String getTerritory();

	/**
	 * Gets issuing date
	 *
	 * @return {@link Date}
	 */
	Date getIssueDate();

	/**
	 * Gets next update date
	 *
	 * @return {@link Date}
	 */
	Date getNextUpdateDate();

	/**
	 * Gets distribution points
	 *
	 * @return a list of {@link String}s
	 */
	List<String> getDistributionPoints();

	/**
	 * Gets trust service providers
	 *
	 * @return a list of {@link TrustServiceProvider}s
	 */
	List<TrustServiceProvider> getTrustServiceProviders();

	/**
	 * Gets LOTL other TSL pointers
	 *
	 * @return a list of {@link OtherTSLPointer}s
	 */
	List<OtherTSLPointer> getLotlOtherPointers();

	/**
	 * Gets TL other TSL pointers
	 *
	 * @return a list of {@link OtherTSLPointer}s
	 */
	List<OtherTSLPointer> getTlOtherPointers();

	/**
	 * Gets pivot URLs
	 *
	 * @return a list of {@link String}s
	 */
	List<String> getPivotUrls();

	/**
	 * Gets signing certificate announcement URL
	 *
	 * @return {@link String}
	 */
	String getSigningCertificateAnnouncementUrl();
	
	/**
	 * Returns a number of all {@code TrustServiceProvider}s present in the TL
	 *
	 * @return TSP number
	 */
	int getTSPNumber();
	
	/**
	 * Returns a number of all {@code TrustService}s present in the TL
	 *
	 * @return TS number
	 */
	int getTSNumber();
	
	/**
	 * Returns a number of all {@code CertificateToken}s present in the TL
	 *
	 * @return number of certificates
	 */
	int getCertNumber();

	/**
	 * Gets a list of error messages when occurred during the structure validation
	 *
	 * @return a list of {@link String} structure validation messages, empty list if the structure validation succeeded
	 */
	List<String> getStructureValidationMessages();
	
}
