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

import java.util.Date;
import java.util.List;

public interface ParsingInfoRecord extends InfoRecord {
	
	Integer getSequenceNumber();
	
	Integer getVersion();
	
	String getTerritory();
	
	Date getIssueDate();
	
	Date getNextUpdateDate();
	
	List<String> getDistributionPoints();
	
	List<TrustServiceProvider> getTrustServiceProviders();
	
	List<OtherTSLPointer> getLotlOtherPointers();
	
	List<OtherTSLPointer> getTlOtherPointers();
	
	List<String> getPivotUrls();
	
	String getSigningCertificateAnnouncementUrl();
	
	/**
	 * Returns a number of all {@code TrustServiceProvider}s present in the TL
	 * @return TSP number
	 */
	int getTSPNumber();
	
	/**
	 * Returns a number of all {@code TrustService}s present in the TL
	 * @return TS number
	 */
	int getTSNumber();
	
	/**
	 * Returns a number of all {@code CertificateToken}s present in the TL
	 * @return number of certificates
	 */
	int getCertNumber();
	
}
