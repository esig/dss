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
package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

public interface SignatureRevocationSource<T extends RevocationToken> {
	
	/**
	 * Retrieves the list of all {@link RevocationToken}s present in the CMS
	 * SignedData
	 * 
	 * NOTE: Applicable only for CAdES revocation sources
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getCMSSignedDataRevocationTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in the SignedData
	 * of a Timestamp Token
	 * 
	 * NOTE: Applicable only for CAdES revocation sources
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getTimestampSignedDataRevocationTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'RevocationValues' element
	 * 
	 * NOTE: Applicable only for CAdES and XAdES revocation sources
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'AttributeRevocationValues' element
	 * 
	 * NOTE: Applicable only for XAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getAttributeRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'TimestampValidationData' element
	 * 
	 * NOTE: Applicable only for XAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getTimestampValidationDataTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'DSS'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getDSSDictionaryTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'VRI'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getVRIDictionaryTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in the Timestamp
	 * 
	 * NOTE: Applicable only for CAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getTimestampRevocationValuesTokens();

}
