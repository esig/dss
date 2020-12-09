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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.Date;
import java.util.List;

/**
 * Validation result record
 */
public interface ValidationInfoRecord extends InfoRecord {

	/**
	 * Gets validation Indication
	 *
	 * @return {@link Indication}
	 */
	Indication getIndication();

	/**
	 * Gets validation SubIndication
	 *
	 * @return {@link SubIndication}
	 */
	SubIndication getSubIndication();

	/**
	 * Gets the (claimed) signing time
	 *
	 * @return {@link Date}
	 */
	Date getSigningTime();

	/**
	 * Gets the signing certificate
	 *
	 * @return {@link CertificateToken}
	 */
	CertificateToken getSigningCertificate();

	/**
	 * Gets a list of signing candidates
	 *
	 * @return a list of {@link CertificateToken}s
	 */
	List<CertificateToken> getPotentialSigners();

	/**
	 * Gets if the signature is valid
	 *
	 * @return TRUE if the validation succeeded, FALSE otherwise
	 */
	boolean isValid();

	/**
	 * Gets if the validation result is indeterminate
	 *
	 * @return TRUE if the validation result is indeterminate, FALSE otherwise
	 */
	boolean isIndeterminate();

	/**
	 * Gets if the signature is invalid
	 *
	 * @return TRUE if the validation failed, FALSE otherwise
	 */
	boolean isInvalid();

}
