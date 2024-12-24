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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.pdf.SigFieldPermissions;
import org.bouncycastle.cms.CMSSignedData;

import java.util.Date;

/**
 * Contains PDF signature dictionary information
 * 
 */
public interface PdfSignatureDictionary {

	/**
	 * Gets the signed/timestamped ByteRange
	 *
	 * @return {@link ByteRange}
	 */
	ByteRange getByteRange();

	/**
	 * Gets name of the signed
	 *
	 * @return {@link String}
	 */
	String getSignerName();

	/**
	 * Gets the signer's location
	 *
	 * @return {@link String}
	 */
	String getLocation();

	/**
	 * Gets the signer's contact info
	 *
	 * @return {@link String}
	 */
	String getContactInfo();

	/**
	 * Gets the signing reason
	 *
	 * @return {@link String}
	 */
	String getReason();

	/**
	 * Gets type of the dictionary
	 *
	 * @return {@link String}
	 */
	String getType();

	/**
	 * Gets the Filter value
	 *
	 * @return {@link String}
	 */
	String getFilter();

	/**
	 * Gets the SubFilter value
	 *
	 * @return {@link String}
	 */
	String getSubFilter();

	/**
	 * Gets the CMSSignedData from /Contents
	 *
	 * @return {@link CMSSignedData}
	 */
	CMSSignedData getCMSSignedData();

	/**
	 * Gets /Contents binaries (CMSSignedData)
	 *
	 * @return /Contents binaries
	 */
	byte[] getContents();

	/**
	 * Gets the claimed signing time
	 *
	 * @return {@link Date}
	 */
	Date getSigningDate();

	/**
	 * Returns a /DocMDP dictionary, when present
	 *
	 * @return {@link CertificationPermission}
	 */
	CertificationPermission getDocMDP();

	/**
	 * Returns a /FieldMDP dictionary, when present
	 *
	 * @return {@link SigFieldPermissions}
	 */
	SigFieldPermissions getFieldMDP();

	/**
	 * Verifies the equality of the current PdfSignatureDictionary with provided {@code signatureDictionary}.
	 * NOTE: this method is similar to {@code equals(PdfSignatureDictionary)} method,
	 * but also modifies the state of the object accessible from {@code isConsistent()} method.
	 * If none signature dictionary found in the signed revision, NULL may be provided.
	 *
	 * @return TRUE if the {@code PdfSignatureDictionary} is equal to the provided {@code signatureDictionary}, FALSE otherwise
	 * @param signatureDictionary {@link PdfSignatureDictionary} to compare with
	 */
	boolean checkConsistency(PdfSignatureDictionary signatureDictionary);

	/**
	 * Checks if the signature dictionary is consistent.
	 * NOTE: method {@code checkConsistency(PdfSignatureDictionary)} shall be executed before!
	 *
	 * @return TRUE if the {@code PdfSignatureDictionary} is consistent, FALSE otherwise
	 */
	boolean isConsistent();

}
