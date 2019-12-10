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

import java.util.Date;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;

/**
 * The usage of this interface permit the user to choose the underlying PDF library use to created PDF signatures.
 */
public interface PdfRevision {

	int[] getSignatureByteRange();
	
	/**
	 * Returns byte array of decoding the hexadecimal string present within the /Contents dictionary
	 * @return byte array
	 */
	byte[] getContents();

	void checkIntegrity();
	
	Date getSigningDate();

	/**
	 * @return a byte array representing the DTBS (without a signature, but with the placeholder)
	 */
	byte[] getSignedDocumentBytes();

	void addOuterSignature(PdfRevision signatureInfo);

	/**
	 * @return signatures that covers a document that contains this signature
	 */
	List<PdfRevision> getOuterSignatures();

	boolean isTimestampRevision();

	boolean doesSignatureCoverAllOriginalBytes();

	CMSSignedData getCMSSignedData();

	String uniqueId();
	
	/**
	 * Returns a PDF Signature Dictionary info container
	 * @return {@link PdfSignatureDictionary}
	 */
	PdfSignatureDictionary getPdfSigDictInfo();
	
	/**
	 * Returns a list of signature field names that refer the current object
	 * 
	 * @return list of {@link String} field names
	 */
	List<String> getFieldNames();
	
	/**
	 * Returns Signature Information Store content
	 * 
	 * @return list of {@link SignerInfo}s
	 */
	List<SignerInfo> getSignatureInformationStore();

}
