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
package eu.europa.esig.dss.pdf;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import eu.europa.esig.dss.validation.SignatureCryptographicVerification;

/**
 * The usage of this interface permit the user to choose the underlying PDF library use to created PDF signatures.
 */
public interface PdfSignatureOrDocTimestampInfo {

	int[] getSignatureByteRange();

	SignatureCryptographicVerification checkIntegrity();

	String getLocation();

	String getContactInfo();

	String getReason();

	String getSubFilter();

	Date getSigningDate();

	X509Certificate getSigningCertificate();

	/**
	 * @return the byte of what is signed (without signature, but with the placeholder)
	 */
	byte[] getSignedDocumentBytes();

	/**
	 * This method return a few extra bytes (the header of the signature) but it's correctly ignored by PDF Box
	 *
	 * @return the byte of the originally signed document (without this signature)
	 */
	byte[] getOriginalBytes();

	PdfDssDict getDssDictionary();

	String uniqueId();

	void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo);

	/**
	 * @return signatures that covers a document that contains this signature
	 */
	Set<PdfSignatureOrDocTimestampInfo> getOuterSignatures();

	boolean isTimestamp();
}