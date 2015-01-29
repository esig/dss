/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.pdf;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.pdf.pdfbox.PdfDssDict;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;

/**
 * The usage of this interface permit the user to choose the underlying PDF library use to created PDF signatures.
 *
 * @version $Revision: 1653 $ - $Date: 2013-02-01 11:48:52 +0100 (Fri, 01 Feb 2013) $
 */
public interface PdfSignatureOrDocTimestampInfo {

	int[] getSignatureByteRange();

	public static class DSSPadesNoSignatureFound extends DSSException {

	}

	SignatureCryptographicVerification checkIntegrity();


	X509Certificate[] getCertificates();

	String getLocation();

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

	PdfDssDict getDocumentDictionary();

	PdfDssDict getOuterCatalog();

	int uniqueId();

	void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo);

	/**
	 * @return signatures that covers a document that contains this signature
	 */
	Map<PdfSignatureOrDocTimestampInfo, Boolean> getOuterSignatures();

	boolean isTimestamp();
}
