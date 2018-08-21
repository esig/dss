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
package eu.europa.esig.dss.pdf.openpdf;

import java.security.cert.Certificate;
import java.util.Calendar;

import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfPKCS7;

import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.x509.CertificateToken;

class ITextPdfSignatureInfo extends ITextPdfSignatureOrDocTimestampInfo implements PdfSignatureInfo {

	public ITextPdfSignatureInfo(PdfPKCS7 pk, PdfDictionary signatureDictionary, CertificateToken signingCertificate, Calendar signingDate, Certificate[] chain, PdfDictionary documentDictionary, PdfDict outerCatalog, byte[] originalContent) {
		super(pk, signatureDictionary, signingCertificate, signingDate, chain, documentDictionary, outerCatalog, originalContent);
	}

}
