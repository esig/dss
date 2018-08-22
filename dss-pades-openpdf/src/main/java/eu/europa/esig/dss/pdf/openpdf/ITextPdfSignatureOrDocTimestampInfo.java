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

import java.io.ByteArrayOutputStream;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.cms.CMSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfString;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.x509.CertificateToken;

public class ITextPdfSignatureOrDocTimestampInfo implements PdfSignatureOrDocTimestampInfo {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPdfSignatureOrDocTimestampInfo.class);

	private PdfPKCS7 wrapped;

	private PdfDictionary signatureDictionary;

	private PdfDictionary documentDictionary;

	private PdfDict outerCatalog;

	private byte[] originalContent;

	private Set<PdfSignatureOrDocTimestampInfo> outerSignatures = Collections.newSetFromMap(new ConcurrentHashMap<PdfSignatureOrDocTimestampInfo, Boolean>());

	public ITextPdfSignatureOrDocTimestampInfo(PdfPKCS7 pk, PdfDictionary signatureDictionary, CertificateToken signingCertificate, Calendar signingDate,
			Certificate[] chain, PdfDictionary documentDictionary, PdfDict outerCatalog, byte[] originalContent) {
		this.signatureDictionary = signatureDictionary;
		this.documentDictionary = documentDictionary;
		this.outerCatalog = outerCatalog;
		this.originalContent = originalContent;
	}

	public CAdESSignature getCades() {
		try {
			PdfObject pdfObject = signatureDictionary.get(PdfName.CONTENTS);
			CAdESSignature signature = new CAdESSignature(pdfObject.getBytes());

			int[] range = getSignatureByteRange();
			int c = range.length / 2;
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			for (int i = 0; i < c; i++) {
				LOG.info("Range[] " + range[i * 2] + " - " + range[(i * 2) + 1]);
				buffer.write(getOriginalBytes(), range[i * 2], range[(i * 2) + 1]);
			}
			signature.setDetachedContents(Arrays.<DSSDocument>asList(new InMemoryDocument(buffer.toByteArray())));
			return signature;
		} catch (CMSException e) {
			LOG.error(e.getMessage(), e);
			throw new DSSException(e);
		}
	}

	@Override
	public int[] getSignatureByteRange() {
		PdfArray array = (PdfArray) signatureDictionary.get(PdfName.BYTERANGE);
		int[] range = new int[array.size()];
		for (int i = 0; i < array.size(); i++) {
			PdfNumber o = (PdfNumber) array.getPdfObject(i);
			range[i] = o.intValue();
		}
		return range;
	}

	@Override
	public void checkIntegrity() {
		getCades().checkSignatureIntegrity();
	}

	@Override
	public String getLocation() {
		return getStringValueFromSignatureDictionary(PdfName.LOCATION);
	}

	@Override
	public Date getSigningDate() {
		PdfObject pdfObject = signatureDictionary.get(PdfName.M);
		PdfString s = (PdfString) pdfObject;
		if (s == null) {
			return null;
		}
		return PdfDate.decode(s.toString()).getTime();
	}

	@Override
	public byte[] getSignedDocumentBytes() {
		LOG.error("Unsupported operation");
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] getOriginalBytes() {
		return originalContent;
	}

//	public PdfDssDict getDocumentDictionary() {
//		return PdfDssDict.build(new ITextPdfDict(documentDictionary));
//	}
//
//	public PdfDssDict getOuterCatalog() {
//		return PdfDssDict.build(outerCatalog);
//	}

	@Override
	public void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo) {
		outerSignatures.add(signatureInfo);
	}

	@Override
	public Set<PdfSignatureOrDocTimestampInfo> getOuterSignatures() {
		return outerSignatures;
	}

	@Override
	public boolean isTimestamp() {
		LOG.error("Unsupported operation");
		throw new UnsupportedOperationException();
	}

	@Override
	public String getContactInfo() {
		return getStringValueFromSignatureDictionary(PdfName.CONTACTINFO);
	}

	@Override
	public String getReason() {
		return getStringValueFromSignatureDictionary(PdfName.REASON);
	}

	@Override
	public String getFilter() {
		return getNameValueFromSignatureDictionary(PdfName.FILTER);
	}

	@Override
	public String getSubFilter() {
		return getNameValueFromSignatureDictionary(PdfName.SUBFILTER);
	}

	@Override
	public PdfDssDict getDssDictionary() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String uniqueId() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public byte[] getContent() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PdfDict getSignatureDictionary() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isCoverAllOriginalBytes() {
		// TODO Auto-generated method stub
		return false;
	}

	private String getStringValueFromSignatureDictionary(PdfName key) {
		PdfString pdfString = signatureDictionary.getAsString(key);
		if (pdfString == null) {
			return null;
		} else {
			return pdfString.toString();
		}
	}

	private String getNameValueFromSignatureDictionary(PdfName key) {
		PdfName pdfName = signatureDictionary.getAsName(key);
		if (pdfName == null) {
			return null;
		} else {
			return PdfName.decodeName(pdfName.toString());
		}
	}

}
