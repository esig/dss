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
package eu.europa.esig.dss.pades.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.CertificateList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * CRLSource that will retrieve the CRL from a PAdES Signature
 */
@SuppressWarnings("serial")
public class PAdESCRLSource extends OfflineCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESCRLSource.class);

	private final PdfDssDict dssDictionary;

	private final String vriDictionaryName;

	private Map<Long, CRLBinary> crlMap;

	private final AttributeTable signedAttributes;

	public PAdESCRLSource(final PdfDssDict dssDictionary) {
		this(dssDictionary, null, null);
	}

	public PAdESCRLSource(final PdfDssDict dssDictionary, final String vriDictionaryName,
			AttributeTable signedAttributes) {
		this.dssDictionary = dssDictionary;
		this.vriDictionaryName = vriDictionaryName;
		this.signedAttributes = signedAttributes;
		appendContainedCRLResponses();
	}

	private void appendContainedCRLResponses() {
		extractDSSCRLs();
		extractVRICRLs();

		/*
		 * (pades): Read revocation data from unsigned attribute 1.2.840.113583.1.1.8 In
		 * the PKCS #7 object of a digital signature in a PDF file, identifies a signed
		 * attribute that "can include all the revocation information that is necessary
		 * to carry out revocation checks for the signer's certificate and its issuer
		 * certificates." Defined as adbe-revocationInfoArchival { adbe(1.2.840.113583)
		 * acrobat(1) security(1) 8 } in
		 * "PDF Reference, fifth edition: Adobe® Portable Document Format, Version 1.6"
		 * Adobe Systems Incorporated, 2004.
		 * http://partners.adobe.com/public/developer/en/pdf/PDFReference16.pdf page 698
		 * 
		 * RevocationInfoArchival ::= SEQUENCE { crl [0] EXPLICIT SEQUENCE of CRLs,
		 * OPTIONAL ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL otherRevInfo
		 * [2] EXPLICIT SEQUENCE of OtherRevInfo, OPTIONAL } OtherRevInfo ::= SEQUENCE {
		 * Type OBJECT IDENTIFIER Value OCTET STRING }
		 * 
		 * 
		 */
		if (signedAttributes != null) {
			collectCRLArchivalValues(signedAttributes);
		}
	}

	private void collectCRLArchivalValues(AttributeTable attributes) {
		final ASN1Encodable attValue = DSSASN1Utils.getAsn1Encodable(attributes, OID.adbe_revocationInfoArchival);
		RevocationInfoArchival revValues = PAdESUtils.getRevocationInfoArchivals(attValue);
		if (revValues != null) {
			for (final CertificateList revValue : revValues.getCrlVals()) {
				try {
					addBinary(CRLUtils.buildCRLBinary(revValue.getEncoded()),
							RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
				} catch (IOException e) {
					LOG.warn("Could not convert CertificateList to CRLBinary : {}", e.getMessage());
				}
			}
		}
	}

	/**
	 * Returns a map of all CRL entries contained in DSS dictionary or into nested
	 * VRI dictionaries
	 * 
	 * @return a map of CRL binaries with their object ids
	 */
	public Map<Long, CRLBinary> getCrlMap() {
		if (crlMap != null) {
			return crlMap;
		}
		return Collections.emptyMap();
	}

	private Map<Long, CRLBinary> getDssCrlMap() {
		if (dssDictionary != null) {
			crlMap = dssDictionary.getCRLs();
			return crlMap;
		}
		return Collections.emptyMap();
	}

	private void extractDSSCRLs() {
		for (CRLBinary crl : getDssCrlMap().values()) {
			addBinary(crl, RevocationOrigin.DSS_DICTIONARY);
		}
	}

	private PdfVRIDict findVriDict() {
		PdfVRIDict vriDictionary = null;
		if (dssDictionary != null) {
			List<PdfVRIDict> vriDictList = dssDictionary.getVRIs();
			if (vriDictionaryName != null && Utils.isCollectionNotEmpty(vriDictList)) {
				for (PdfVRIDict vriDict : vriDictList) {
					if (vriDictionaryName.equals(vriDict.getName())) {
						vriDictionary = vriDict;
						break;
					}
				}
			}
		}
		return vriDictionary;
	}

	private void extractVRICRLs() {
		PdfVRIDict vriDictionary = findVriDict();
		if (vriDictionary != null) {
			for (Entry<Long, CRLBinary> crlEntry : vriDictionary.getCRLs().entrySet()) {
				if (!crlMap.containsKey(crlEntry.getKey())) {
					crlMap.put(crlEntry.getKey(), crlEntry.getValue());
				}
				addBinary(crlEntry.getValue(), RevocationOrigin.VRI_DICTIONARY);
			}
		}
	}

}
