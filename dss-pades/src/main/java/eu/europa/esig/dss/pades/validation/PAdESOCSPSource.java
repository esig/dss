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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 *
 */
@SuppressWarnings("serial")
public class PAdESOCSPSource extends OfflineOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESOCSPSource.class);
	
	private final PdfDssDict dssDictionary;
	
	private final String vriDictionaryName;
	
	private final AttributeTable signedAttributes;
	 
	private transient Map<Long, BasicOCSPResp> ocspMap;
	
	public PAdESOCSPSource(final PdfDssDict dssDictionary) {
		this(dssDictionary, null, null);
	}
	
	public PAdESOCSPSource(final PdfDssDict dssDictionary, final String vriDictionaryName, AttributeTable signedAttributes) {
		this.dssDictionary = dssDictionary;
		this.vriDictionaryName = vriDictionaryName;
		this.signedAttributes = signedAttributes;
		appendContainedOCSPResponses();
	}
	
	public void appendContainedOCSPResponses() {
		extractDSSOCSPs();
		extractVRIOCSPs();
		
		/*
		 * (pades): Read revocation data from from unsigned attribute  1.2.840.113583.1.1.8
         * In the PKCS #7 object of a digital signature in a PDF file, identifies a signed attribute
         * that "can include all the revocation information that is necessary to carry out revocation
         * checks for the signer's certificate and its issuer certificates."
         * Defined as adbe-revocationInfoArchival { adbe(1.2.840.113583) acrobat(1) security(1) 8 } in "PDF Reference, 
         * fifth edition: Adobe® Portable Document Format, Version 1.6" Adobe Systems Incorporated, 2004.
         * http://partners.adobe.com/public/developer/en/pdf/PDFReference16.pdf page 698
		 *
         * RevocationInfoArchival ::= SEQUENCE {
         *   crl [0] EXPLICIT SEQUENCE of CRLs, OPTIONAL
         *   ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL
         *   otherRevInfo [2] EXPLICIT SEQUENCE of OtherRevInfo, OPTIONAL
         * }
         * 
		 */
		if (signedAttributes != null) {
			collectOCSPArchivalValues(signedAttributes);
		}
		
	}
	
	private void collectOCSPArchivalValues(AttributeTable attributes) {
		final ASN1Encodable attValue = DSSASN1Utils.getAsn1Encodable(attributes, OID.adbe_revocationInfoArchival);
		if (attValue !=null) {	
			RevocationInfoArchival revocationArchival = PAdESUtils.getRevocationInfoArchivals(attValue);
			if (revocationArchival != null) {
				for (final OCSPResponse ocspResponse : revocationArchival.getOcspVals()) {
					final OCSPResp ocspResp = new OCSPResp(ocspResponse);
					try {
						BasicOCSPResp basicOCSPResponse = (BasicOCSPResp) ocspResp.getResponseObject();
						addBinary(OCSPResponseBinary.build(basicOCSPResponse), RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
					} catch (OCSPException e) {
						LOG.warn("Error while extracting OCSPResponse from Revocation Info Archivals (ADBE) : {}", e.getMessage());
					}					
				}
			}
		}
	}
	
	/**
	 * Returns a map of all OCSP entries contained in DSS dictionary or into nested
	 * VRI dictionaries
	 * 
	 * @return a map of BasicOCSPResp with their object ids
	 */
	public Map<Long, BasicOCSPResp> getOcspMap() {
		if (ocspMap != null) {
			return ocspMap;
		}
		return Collections.emptyMap();
	}

	/**
	 * This method returns a map with the object number and the ocsp response
	 * 
	 * @return a map with the object number and the ocsp response
	 */
	private Map<Long, BasicOCSPResp> getDssOcspMap() {
		if (dssDictionary != null) {
			ocspMap = dssDictionary.getOCSPs();
			return ocspMap;
		}
		return Collections.emptyMap();
	}
	
	private void extractDSSOCSPs() {
		for (BasicOCSPResp basicOCSPResp : getDssOcspMap().values()) {
			addBinary(OCSPResponseBinary.build(basicOCSPResp), RevocationOrigin.DSS_DICTIONARY);
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
	
	private void extractVRIOCSPs() {
		PdfVRIDict vriDictionary = findVriDict();
		if (vriDictionary != null) {
			for (Entry<Long, BasicOCSPResp> ocspEntry : vriDictionary.getOCSPs().entrySet()) {
				if (!ocspMap.containsKey(ocspEntry.getKey())) {
					ocspMap.put(ocspEntry.getKey(), ocspEntry.getValue());
				}
				addBinary(OCSPResponseBinary.build(ocspEntry.getValue()), RevocationOrigin.VRI_DICTIONARY);
			}
		}
	}

}
