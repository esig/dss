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

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponse;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 *
 */
@SuppressWarnings("serial")
public class PAdESOCSPSource extends SignatureOCSPSource {

	private final PdfDssDict dssDictionary;
	
	private final String vriDictionaryName;
	
	private Map<Long, BasicOCSPResp> ocspMap;

	/**
	 * The default constructor for PAdESOCSPSource.
	 *
	 * @param dssDictionary
	 *                      the DSS dictionary
	 */
	public PAdESOCSPSource(PdfDssDict dssDictionary) {
		this(dssDictionary, null);
	}
	
	public PAdESOCSPSource(PdfDssDict dssDictionary, String vriDictionaryName) {
		this.dssDictionary = dssDictionary;
		this.vriDictionaryName = vriDictionaryName;
	}

	@Override
	public void appendContainedOCSPResponses() {
		extractDSSOCSPs();
		extractVRIOCSPs();
	}
	
	/**
	 * Returns a map of all OCSP entries contained in DSS dictionary or into nested
	 * VRI dictionaries
	 * 
	 * @return a map of BasicOCSPResp with their object ids
	 */
	public Map<Long, BasicOCSPResp> getOcspMap() {
		if (ocspMap == null) {
			appendContainedOCSPResponses();
		}
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
			ocspResponses.add(new OCSPResponse(basicOCSPResp, RevocationOrigin.INTERNAL_DSS));
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
			for (Entry<Long, BasicOCSPResp> ocspEntry : vriDictionary.getOcspMap().entrySet()) {
				if (!ocspMap.containsKey(ocspEntry.getKey())) {
					ocspMap.put(ocspEntry.getKey(), ocspEntry.getValue());
				}
				ocspResponses.add(new OCSPResponse(ocspEntry.getValue(), RevocationOrigin.INTERNAL_VRI));
			}
		}
	}

}
