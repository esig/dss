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

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.crl.SignatureCRLSource;

/**
 * CRLSource that will retrieve the CRL from a PAdES Signature
 */
@SuppressWarnings("serial")
public class PAdESCRLSource extends SignatureCRLSource {

	private final PdfDssDict dssDictionary;
	
	private final String vriDictionaryName;
	
	private Map<Long, byte[]> crlMap;

	/**
	 * The default constructor for PAdESCRLSource.
	 *
	 * @param dssDictionary
	 *                      the DSS dictionary
	 */
	public PAdESCRLSource(final PdfDssDict dssDictionary) {
		this(dssDictionary, null);
	}
	
	public PAdESCRLSource(final PdfDssDict dssDictionary, final String vriDictionaryName) {
		this.dssDictionary = dssDictionary;
		this.vriDictionaryName = vriDictionaryName;
		appendContainedCRLResponses();
	}
	
	private void appendContainedCRLResponses() {
		extractDSSCRLs();
		extractVRICRLs();
	}
	
	/**
	 * Returns a map of all CRL entries contained in DSS dictionary or into nested
	 * VRI dictionaries
	 * 
	 * @return a map of CRL binaries with their object ids
	 */
	public Map<Long, byte[]> getCrlMap() {
		if (crlMap == null) {
			appendContainedCRLResponses();
		}
		if (crlMap != null) {
			return crlMap;
		}
		return Collections.emptyMap();
	}

	private Map<Long, byte[]> getDssCrlMap() {
		if (dssDictionary != null) {
			crlMap = dssDictionary.getCRLs();
			return crlMap;
		}
		return Collections.emptyMap();
	}

	private void extractDSSCRLs() {
		for (byte[] crl : getDssCrlMap().values()) {
			addCRLBinary(crl, RevocationOrigin.DSS_DICTIONARY);
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
			for (Entry<Long, byte[]> crlEntry : vriDictionary.getCrlMap().entrySet()) {
				if (!crlMap.containsKey(crlEntry.getKey())) {
					crlMap.put(crlEntry.getKey(), crlEntry.getValue());
				}
				addCRLBinary(crlEntry.getValue(), RevocationOrigin.VRI_DICTIONARY);
			}
		}
	}

}
