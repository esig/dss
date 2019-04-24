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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a representation of a DSS (Document Security Store) Dictionary embedded in a PDF file.
 * The dictionary is unique in a PDF file and can contain : VRI dictionary, certificates (Certs), OCSP responses (OCSPs)
 * and CRLs.
 * This dictionary is filled in PAdES-BASELINE-LT extension process.
 */
public class PdfDssDict {

	private static final Logger LOG = LoggerFactory.getLogger(PdfDssDict.class);

	private List<PdfVRIDict> vris;
	private final Map<Long, byte[]> crlMap;
	private final Map<Long, BasicOCSPResp> ocspMap;
	private final Map<Long, CertificateToken> certMap;

	public static PdfDssDict extract(PdfDict documentDict) {
		if (documentDict != null) {
			final PdfDict dssCatalog = documentDict.getAsDict(PAdESConstants.DSS_DICTIONARY_NAME);
			if (dssCatalog != null) {
				return new PdfDssDict(dssCatalog);
			}
		}
		LOG.debug("No DSS dictionary found");
		return null;
	}

	private PdfDssDict(PdfDict dssDictionary) {
		readVRI(dssDictionary);
		certMap = DSSDictionaryExtractionUtils.getCertsFromArray(dssDictionary, PAdESConstants.DSS_DICTIONARY_NAME, PAdESConstants.CERT_ARRAY_NAME_DSS);
		ocspMap = DSSDictionaryExtractionUtils.getOCSPsFromArray(dssDictionary, PAdESConstants.DSS_DICTIONARY_NAME, PAdESConstants.OCSP_ARRAY_NAME_DSS);
		crlMap = DSSDictionaryExtractionUtils.getCRLsFromArray(dssDictionary, PAdESConstants.DSS_DICTIONARY_NAME, PAdESConstants.CRL_ARRAY_NAME_DSS);
	}

	private void readVRI(PdfDict dssDictionary) {
		PdfDict vriDict = dssDictionary.getAsDict(PAdESConstants.VRI_DICTIONARY_NAME);
		if (vriDict != null) {
			LOG.debug("There is a VRI dictionary in DSS dictionary");
			try {
				String[] names = vriDict.list();
				if (Utils.isArrayNotEmpty(names)) {
					vris = new ArrayList<PdfVRIDict>();
					for (String name : names) {
						vris.add(new PdfVRIDict(name, vriDict.getAsDict(name)));
					}
				}
			} catch (Exception e) {
				LOG.debug("Unable to analyse VRI dictionary : {}", e.getMessage());
			}
		} else {
			LOG.debug("No VRI dictionary found in DSS dictionary");
		}
	}

	public Map<Long, byte[]> getCRLs() {
		return crlMap;
	}

	public Map<Long, BasicOCSPResp> getOCSPs() {
		return ocspMap;
	}

	public Map<Long, CertificateToken> getCERTs() {
		return certMap;
	}

	public List<PdfVRIDict> getVRIs() {
		return vris;
	}

}
