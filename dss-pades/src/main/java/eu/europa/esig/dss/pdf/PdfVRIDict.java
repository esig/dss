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

import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.x509.CertificateToken;

public class PdfVRIDict {

	private final String name;
	private final Map<Long, byte[]> crlMap;
	private final Map<Long, BasicOCSPResp> ocspMap;
	private final Map<Long, CertificateToken> certMap;

	public PdfVRIDict(String name, PdfDict vriDict) {
		this.name = name;
		this.certMap = DSSDictionaryExtractionUtils.getCertsFromArray(vriDict, PAdESConstants.VRI_DICTIONARY_NAME + "/" + name,
				PAdESConstants.CERT_ARRAY_NAME_VRI);
		this.ocspMap = DSSDictionaryExtractionUtils.getOCSPsFromArray(vriDict, PAdESConstants.VRI_DICTIONARY_NAME + "/" + name,
				PAdESConstants.OCSP_ARRAY_NAME_VRI);
		this.crlMap = DSSDictionaryExtractionUtils.getCRLsFromArray(vriDict, PAdESConstants.VRI_DICTIONARY_NAME + "/" + name,
				PAdESConstants.CRL_ARRAY_NAME_VRI);
	}

	public String getName() {
		return name;
	}

	public Map<Long, byte[]> getCrlMap() {
		return crlMap;
	}

	public Map<Long, BasicOCSPResp> getOcspMap() {
		return ocspMap;
	}

	public Map<Long, CertificateToken> getCertMap() {
		return certMap;
	}

}
