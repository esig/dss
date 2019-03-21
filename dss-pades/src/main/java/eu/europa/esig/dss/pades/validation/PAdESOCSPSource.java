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
import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 *
 */
@SuppressWarnings("serial")
public class PAdESOCSPSource extends SignatureOCSPSource {

	private final PdfDssDict dssDictionary;

	/**
	 * The default constructor for PAdESOCSPSource.
	 *
	 * @param dssDictionary
	 *                      the DSS dictionary
	 */
	public PAdESOCSPSource(PdfDssDict dssDictionary) {
		this.dssDictionary = dssDictionary;
	}

	@Override
	public void appendContainedOCSPResponses() {
		for (BasicOCSPResp basicOCSPResp : getOcspMap().values()) {
			ocspResponses.put(basicOCSPResp, RevocationOrigin.INTERNAL_DSS);
		}
	}

	/**
	 * This method returns a map with the object number and the ocsp response
	 * 
	 * @return a map with the object number and the ocsp response
	 */
	public Map<Long, BasicOCSPResp> getOcspMap() {
		if (dssDictionary != null) {
			return dssDictionary.getOcspMap();
		}
		return Collections.emptyMap();
	}

}
