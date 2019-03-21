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

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.crl.SignatureCRLSource;

/**
 * CRLSource that will retrieve the CRL from a PAdES Signature
 */
@SuppressWarnings("serial")
public class PAdESCRLSource extends SignatureCRLSource {

	private final PdfDssDict dssDictionary;

	/**
	 * The default constructor for PAdESCRLSource.
	 *
	 * @param dssDictionary
	 *                      the DSS dictionary
	 */
	public PAdESCRLSource(final PdfDssDict dssDictionary) {
		this.dssDictionary = dssDictionary;
		extract();
	}

	private void extract() {
		for (byte[] crl : getCrlMap().values()) {
			addCRLBinary(crl, RevocationOrigin.INTERNAL_DSS);
		}
	}

	public Map<Long, byte[]> getCrlMap() {
		if (dssDictionary != null) {
			return dssDictionary.getCrlMap();
		}
		return Collections.emptyMap();
	}

}
