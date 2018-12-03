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

import org.bouncycastle.cms.CMSSignedData;

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.validation.CAdESCertificateSource;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * CertificateSource that will retrieve the certificate from a PAdES Signature
 *
 */
public class PAdESCertificateSource extends CAdESCertificateSource {

	private final PdfDssDict dssDictionary;

	/**
	 * The default constructor for PAdESCertificateSource.
	 *
	 * @param dssDictionary
	 *                      the DSS dictionary
	 * @param cmsSignedData
	 * @param certPool
	 *                      The pool of certificates to be used. Can be null.
	 */
	public PAdESCertificateSource(final PdfDssDict dssDictionary, final CMSSignedData cmsSignedData, final CertificatePool certPool) {
		super(cmsSignedData, certPool);

		this.dssDictionary = dssDictionary;

		extractFromDSSDict();
	}

	private void extractFromDSSDict() {
		Map<Long, CertificateToken> certificateMap = getCertificateMap();
		for (CertificateToken certToken : certificateMap.values()) {
			addCertificate(certToken);
		}
	}

	public Map<Long, CertificateToken> getCertificateMap() {
		if (dssDictionary != null) {
			return dssDictionary.getCertMap();
		}
		return Collections.emptyMap();
	}

}
