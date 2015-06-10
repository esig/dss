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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.validation.CAdESCertificateSource;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;

/**
 * CertificateSource that will retrieve the certificate from a PAdES Signature
 *
 *
 */

public class PAdESCertificateSource extends SignatureCertificateSource {

	/**
	 * The default constructor for PAdESCertificateSource.
	 *
	 * @param dssCatalog
	 * @param cadesCertSource
	 * @param certPool        The pool of certificates to be used. Can be null.
	 */
	public PAdESCertificateSource(final PdfDssDict dssCatalog, final CAdESCertificateSource cadesCertSource, final CertificatePool certPool) {

		super(certPool);

		// TODO certificateTokens -> private
		certificateTokens = new ArrayList<CertificateToken>();
		if (dssCatalog != null) {
			final Set<CertificateToken> certList = dssCatalog.getCertList();
			for (final CertificateToken certToken : certList) {
				addCertificate(certToken);
			}
		}

		if (cadesCertSource != null) {
			// We add the CAdES specific certificates to this source.
			for (final CertificateToken certToken : cadesCertSource.getCertificates()) {
				addCertificate(certToken);
			}
		}
	}

	@Override
	public List<CertificateToken> getEncapsulatedCertificates() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<CertificateToken> getKeyInfoCertificates() {
		// TODO Auto-generated method stub
		return null;
	}
}