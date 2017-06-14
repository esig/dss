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

import java.util.List;
import java.util.Set;

import org.bouncycastle.cms.CMSSignedData;

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.validation.CAdESCertificateSource;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * CertificateSource that will retrieve the certificate from a PAdES Signature
 *
 *
 */

public class PAdESCertificateSource extends CAdESCertificateSource {

	/**
	 * The default constructor for PAdESCertificateSource.
	 *
	 * @param dssCatalog
	 * @param cmsSignedData
	 * @param certPool
	 *            The pool of certificates to be used. Can be null.
	 */
	public PAdESCertificateSource(final PdfDssDict dssCatalog, final CMSSignedData cmsSignedData, final CertificatePool certPool) {
		super(cmsSignedData, certPool);

		if (dssCatalog != null) {
			final Set<CertificateToken> certList = dssCatalog.getCertList();
			for (final CertificateToken certToken : certList) {
				addCertificate(certToken);
			}
		}
	}

	@Override
	public List<CertificateToken> getEncapsulatedCertificates() {
		return super.getEncapsulatedCertificates();
	}

	@Override
	public List<CertificateToken> getKeyInfoCertificates() {
		return super.getKeyInfoCertificates();
	}

}