/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.validation.pades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import eu.europa.ec.markt.dss.signature.pdf.pdfbox.PdfDssDict;
import eu.europa.ec.markt.dss.signature.validation.cades.CAdESCertificateSource;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.SignatureCertificateSource;

/**
 * CertificateSource that will retrieve the certificate from a PAdES Signature
 *
 * @version $Revision: 1711 $ - $Date: 2013-03-04 18:22:32 +0100 (Mon, 04 Mar 2013) $
 */

public class PAdESCertificateSource extends SignatureCertificateSource {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(PAdESCertificateSource.class.getName());

    private final PdfDssDict dssCatalog;

    /**
     * The default constructor for PAdESCertificateSource.
     *
     * @param dssCatalog
     * @param cadesCertSource
     * @param certPool        The pool of certificates to be used. Can be null.
     */
    public PAdESCertificateSource(final PdfDssDict dssCatalog, final CAdESCertificateSource cadesCertSource, final CertificatePool certPool) {

        super(certPool);
        this.dssCatalog = dssCatalog;

        certificateTokens = new ArrayList<CertificateToken>();
        if (dssCatalog != null) {

            final Set<X509Certificate> certList = dssCatalog.getCertList();
            for (final X509Certificate x509Certificate : certList) {
                addCertificate(x509Certificate);
            }
        }

        if (cadesCertSource != null) {
            // We add the CAdES specific certificates to this source.
            for (final CertificateToken certToken : cadesCertSource.getCertificates()) {
                if (!certificateTokens.contains(certToken)) {
                    certificateTokens.add(certToken);
                }
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
