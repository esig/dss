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

package eu.europa.ec.markt.dss.validation102853;

import java.util.List;

import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;

/**
 * The advanced signature contains a list of certificate that was needed to validate the signature. This class is a
 * basic skeleton that is able to retrieve the needed certificate from a list. The child need to retrieve the list of
 * wrapped certificates.
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public abstract class SignatureCertificateSource extends CommonCertificateSource {

    /**
     * The default constructor with mandatory certificates pool.
     *
     * @param certPool
     */
    protected SignatureCertificateSource(final CertificatePool certPool) {

        super(certPool);
    }

    /**
     * Retrieves the list of all encapsulated certificates (-XL extension) from this source.
     *
     * @return
     */
    public abstract List<CertificateToken> getEncapsulatedCertificates();

    /**
     * Retrieves the list of all certificates present in -BES level of the signature from this source.
     *
     * @return
     */
    public abstract List<CertificateToken> getKeyInfoCertificates();

    /**
     * This method returns the certificate source type associated to the implementation class.
     *
     * @return
     */
    protected CertificateSourceType getCertificateSourceType() {

        return CertificateSourceType.SIGNATURE;
    }
    
}
