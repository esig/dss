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
package eu.europa.esig.dss.x509;

import java.util.List;

/**
 * The advanced signature contains a list of certificate that was needed to validate the signature. This class is a
 * basic skeleton that is able to retrieve the needed certificate from a list. The child need to retrieve the list of
 * wrapped certificates.
 *
 *
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
