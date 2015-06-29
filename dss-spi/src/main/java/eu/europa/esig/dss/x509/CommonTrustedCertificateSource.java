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

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.tsl.ServiceInfo;

/**
 * This class represents the simple list of trusted certificates.
 *
 *
 */

public class CommonTrustedCertificateSource extends CommonCertificateSource {

    @Override
    protected CertificateSourceType getCertificateSourceType() {

        return CertificateSourceType.TRUSTED_STORE;
    }

    protected CertificateToken addCertificate(final CertificateToken cert, final List<CertificateSourceType> sources, final List<ServiceInfo> services) {

        final CertificateToken certToken = certPool.getInstance(cert, sources, services);
        return certToken;
    }

    /**
     * This method allows to define (to add) any certificate as trusted. A service information is associated to this certificate. The source of the certificate is set to
     * {@code CertificateSourceType.TRUSTED_LIST}
     *
     * @param certificate the certificate you have to trust
     * @param serviceInfo the service information associated to the service
     * @return the corresponding certificate token
     */
    public CertificateToken addCertificate(final CertificateToken certificate, final ServiceInfo serviceInfo) {

        final CertificateToken certToken = certPool.getInstance(certificate, getCertificateSourceType(), serviceInfo);
        return certToken;
    }

    /**
     * This method allows to declare all certificates from a given key store as trusted.
     *
     * @param keyStore the set of certificates you have to trust
     */
    public void importAsTrusted(final KeyStoreCertificateSource keyStore) {

        final List<CertificateToken> certTokenList = keyStore.getCertificates();
        for (final CertificateToken certToken : certTokenList) {

            certPool.getInstance(certToken, getCertificateSourceType());
        }
    }

    /**
     * Retrieves the list of all certificate tokens from this source.
     *
     * @return
     */
    public List<CertificateToken> getCertificates() {

        return certPool.getCertificateTokens();
    }

    /**
     * This method returns the {@code List} of {@code CertificateToken}(s) corresponding to the given subject distinguished name. In the case of
     * {@code CommonTrustedCertificateSource} the content of the encapsulated pool is equal to the content of the source.
     *
     * @param x500Principal subject distinguished names of the certificate to find
     * @return If no match is found then an empty list is returned.
     */
    @Override
    public List<CertificateToken> get(final X500Principal x500Principal) {

        return certPool.get(x500Principal);
    }
}