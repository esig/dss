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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.tsl.ServiceInfo;

/**
 * This source of certificates handles any non trusted certificates. (ex: intermediate certificates used in building certification chain)
 */
public class CommonCertificateSource implements CertificateSource {

    /**
     * This variable represents the certificate pool with all encapsulated certificates
     */
    protected CertificatePool certPool;
    /**
     * The list of all encapsulated certificate tokens. It must be <code>null</code> when instantiating.
     */
    protected List<CertificateToken> certificateTokens;

    /**
     * The default constructor to generate a certificates source with an independent certificates pool.
     */
    public CommonCertificateSource() {

        certPool = new CertificatePool();
    }

    /**
     * The default constructor with mandatory certificates pool.
     *
     * @param certPool
     */
    public CommonCertificateSource(final CertificatePool certPool) {

        if (certPool == null) {

            throw new NullPointerException();
        }
        this.certPool = certPool;
    }

    /**
     * This method returns the certificate source type associated to the implementation class.
     *
     * @return
     */
    protected CertificateSourceType getCertificateSourceType() {

        return CertificateSourceType.OTHER;
    }

    @Override
    public CertificatePool getCertificatePool() {

        return certPool;
    }

    /**
     * This method adds an external certificate to the encapsulated pool and to the source. If the certificate is already present in the pool its
     * source type is associated to the token.
     *
     * @param x509Certificate the certificate to add
     * @return the corresponding certificate token
     */
    @Override
    public CertificateToken addCertificate(final CertificateToken x509Certificate) {

        final CertificateToken certToken = certPool.getInstance(x509Certificate, getCertificateSourceType());
        if (certificateTokens != null) {

            if (!certificateTokens.contains(certToken)) {

                certificateTokens.add(certToken);
            }
        }
        return certToken;
    }

    /**
     * Retrieves the unmodifiable list of all certificate tokens from this source.
     *
     * @return
     */
    public List<CertificateToken> getCertificates() {

        return Collections.unmodifiableList(certificateTokens);
    }

    /**
     * This method returns the <code>List</code> of <code>CertificateToken</code>(s) corresponding to the given subject distinguished name.
     * The content of the encapsulated certificates pool can be different from the content of the source.
     *
     * @param x500Principal subject distinguished names of the certificate to find
     * @return If no match is found then an empty list is returned.
     */
    @Override
    public List<CertificateToken> get(final X500Principal x500Principal) {

        List<CertificateToken> certificateTokenList = null;
        if (x500Principal != null) {

            final List<CertificateToken> missingCertificateTokens = new ArrayList<CertificateToken>();
            certificateTokenList = certPool.get(x500Principal);
            for (final CertificateToken certificateToken : certificateTokenList) {

                if (!certificateTokens.contains(certificateToken)) {

                    missingCertificateTokens.add(certificateToken);
                }
            }
            if (missingCertificateTokens.size() > 0) {

                certificateTokenList.removeAll(missingCertificateTokens);
            }
        } else {

            certificateTokenList = new ArrayList<CertificateToken>();
        }
        return Collections.unmodifiableList(certificateTokenList);
    }

    /**
     * This method is used internally to prevent the addition of a certificate through the <code>CertificatePool</code>.
     *
     * @param certificate
     * @param serviceInfo
     * @return
     */
    protected CertificateToken addCertificate(final CertificateToken certificate, final ServiceInfo serviceInfo) {

        final CertificateToken certToken = certPool.getInstance(certificate, getCertificateSourceType(), serviceInfo);
        if (certificateTokens != null) {

            if (!certificateTokens.contains(certToken)) {

                certificateTokens.add(certToken);
            }
        }
        return certToken;
    }

}
