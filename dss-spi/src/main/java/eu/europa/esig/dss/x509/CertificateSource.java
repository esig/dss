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

import java.io.Serializable;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * The validation of a certificate requires to access some other certificates from multiple sources (Trusted List, Trust
 * Store, the signature itself). This interface provides an abstraction for accessing a certificate, regardless of the
 * source.
 *
 *
 */

public interface CertificateSource extends Serializable {

    /**
     * This method return the {@link CertificatePool} encapsulated by the source.
     */
    public CertificatePool getCertificatePool();

    /**
     * This method allows to manually add any certificate to the source. The type of the source is automatically set par each specific
     * implementation.
     *
     * @param certificate the certificate you have to trust
     * @return the corresponding certificate token
     */
    public CertificateToken addCertificate(final CertificateToken certificate);

    /**
     * This method returns the <code>List</code> of <code>CertificateToken</code>(s) corresponding to the given subject distinguished name.
     * The search is performed at the level of source and not at the pool level (The same pool can be shared by many sources).
     *
     * @param x500Principal subject distinguished names of the certificate to find
     * @return
     */
    public List<CertificateToken> get(final X500Principal x500Principal);
}
