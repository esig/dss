/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 * 4.2.1.13. CRL Distribution Points
 * <p>
 * The CRL distribution points extension identifies how CRL information
 * is obtained. The extension SHOULD be non-critical, but this profile
 * RECOMMENDS support for this extension by CAs and applications.
 *
 */
public class CRLDistributionPoints extends CertificateExtension {

    private static final long serialVersionUID = 8414843047407478743L;

    /** List of CRL distribution points */
    private List<String> crlUrls;

    /**
     * Default constructor
     */
    public CRLDistributionPoints() {
        super(CertificateExtensionEnum.CRL_DISTRIBUTION_POINTS.getOid());
    }

    /**
     * Returns a list of CRL distribution point URLs
     *
     * @return a list of {@link String}s
     */
    public List<String> getCrlUrls() {
        return crlUrls;
    }

    /**
     * Sets a list of CRL distribution point URLs
     *
     * @param crlUrls a list of {@link String}s
     */
    public void setCrlUrls(List<String> crlUrls) {
        this.crlUrls = crlUrls;
    }

}
