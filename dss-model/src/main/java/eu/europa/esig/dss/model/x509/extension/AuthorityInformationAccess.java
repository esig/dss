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
package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 * 4.2.2.1.  Authority Information Access
 *
 *    The authority information access extension indicates how to access
 *    information and services for the issuer of the certificate in which
 *    the extension appears.  Information and services may include on-line
 *    validation services and CA policy data.  (The location of CRLs is not
 *    specified in this extension; that information is provided by the
 *    cRLDistributionPoints extension.)  This extension may be included in
 *    end entity or CA certificates.  Conforming CAs MUST mark this
 *    extension as non-critical.
 */
public class AuthorityInformationAccess extends CertificateExtension {

    private static final long serialVersionUID = 3737049345593065825L;

    /** Lists certificates that were issued to the CA that issued this certificate */
    private List<String> caIssuers;

    /** Defines location of OCSP responder */
    private List<String> ocsp;

    /**
     * Default constructor
     */
    public AuthorityInformationAccess() {
        super(CertificateExtensionEnum.AUTHORITY_INFORMATION_ACCESS.getOid());
    }

    /**
     * Returns a list of CA issuers URLs
     *
     * @return a list of {@link String}s
     */
    public List<String> getCaIssuers() {
        return caIssuers;
    }

    /**
     * Sets a list of CA issuers URLs
     *
     * @param caIssuers a list of {@link String}s
     */
    public void setCaIssuers(List<String> caIssuers) {
        this.caIssuers = caIssuers;
    }

    /**
     * Returns a list of OCSP access URLs
     *
     * @return a list of {@link String}s
     */
    public List<String> getOcsp() {
        return ocsp;
    }

    /**
     * Sets a list of OCSP access URLs
     *
     * @param ocsp a list of {@link String}s
     */
    public void setOcsp(List<String> ocsp) {
        this.ocsp = ocsp;
    }

}
