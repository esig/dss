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
 * 4.2.1.6.  Subject Alternative Name
 *    The subject alternative name extension allows identities to be bound
 *    to the subject of the certificate.  These identities may be included
 *    in addition to or in place of the identity in the subject field of
 *    the certificate.  Defined options include an Internet electronic mail
 *    address, a DNS name, an IP address, and a Uniform Resource Identifier
 *    (URI).  Other options exist, including completely local definitions.
 *    Multiple name forms, and multiple instances of each name form, MAY be
 *    included.  Whenever such identities are to be bound into a
 *    certificate, the subject alternative name (or issuer alternative
 *    name) extension MUST be used; however, a DNS name MAY also be
 *    represented in the subject field using the domainComponent attribute
 *    as described in Section 4.1.2.4.  Note that where such names are
 *    represented in the subject field implementations are not required to
 *    convert them into DNS names.
 */
public class SubjectAlternativeNames extends CertificateExtension {

    private static final long serialVersionUID = 1164359049003917189L;

    /** List of subject alternative names */
    private List<GeneralName> names;

    /**
     * Default constructor
     */
    public SubjectAlternativeNames() {
        super(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
    }

    /**
     * Returns a list of subject alternative names
     *
     * @return list of {@link GeneralName}s
     */
    public List<GeneralName> getGeneralNames() {
        return names;
    }

    /**
     * Sets a list of subject alternative names
     *
     * @param names list of {@link GeneralName}s
     */
    public void setGeneralNames(List<GeneralName> names) {
        this.names = names;
    }

}
