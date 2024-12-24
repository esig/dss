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
 * 4.2.1.4.  Certificate Policies
 *    The certificate policies extension contains a sequence of one or more
 *    policy information terms, each of which consists of an object
 *    identifier (OID) and optional qualifiers.  Optional qualifiers, which
 *    MAY be present, are not expected to change the definition of the
 *    policy.  A certificate policy OID MUST NOT appear more than once in a
 *    certificate policies extension.
 */
public class CertificatePolicies extends CertificateExtension {

    private static final long serialVersionUID = -7265911253903526171L;

    /** List of certificate policies */
    private List<CertificatePolicy> policyList;

    /**
     * Default constructor
     */
    public CertificatePolicies() {
        super(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
    }

    /**
     * Returns the list of certificate policies
     *
     * @return a list of {@link CertificatePolicy}
     */
    public List<CertificatePolicy> getPolicyList() {
        return policyList;
    }

    /**
     * Sets a list of certificate policies
     *
     * @param policyList a list of {@link CertificatePolicy}
     */
    public void setPolicyList(List<CertificatePolicy> policyList) {
        this.policyList = policyList;
    }

}
