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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationStatus;
import eu.europa.esig.dss.enumerations.AttestationStatus;

/**
 * Contains information about the validity of an attestation
 *
 */
public class AttestationRevocationWrapper extends AttestationRevocationTokenWrapper {

    /** Wrapped {@code XmlAttestationRevocationStatus} */
    private final XmlAttestationRevocationStatus xmlAttestationRevocationStatus;

    /**
     * Default constructor
     *
     * @param xmlAttestationRevocationStatus {@link XmlAttestationRevocationStatus}
     */
    public AttestationRevocationWrapper(XmlAttestationRevocationStatus xmlAttestationRevocationStatus) {
        super(xmlAttestationRevocationStatus.getAttestationRevocationToken());
        this.xmlAttestationRevocationStatus = xmlAttestationRevocationStatus;
    }

    /**
     * Returns the revocation of the concerned attestation
     *
     * @return {@link AttestationStatus}
     */
    public AttestationStatus getStatus() {
        return xmlAttestationRevocationStatus.getStatus();
    }

}
