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

import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationStatus;
import eu.europa.esig.dss.enumerations.AttestationStatus;

/**
 * Contains information about the validity of an EAA
 *
 */
public class AttestationRevocationWrapper extends AttestationRevocationTokenWrapper {

    /** Wrapped {@code XmlEAARevocationStatus} */
    private final XmlEAARevocationStatus xmlEAARevocationStatus;

    /**
     * Default constructor
     *
     * @param xmlEAARevocationStatus {@link XmlEAARevocationStatus}
     */
    public AttestationRevocationWrapper(XmlEAARevocationStatus xmlEAARevocationStatus) {
        super(xmlEAARevocationStatus.getEAARevocationToken());
        this.xmlEAARevocationStatus = xmlEAARevocationStatus;
    }

    /**
     * Returns the status of the concerned EAA
     *
     * @return {@link AttestationStatus}
     */
    public AttestationStatus getStatus() {
        return xmlEAARevocationStatus.getStatus();
    }

}
