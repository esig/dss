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
 * 4.2.1.12.  Extended Key Usage
 *    This extension indicates one or more purposes for which the certified
 *    public key may be used, in addition to or in place of the basic
 *    purposes indicated in the key usage extension. In general, this
 *    extension will appear only in end entity certificates.
 */
public class ExtendedKeyUsages extends CertificateExtension {

    private static final long serialVersionUID = -7670242503924784204L;

    /** List of extended key usage OIDs */
    private List<String> oids;

    /**
     * Default constructor
     */
    public ExtendedKeyUsages() {
        super(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
    }

    /**
     * Returns the extended key usage OIDs
     *
     * @return a list of {@link String}s
     */
    public List<String> getOids() {
        return oids;
    }

    /**
     * Sets the extended key usage OIDs
     *
     * @param oids a list of {@link String}s
     */
    public void setOids(List<String> oids) {
        this.oids = oids;
    }

}
