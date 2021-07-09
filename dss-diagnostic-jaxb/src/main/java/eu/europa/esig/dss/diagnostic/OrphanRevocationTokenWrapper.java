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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.enumerations.RevocationType;

/**
 * Wrapper class for XML orphan revocation data
 *
 */
public class OrphanRevocationTokenWrapper extends OrphanTokenWrapper<XmlOrphanRevocationToken> {

    /**
     * Default constructor
     *
     * @param orphanToken {@link XmlOrphanRevocationToken}
     */
    protected OrphanRevocationTokenWrapper(XmlOrphanRevocationToken orphanToken) {
        super(orphanToken);
    }

    /**
     * Returns a revocation data type (CRL or OCSP)
     *
     * @return {@link RevocationType}
     */
    public RevocationType getRevocationType() {
        return orphanToken.getRevocationType();
    }

    @Override
    public byte[] getBinaries() {
        return orphanToken.getBase64Encoded();
    }

    @Override
    public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
        return orphanToken.getDigestAlgoAndValue();
    }

}
