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
package eu.europa.esig.dss.xades.evidencerecord;

import eu.europa.esig.dss.evidencerecord.AbstractEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

import java.util.Objects;

/**
 * Parameters for an evidence record incorporation within a XAdES signature
 *
 */
public class XAdESEvidenceRecordIncorporationParameters extends AbstractEvidenceRecordIncorporationParameters {

    private static final long serialVersionUID = 5795224409129307896L;

    /**
     * XAdES 132-3 namespace definition for the evidence record element incorporation
     */
    private DSSNamespace xadesERNamespace = XAdESNamespace.XADES_EVIDENCERECORD_NAMESPACE;

    /**
     * Default constructor
     */
    public XAdESEvidenceRecordIncorporationParameters() {
        // empty
    }

    /**
     * Gets a namespace for elements for the evidence record inclusion
     *
     * @return {@link DSSNamespace}
     */
    public DSSNamespace getXadesERNamespace() {
        return xadesERNamespace;
    }

    /**
     * Sets a namespace for elements for the evidence record inclusion.
     * <p>
     * Default: xadesen:http://uri.etsi.org/19132/v1.1.1#
     *
     * @param xadesERNamespace {@link DSSNamespace}
     */
    public void setXadesERNamespace(DSSNamespace xadesERNamespace) {
        Objects.requireNonNull(xadesERNamespace);
        String uri = xadesERNamespace.getUri();
        if (XAdESNamespace.XADES_EVIDENCERECORD_NAMESPACE.isSameUri(uri)) {
            this.xadesERNamespace = xadesERNamespace;
        } else {
            throw new IllegalArgumentException("The provided URI does not match the 132-3 definition!");
        }
    }

}
