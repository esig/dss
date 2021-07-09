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

import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;

import java.util.List;

/**
 * Wrapper for a list of {@code eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName}s
 *
 */
public class DistinguishedNameListWrapper {

    /** The distinguished names */
    private final List<XmlDistinguishedName> xmlDistinguishedNames;

    /**
     * Default constructor
     *
     * @param xmlDistinguishedNames a list of {@link XmlDistinguishedName}s
     */
    public DistinguishedNameListWrapper(final List<XmlDistinguishedName> xmlDistinguishedNames) {
        this.xmlDistinguishedNames = xmlDistinguishedNames;
    }

    /**
     * Returns a value according to the given {@code format}
     *
     * @param format {@link String} to get distinguished name value
     * @return {@link String}
     */
    public String getValue(String format) {
        if (xmlDistinguishedNames != null) {
            for (XmlDistinguishedName distinguishedName : xmlDistinguishedNames) {
                if (distinguishedName.getFormat().equals(format)) {
                    return distinguishedName.getValue();
                }
            }
        }
        return "";
    }

}
