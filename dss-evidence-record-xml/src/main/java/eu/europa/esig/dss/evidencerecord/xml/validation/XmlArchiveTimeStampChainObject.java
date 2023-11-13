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
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import org.w3c.dom.Element;

/**
 * Ths Xml Evidence Record representation of ArchiveTimeStampChain element
 *
 */
public class XmlArchiveTimeStampChainObject extends ArchiveTimeStampChainObject implements XmlEvidenceRecordObject {

    private static final long serialVersionUID = -7472251015176736731L;

    /** The current Element */
    private final Element element;

    /** Canonicalization method (XML only) */
    private String canonicalizationMethod;

    /**
     * Default constructor
     *
     * @param element {@link Element}
     */
    public XmlArchiveTimeStampChainObject(final Element element) {
        this.element = element;
    }

    @Override
    public Element getElement() {
        return element;
    }

    /**
     * Gets canonicalization method (XML only)
     *
     * @return {@link String} representing the canonicalization algorithm
     */
    public String getCanonicalizationMethod() {
        return canonicalizationMethod;
    }

    /**
     * Sets canonicalization method (XML only)
     *
     * @param canonicalizationMethod {@link String} representing the canonicalization algorithm
     */
    public void setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
    }

}
