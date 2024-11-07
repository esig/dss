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
package eu.europa.esig.dss.enumerations;

/**
 * Defines common TSLType values supported by the implementation
 *
 */
public enum TSLTypeEnum implements TSLType {

    /** EU List of the Trusted Lists */
    EUlistofthelists("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists", "EU List of the Trusted Lists"),

    /** EU Trusted Lists */
    EUgeneric("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", "EU Trusted List"),

    /** AdES List of the Trusted Lists */
    AdESlistofthelists("http://ec.europa.eu/tools/lotl/mra/ades-lotl-tsl-type", "AdES List of the Trusted Lists");

    /** URI associated with the TSPType */
    private String uri;

    /** Name of the TSLType */
    private String label;

    /**
     * Default constructor
     *
     * @param uri {@link String}
     * @param label {@link String}
     */
    TSLTypeEnum(final String uri, final String label) {
        this.uri = uri;
        this.label = label;
    }

    @Override
    public String getUri() {
        return uri;
    }

    @Override
    public String getLabel() {
        return label;
    }

}
