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
package eu.europa.esig.dss.model;

import java.io.Serializable;

/**
 * This class is used to define a CommitmentTypeQualifier to be incorporated within a signature
 *
 */
public class CommitmentQualifier implements Serializable {

    private static final long serialVersionUID = -1291715111587521496L;

    /** Defines unique commitment qualifier identifier (CAdES/PAdES only) */
    private String oid;

    /** Defines the content of the qualifier (required) */
    private DSSDocument content;

    /**
     * Default constructor instantiating object with null values
     */
    public CommitmentQualifier() {
        // empty
    }

    /**
     * Gets unique object identifier of the Commitment Qualifier
     *
     * @return {@link String}
     */
    public String getOid() {
        return oid;
    }

    /**
     * Sets unique object identifier of the Commitment Qualifier (CAdES/PAdES only!)
     *
     * Use : CONDITIONAL (required for CAdES/PAdES)
     *
     * @param oid {@link String}
     */
    public void setOid(String oid) {
        this.oid = oid;
    }

    /**
     * Gets the content of the Commitment Qualifier
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getContent() {
        return content;
    }

    /**
     * Sets the content of Commitment Qualifier.
     *
     * The content of a qualifier may be anytype, but developers may need to ensure
     * the content corresponds to the used signature format (i.e. XML for XAdES, ASN.1 for CAdES, etc.).
     *
     * Use : REQUIRED
     *
     * @param content {@link DSSDocument}
     */
    public void setContent(DSSDocument content) {
        this.content = content;
    }

}
