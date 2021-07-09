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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.validation.SignaturePolicy;
import org.w3c.dom.Element;

import java.util.Collections;
import java.util.List;

/**
 * Represents a signature policy extracted from a XAdES (XML) signature
 *
 */
public class XAdESSignaturePolicy extends SignaturePolicy {

    private static final long serialVersionUID = 7680417705376716706L;

    /** The transforms Element (used in XAdES) */
    private Element transforms;

    /**
     * The default constructor for XAdESSignaturePolicy. It represents the implied policy.
     */
    public XAdESSignaturePolicy() {
        super();
    }

    /**
     * The default constructor for XAdESSignaturePolicy.
     *
     * @param identifier
     *            the policy identifier
     */
    public XAdESSignaturePolicy(final String identifier) {
        super(identifier);
    }

    /**
     * Returns a 'ds:Transforms' element if found
     * NOTE: XAdES only
     *
     * @return 'ds:Transforms' {@link Element} if found, NULL otherwise
     */
    public Element getTransforms() {
        return transforms;
    }

    /**
     * Sets a 'ds:Transforms' node
     *
     * @param transforms {@link Element}
     */
    public void setTransforms(Element transforms) {
        this.transforms = transforms;
    }

    /**
     * Gets a list of Strings describing the 'ds:Transforms' element
     * NOTE: XAdES only
     *
     * @return a description of 'ds:Transforms' if present, null otherwise
     */
    @Override
    public List<String> getTransformsDescription() {
        if (transforms != null) {
            return new TransformsDescriptionBuilder(transforms).build();
        }
        return Collections.emptyList();
    }

}
