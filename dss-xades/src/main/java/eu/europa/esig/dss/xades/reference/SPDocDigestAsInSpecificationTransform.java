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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import org.w3c.dom.Node;

/**
 * This is a special transform to be used exclusively within a xades:SignaturePolicyId
 * to define special digest computation rules.
 * See EN 319 132-1 "5.2.9 The SignaturePolicyIdentifier qualifying property"
 *
 */
public class SPDocDigestAsInSpecificationTransform extends AbstractTransform {
    
    private static final long serialVersionUID = -2521900114294437390L;

    /** The SPDocDigestAsInSpecification algorithm URI */
    private static final String ALGORITHM_URI = DSSXMLUtils.SP_DOC_DIGEST_AS_IN_SPECIFICATION_ALGORITHM_URI;

    /**
     * Default constructor with ds: xmldsig namespace
     */
    public SPDocDigestAsInSpecificationTransform() {
        super(ALGORITHM_URI);
    }

    /**
     * Constructor with a custom namespace
     *
     * @param xmlDSigNamespace {@link DSSNamespace}
     */
    protected SPDocDigestAsInSpecificationTransform(DSSNamespace xmlDSigNamespace) {
        super(xmlDSigNamespace, ALGORITHM_URI);
    }

    @Override
    public DSSTransformOutput performTransform(DSSTransformOutput transformOutput) {
        throw new IllegalArgumentException(
                "The transform SPDocDigestAsInSpecificationTransform cannot be used for reference processing!");
    }

}
