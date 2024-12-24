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
package eu.europa.esig.dss.xades.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;

import java.util.List;

/**
 * Defines a root XML document signature scope
 */
public class XmlRootSignatureScope extends XmlElementSignatureScope {

    private static final long serialVersionUID = 7325542318746995759L;

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument}
     * @param transformations a list of {@link String} transform descriptions
     */
    protected XmlRootSignatureScope(final DSSDocument document, final List<String> transformations) {
    	super("Full XML File", document, transformations);
    }

    /**
     * Constructor with document name
     *
     * @param name {@link String} document name
     * @param document {@link DSSDocument}
     * @param transformations a list of {@link String} transform descriptions
     */
    protected XmlRootSignatureScope(final String name, final DSSDocument document, final List<String> transformations) {
        super(name, document, transformations);
    }

    @Override
    public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
        String description = "The full XML file";
        return addTransformationIfNeeded(description);
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
