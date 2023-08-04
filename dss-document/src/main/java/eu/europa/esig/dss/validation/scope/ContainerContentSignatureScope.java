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
package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;

/**
 * This SignatureScope represents a content of a package.zip container file for an ASiC-S container
 *
 */
public class ContainerContentSignatureScope extends ContainerSignatureScope {

	private static final long serialVersionUID = 7807261511908211301L;

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument}
	 */
	public ContainerContentSignatureScope(DSSDocument document) {
		super(document);
	}

    @Override
    public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
        return "ASiCS archive content";
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.ARCHIVED;
	}

}
