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
package eu.europa.esig.dss.spi.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.Objects;

/**
 * This signature scope is used to refer a counter-signed SignatureValue
 *
 */
public class CounterSignatureScope extends SignatureScope {

    private static final long serialVersionUID = 8599151632129217473L;

    /** The counter-signed parent signature */
    private AdvancedSignature masterSignature;

    /**
     * Default constructor
     *
     * @param masterSignature {@link String}
     * @param originalDocument {@link DSSDocument}
     */
    public CounterSignatureScope(final AdvancedSignature masterSignature, final DSSDocument originalDocument) {
        super(originalDocument);
        Objects.requireNonNull(masterSignature, "Master signature cannot be null!");
        this.masterSignature = masterSignature;
    }

    @Override
    public String getName(TokenIdentifierProvider tokenIdentifierProvider) {
        return getMasterSignatureId(tokenIdentifierProvider);
    }

    @Override
    public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
        return String.format("Master signature with Id : %s", getMasterSignatureId(tokenIdentifierProvider));
    }

    private String getMasterSignatureId(TokenIdentifierProvider tokenIdentifierProvider) {
        return tokenIdentifierProvider.getIdAsString(masterSignature);
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.COUNTER_SIGNATURE;
	}

}
