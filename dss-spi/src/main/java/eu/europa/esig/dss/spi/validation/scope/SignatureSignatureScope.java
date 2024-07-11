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
package eu.europa.esig.dss.spi.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.DataIdentifier;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.Objects;

/**
 * Defines a signature scope covering a signature
 *
 */
public class SignatureSignatureScope extends SignatureScope {

    /**
     * Covered signature
     */
    private final AdvancedSignature signature;

    /**
     * Default constructor to create a signature scope
     *
     * @param signature {@link AdvancedSignature}
     * @param document {@link DSSDocument} representing the covered signature document (NOTE: not necessary to be a signature file)
     */
    public SignatureSignatureScope(final AdvancedSignature signature, final DSSDocument document) {
        super(signature.getId(), document);
        Objects.requireNonNull(signature, "Signature shall be provided!");
        this.signature = signature;
    }

    @Override
    public DataIdentifier getDSSId() {
        return super.getDSSId();
    }

    @Override
    public String getName(TokenIdentifierProvider tokenIdentifierProvider) {
        return getSignatureId(tokenIdentifierProvider);
    }

    @Override
    public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
        return String.format("Signature with Id : %s", getSignatureId(tokenIdentifierProvider));
    }

    private String getSignatureId(TokenIdentifierProvider tokenIdentifierProvider) {
        return tokenIdentifierProvider.getIdAsString(signature);
    }

    @Override
    public SignatureScopeType getType() {
        return SignatureScopeType.SIGNATURE;
    }

}
