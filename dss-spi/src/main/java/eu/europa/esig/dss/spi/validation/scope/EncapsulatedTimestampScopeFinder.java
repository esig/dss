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

import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.Collections;
import java.util.List;

/**
 * This class is used to find a signature scope for an embedded timestamp
 * from a collection of {@code SignatureScope} candidates, extracted from a signature
 *
 */
public class EncapsulatedTimestampScopeFinder extends AbstractSignatureScopeFinder implements TimestampScopeFinder {

    /** {@code AdvancedSignature} embedding the timestamp */
    protected AdvancedSignature signature;

    /**
     * Default constructor instantiating object with null signature
     */
    public EncapsulatedTimestampScopeFinder() {
        // empty
    }

    /**
     * This method sets an encapsulating {@code AdvancedSignature}
     *
     * @param signature {@link AdvancedSignature}
     */
    public void setSignature(AdvancedSignature signature) {
        this.signature = signature;
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact()) {
            return filterCoveredSignatureScopes(timestampToken);
        }
        return Collections.emptyList();
    }

    /**
     * This method filters and returns covered {@code SignatureScope}s by the current timestamp
     *
     * @param timestampToken {@link TimestampToken}
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> filterCoveredSignatureScopes(TimestampToken timestampToken) {
        // return all by default
        return signature.getSignatureScopes();
    }

}
