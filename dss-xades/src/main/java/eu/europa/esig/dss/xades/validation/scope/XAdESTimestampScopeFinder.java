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
package eu.europa.esig.dss.xades.validation.scope;

import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampInclude;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.scope.EncapsulatedTimestampScopeFinder;
import eu.europa.esig.dss.xades.reference.XAdESReferenceValidation;

import java.util.ArrayList;
import java.util.List;

/**
 * Finds a timestamp scope for a XAdES encapsulated timestamps
 *
 */
public class XAdESTimestampScopeFinder extends EncapsulatedTimestampScopeFinder {

    /**
     * Default constructor
     */
    public XAdESTimestampScopeFinder() {
        // empty
    }

    @Override
    protected List<SignatureScope> filterCoveredSignatureScopes(TimestampToken timestampToken) {
        final List<TimestampInclude> timestampIncludes = timestampToken.getTimestampIncludes();
        if (Utils.isCollectionNotEmpty(timestampIncludes)) {
            List<SignatureScope> individualSignatureScopes = new ArrayList<>();
            List<SignatureScope> signatureScopes = signature.getSignatureScopes();
            if (Utils.isCollectionNotEmpty(signatureScopes)) {
                for (ReferenceValidation referenceValidation : signature.getReferenceValidations()) {
                    XAdESReferenceValidation xadesReferenceValidation = (XAdESReferenceValidation) referenceValidation;
                    if (isContentTimestampedReference(xadesReferenceValidation, timestampIncludes)) {
                        for (SignatureScope signatureScope : signatureScopes) {
                            if (Utils.endsWithIgnoreCase(xadesReferenceValidation.getUri(), signatureScope.getDocumentName())) {
                                individualSignatureScopes.add(signatureScope);
                            }
                        }
                    }
                }
            }
            return individualSignatureScopes;
        }
        return super.filterCoveredSignatureScopes(timestampToken);
    }

    private boolean isContentTimestampedReference(XAdESReferenceValidation xadesReferenceValidation, List<TimestampInclude> includes) {
        if (xadesReferenceValidation.getId() != null) {
            for (TimestampInclude timestampInclude : includes) {
                if (xadesReferenceValidation.getId().equals(timestampInclude.getURI())) {
                    return true;
                }
            }
        }
        return false;
    }

}
