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

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.EncapsulatedTimestampScopeFinder;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.xml.security.signature.Reference;

import java.util.ArrayList;
import java.util.List;

/**
 * Finds a timestamp scope for a XAdES encapsulated timestamps
 *
 */
public class XAdESTimestampScopeFinder extends EncapsulatedTimestampScopeFinder {

    @Override
    protected List<SignatureScope> filterCoveredSignatureScopes(TimestampToken timestampToken) {
        final List<TimestampInclude> timestampIncludes = timestampToken.getTimestampIncludes();
        if (Utils.isCollectionNotEmpty(timestampIncludes)) {
            List<SignatureScope> individualSignatureScopes = new ArrayList<>();
            XAdESSignature xadesSignature = (XAdESSignature) signature;
            for (Reference reference : xadesSignature.getReferences()) {
                if (isContentTimestampedReference(reference, timestampIncludes)) {
                    List<SignatureScope> signatureScopes = signature.getSignatureScopes();
                    if (Utils.isCollectionNotEmpty(signatureScopes)) {
                        for (SignatureScope signatureScope : signatureScopes) {
                            if (Utils.endsWithIgnoreCase(reference.getURI(), signatureScope.getName())) {
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

    private boolean isContentTimestampedReference(Reference reference, List<TimestampInclude> includes) {
        for (TimestampInclude timestampInclude : includes) {
            if (reference.getId().equals(timestampInclude.getURI())) {
                return true;
            }
        }
        return false;
    }

}
