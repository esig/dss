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
package eu.europa.esig.dss.validation.status;

import eu.europa.esig.dss.alert.status.ObjectStatus;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains signatures concerned by an occurred event and corresponding information about them
 *
 */
public class SignatureStatus extends ObjectStatus {

    /** Map between signatures concerned by the check and corresponding error explanation messages */
    private final Map<AdvancedSignature, String> relatedSignatureMap = new HashMap<>();

    /**
     * Adds concerned signature and information about the occurred event
     *
     * @param signature {@link AdvancedSignature}
     * @param errorMessage {@link String} message
     */
    public void addRelatedTokenAndErrorMessage(AdvancedSignature signature, String errorMessage) {
        super.addRelatedObjectIdentifierAndErrorMessage(signature.getId(), errorMessage);
        relatedSignatureMap.put(signature, errorMessage);
    }

    /**
     * Returns a collection of signatures concerned by failure of the processed check
     *
     * @return a collection of {@link AdvancedSignature}s
     */
    public Collection<AdvancedSignature> getRelatedSignatures() {
        return relatedSignatureMap.keySet();
    }

    /**
     * Returns error message for the given signature
     *
     * @param signature {@link AdvancedSignature} to get caused error message for
     * @return {@link String} error message
     */
    public String getMessageForSignature(AdvancedSignature signature) {
        return relatedSignatureMap.get(signature);
    }

    @Override
    public boolean isEmpty() {
        return super.isEmpty() && Utils.isMapEmpty(relatedSignatureMap);
    }

}
