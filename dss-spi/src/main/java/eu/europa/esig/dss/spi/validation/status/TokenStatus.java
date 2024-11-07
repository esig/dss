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
package eu.europa.esig.dss.spi.validation.status;

import eu.europa.esig.dss.alert.status.ObjectStatus;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains tokens concerned by an occurred event and corresponding information about them
 *
 */
public class TokenStatus extends ObjectStatus {

    /** Map between tokens concerned by the check and corresponding error explanation messages */
    private final Map<Token, String> relatedTokenMap = new HashMap<>();

    /**
     * Default constructor instantiating an empty map of related tokens
     */
    public TokenStatus() {
        // empty
    }

    /**
     * Adds concerned token and information about the occurred event
     *
     * @param token {@link Token}
     * @param errorMessage {@link String} message
     */
    public void addRelatedTokenAndErrorMessage(Token token, String errorMessage) {
        super.addRelatedObjectIdentifierAndErrorMessage(token.getDSSIdAsString(), errorMessage);
        relatedTokenMap.put(token, errorMessage);
    }

    /**
     * Returns a collection of tokens concerned by failure of the processed check
     *
     * @return a collection of {@link Token}s
     */
    public Collection<Token> getRelatedTokens() {
        return relatedTokenMap.keySet();
    }

    /**
     * Returns error message for the given token
     *
     * @param token {@link Token} to get caused error message for
     * @return {@link String} error message
     */
    public String getMessageForToken(Token token) {
        return relatedTokenMap.get(token);
    }

    @Override
    public boolean isEmpty() {
        return super.isEmpty() && Utils.isMapEmpty(relatedTokenMap);
    }

}
