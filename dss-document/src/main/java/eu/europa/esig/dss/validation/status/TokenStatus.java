package eu.europa.esig.dss.validation.status;

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
