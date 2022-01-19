package eu.europa.esig.dss.validation.status;

import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains information about the performed revocation freshness check
 *
 */
public class RevocationFreshnessStatus extends TokenStatus {

    /**
     * Map between tokens concerned by the revocation freshness check and
     * the nextUpdate time of the corresponding revocation data
     */
    private final Map<Token, Date> tokenRevocationNextUpdateMap = new HashMap<>();

    /**
     * Adds concerned token and nextUpdate time of the revocation data
     *
     * @param token {@link Token}
     * @param revocationNextUpdate {@link String} message
     */
    public void addTokenAndRevocationNextUpdateTime(Token token, Date revocationNextUpdate) {
        tokenRevocationNextUpdateMap.put(token, revocationNextUpdate);
    }

    /**
     * Returns nextUpdate time of revocation data for the given token
     *
     * NOTE: returns Date only if the obtained revocation data is not fresh enough (otherwise returns null)
     *
     * @param token {@link Token} to get related revocation data's nextUpdate time
     * @return {@link Date}
     */
    public Date getTokenRevocationNextUpdateTime(Token token) {
        return tokenRevocationNextUpdateMap.get(token);
    }

    /**
     * Returns minimal time when revocation data should be updated for all concerned tokens
     *
     * NOTE: returns NULL if no suitable revocation data found or if the revocation data is fresh enough
     *
     * @return {@link Date}
     */
    public Date getMinimalNextUpdateTime() {
        Date minimalNextUpdate = null;
        for (Date nextUpdate : tokenRevocationNextUpdateMap.values()) {
            if (minimalNextUpdate == null || minimalNextUpdate.before(nextUpdate)) {
                minimalNextUpdate = nextUpdate;
            }
        }
        return minimalNextUpdate;
    }

    @Override
    public String getErrorString() {
        Date nextUpdateTime = getMinimalNextUpdateTime();
        return nextUpdateTime != null ?
                getMessage() + " NextUpdate time : " + DSSUtils.formatDateToRFC(nextUpdateTime) + " " + objectMapToString() :
                super.getErrorString();
    }

}
