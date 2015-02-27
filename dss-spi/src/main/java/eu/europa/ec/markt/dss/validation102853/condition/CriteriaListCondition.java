/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.condition;

import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * Condition resulting of the matchingCriteriaIndicator of other Conditions
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (Mon, 06 Jun 2011) $
 */

public class CriteriaListCondition extends CompositeCondition {

    private MatchingCriteriaIndicator matchingCriteriaIndicator;

    /**
     * The default constructor for CriteriaListCondition.
     *
     * @param matchingCriteriaIndicator matching criteria indicator: atLeastOne, all, none
     */
    public CriteriaListCondition(final MatchingCriteriaIndicator matchingCriteriaIndicator) {

        if (matchingCriteriaIndicator == null) {

            throw new DSSNullException(MatchingCriteriaIndicator.class);
        }
        this.matchingCriteriaIndicator = matchingCriteriaIndicator;
    }

    /**
     * Returns the matching criteria indicator
     *
     * @return matching criteria indicator: atLeastOne, all, none
     */
    public MatchingCriteriaIndicator getMatchingCriteriaIndicator() {

        return matchingCriteriaIndicator;
    }

    /**
     * @param certificateToken certificate to be checked
     * @return
     */
    @Override
    public boolean check(final CertificateToken certificateToken) {

        switch (matchingCriteriaIndicator) {
            case all:
                for (final Condition condition : children) {
                    if (!condition.check(certificateToken)) {
                        return false;
                    }
                }
                return true;
            case atLeastOne:
                for (final Condition condition : children) {
                    if (condition.check(certificateToken)) {
                        return true;
                    }
                }
                return false;
            case none:
                for (final Condition condition : children) {
                    if (condition.check(certificateToken)) {
                        return false;
                    }
                }
                return true;
        }
        throw new IllegalStateException("Unsupported MatchingCriteriaIndicator " + matchingCriteriaIndicator);
    }

    @Override
    public String toString(String indent) {

        if (indent == null) {
            indent = "";
        }
        try {

            final StringBuilder builder = new StringBuilder();
            builder.append(indent).append("CriteriaListCondition: ").append(matchingCriteriaIndicator.name()).append('\n');
            if (children != null) {

                indent += "\t";
                for (final Condition condition : children) {

                    builder.append(condition.toString(indent));
                }
            }
            return builder.toString();
        } catch (Exception e) {

            return e.toString();
        }
    }

    @Override
    public String toString() {

        return toString("");
    }
}
