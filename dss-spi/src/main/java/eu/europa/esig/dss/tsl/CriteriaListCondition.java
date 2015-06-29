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
package eu.europa.esig.dss.tsl;

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Condition resulting of the matchingCriteriaIndicator of other Conditions
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

            throw new NullPointerException();
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
