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

import java.util.ArrayList;
import java.util.List;
import static java.util.Collections.unmodifiableList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Condition resulting of the matchingCriteriaIndicator of other Conditions
 */
public class CompositeCondition extends Condition {

	private static final long serialVersionUID = -3756905347291887068L;

	private MatchingCriteriaIndicator matchingCriteriaIndicator;

	/**
	 * The list of child conditions
	 */
	private List<Condition> children = new ArrayList<Condition>();

	/**
	 * The default constructor for CriteriaListCondition.
	 * All conditions must match
	 */
	public CompositeCondition() {
		this.matchingCriteriaIndicator = MatchingCriteriaIndicator.all;
	}

	/**
	 * Constructor for CriteriaListCondition.
	 *
	 * @param matchingCriteriaIndicator
	 *            matching criteria indicator: atLeastOne, all, none
	 */
	public CompositeCondition(final MatchingCriteriaIndicator matchingCriteriaIndicator) {
		this.matchingCriteriaIndicator = matchingCriteriaIndicator;
	}

    /**
     * Returns the list of child conditions.
     * 
     * @return an unmodifiable list, possibly empty; never {@code null}
     */
    public final List<Condition> getChildren() {
        return unmodifiableList(children);
    }

	/**
	 * This method adds a child condition. This allows to handle embedded conditions.
	 *
	 * @param condition
	 *            the condition to add in the composite
	 */
	public void addChild(final Condition condition) {
		children.add(condition);
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
	 * Execute the composite condition of the given certificate
	 * 
	 * @param certificateToken
	 *            certificate to be checked
	 * @return true if the condition matches
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
		default:
			throw new DSSException("Unsupported MatchingCriteriaIndicator : " + matchingCriteriaIndicator);
		}
	}

	@Override
	public String toString(String indent) {
		if (indent == null) {
			indent = "";
		}
		final StringBuilder builder = new StringBuilder();
		builder.append(indent).append("CriteriaListCondition: ").append(matchingCriteriaIndicator.name()).append('\n');
		if (children != null) {
			indent += "\t";
			for (final Condition condition : children) {
				builder.append(condition.toString(indent));
			}
		}
		return builder.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}
}
