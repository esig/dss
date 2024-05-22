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
package eu.europa.esig.dss.tsl.dto.condition;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.tsl.Condition;
import eu.europa.esig.trustedlist.enums.Assert;

import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.unmodifiableList;

/**
 * Condition resulting of the matchingCriteriaIndicator of other Conditions
 */
public class CompositeCondition implements Condition {

	private static final long serialVersionUID = -3756905347291887068L;

	/** The matching criteria */
	private Assert matchingCriteriaIndicator;

	/**
	 * The list of child conditions
	 */
	private List<Condition> children = new ArrayList<>();

	/**
	 * The default constructor for CriteriaListCondition.
	 * All conditions must match
	 */
	public CompositeCondition() {
		this.matchingCriteriaIndicator = Assert.ALL;
	}

	/**
	 * Constructor for CriteriaListCondition.
	 *
	 * @param matchingCriteriaIndicator
	 *            matching criteria indicator: atLeastOne, all, none
	 */
	public CompositeCondition(final Assert matchingCriteriaIndicator) {
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
	public Assert getMatchingCriteriaIndicator() {
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
			case ALL:
				for (final Condition condition : children) {
					if (!condition.check(certificateToken)) {
						return false;
					}
				}
				return true;
			case AT_LEAST_ONE:
				for (final Condition condition : children) {
					if (condition.check(certificateToken)) {
						return true;
					}
				}
				return false;
			case NONE:
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
