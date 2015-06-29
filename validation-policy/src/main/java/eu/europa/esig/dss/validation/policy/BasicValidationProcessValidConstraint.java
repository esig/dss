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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;

/**
 * This class represents the basic validation process validity constraints.
 */
public class BasicValidationProcessValidConstraint extends Constraint {

	private XmlDom basicValidationProcessConclusionNode;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
	 *
	 * @param level the constraint level string.
	 */
	public BasicValidationProcessValidConstraint(final String level) {

		super(level);
	}

	/**
	 * This method carry out the validation of the constraint. This constraint has a constant {@code Level} FAIL.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	@Override
	public boolean check() {

		if (!value.equals(expectedValue)) {

			node.addChild(NodeName.STATUS, NodeValue.KO);
			conclusion.copyConclusion(basicValidationProcessConclusionNode);
			return false;
		}
		node.addChild(NodeName.STATUS, NodeValue.OK);
		// The consolidation of the warning is made in the SimpleReportBuilder
		// conclusion.copyWarnings(basicValidationProcessConclusionNode);
		return true;
	}

	public void setBasicValidationProcessConclusionNode(final XmlDom basicValidationProcessConclusionNode) {
		this.basicValidationProcessConclusionNode = basicValidationProcessConclusionNode;
	}

	public XmlDom getBasicValidationProcessConclusionNode() {
		return basicValidationProcessConclusionNode;
	}
}

