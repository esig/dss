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

package eu.europa.ec.markt.dss.validation102853.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class represents the basic validation process validity constraints.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class BasicValidationProcessValidConstraint extends Constraint {

	private static final Logger LOG = LoggerFactory.getLogger(BasicValidationProcessValidConstraint.class);
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

			node.addChild(STATUS, KO);
			conclusion.copyConclusion(basicValidationProcessConclusionNode);
			return false;
		}
		node.addChild(STATUS, OK);
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

