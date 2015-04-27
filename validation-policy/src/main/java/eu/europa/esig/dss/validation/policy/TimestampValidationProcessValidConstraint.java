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

import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;

/**
 * This class represents the timestamp validation process validity constraints.
 */
public class TimestampValidationProcessValidConstraint extends Constraint {

	private int validTimestampCount;
	private String subIndication1;
	private String subIndication2;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
	 *
	 * @param level the constraint level string.
	 */
	public TimestampValidationProcessValidConstraint(final String level) {

		super(level);
	}

	/**
	 * This method carries out the validation of the constraint. This constraint has a constant {@code Level} FAIL.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	@Override
	public boolean check() {

		if (validTimestampCount < 1) {

			node.addChild(NodeName.STATUS, NodeValue.KO);

			if (validTimestampCount == 0) {

				conclusion.setIndication(indication, subIndication1);
			} else {

				conclusion.setIndication(indication, subIndication2);
			}
			conclusion.addError(failureMessageTag, messageAttributes);
			return false;
		}
		node.addChild(NodeName.STATUS, NodeValue.OK);
		if (!messageAttributes.isEmpty()) {
			node.addChild(NodeName.INFO, null, messageAttributes);
		}
		return true;
	}

	public void setValidTimestampCount(final int validTimestampCount) {

		this.validTimestampCount = validTimestampCount;
	}

	public int getValidTimestampCount() {
		return validTimestampCount;
	}

	public void setSubIndication1(final String subIndication1) {
		this.subIndication1 = subIndication1;
	}

	public String getSubIndication1() {
		return subIndication1;
	}

	public void setSubIndication2(final String subIndication2) {
		this.subIndication2 = subIndication2;
	}

	public String getSubIndication2() {
		return subIndication2;
	}
}

