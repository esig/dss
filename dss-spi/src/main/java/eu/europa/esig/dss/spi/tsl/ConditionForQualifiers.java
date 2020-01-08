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
package eu.europa.esig.dss.spi.tsl;

import java.util.List;

/**
 * This class is a DTO representation for qualifier and conditions
 *
 */
public class ConditionForQualifiers {

	private Condition condition;
	private List<String> qualifiers;

	public ConditionForQualifiers(Condition condition, List<String> qualifiers) {
		this.condition = condition;
		this.qualifiers = qualifiers;
	}

	public List<String> getQualifiers() {
		return qualifiers;
	}

	public Condition getCondition() {
		return condition;
	}

	@Override
	public String toString() {
		return "ConditionForQualifiers [qualifiers=" + qualifiers + ", condition=" + condition + "]";
	}

}
