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
package eu.europa.esig.dss.validation.process.bbb;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public abstract class AbstractMultiValuesCheckItem<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private static final String ALL_VALUE = "*";

	private final MultiValuesConstraint constraint;

	protected AbstractMultiValuesCheckItem(T result, MultiValuesConstraint constraint) {
		super(result, constraint);

		this.constraint = constraint;
	}

	protected boolean processValueCheck(String value) {
		List<String> expecteds = constraint.getId();
		if (Utils.isStringNotEmpty(value) && Utils.isCollectionNotEmpty(expecteds)) {
			if (expecteds.contains(ALL_VALUE)) {
				return true;
			} else if (expecteds.contains(value)) {
				return true;
			}
		}
		return false;
	}

	protected boolean processValuesCheck(List<String> values) {
		if (Utils.isCollectionNotEmpty(values)) {
			if (Utils.isCollectionNotEmpty(constraint.getId())) {
				for (String value : values) {
					for (String expected : constraint.getId()) {
						if (expected.equals(value)) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

}
