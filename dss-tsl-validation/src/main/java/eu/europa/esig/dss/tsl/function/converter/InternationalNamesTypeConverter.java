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
package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;

public class InternationalNamesTypeConverter implements Function<InternationalNamesType, Map<String, List<String>>> {

	private final Predicate<String> predicate;

	public InternationalNamesTypeConverter() {
		// select all
		this(x -> true);
	}

	public InternationalNamesTypeConverter(Predicate<String> predicate) {
		super();
		this.predicate = predicate;
	}

	@Override
	public Map<String, List<String>> apply(InternationalNamesType original) {
		Map<String, List<String>> result = new HashMap<>();
		if (original != null && Utils.isCollectionNotEmpty(original.getName())) {
			for (MultiLangNormStringType multiLangNormString : original.getName()) {
				final String lang = multiLangNormString.getLang();
				final String value = multiLangNormString.getValue();
				if (predicate.test(value)) {
					result.computeIfAbsent(lang, k -> new ArrayList<>()).add(value);
				}
			}
		}
		return result;
	}

}
