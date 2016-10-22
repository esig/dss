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
package eu.europa.esig.dss.util;

import java.lang.reflect.Method;
import java.util.List;

/**
 * A language preference can select a "best" variant of a datum from a list
 * based on language.
 * 
 * @author jdvorak
 *
 */
public class LanguagePreference {

	private final String[] prefLangCodes;

	/**
	 * A new language preference (languages from left to right).
	 * 
	 * @param langCodes
	 *            the code of the most preferred language, of the second most
	 *            preferred one, etc.
	 */
	public LanguagePreference(final String... langCodes) {
		this.prefLangCodes = langCodes;
	}

	/**
	 * Choose the preferred item from the given list of items based on language.
	 * The item with the first preferred language is selected. If that does not
	 * exist then the item with the second preferred language, and so on. If no
	 * item matches a preferred language, the first item from the list is
	 * returned.
	 * 
	 * @param items
	 *            list of items; the items must not be null and must support a
	 *            <code>getLang()</code> method that returns String
	 * @return the item that matches the preference best; null if the input list
	 *         is null or empty
	 * @throws IllegalArgumentException
	 *             when there is trouble getting the language of the item
	 */
	public <T> T getPreferredOrFirst(final List<T> items) {
		if (items != null && !items.isEmpty()) {
			for (final String prefLangCode : prefLangCodes) {
				for (final T item : items) {
					final Class<?> clazz = item.getClass();
					try {
						final Method method = clazz.getMethod("getLang");
						final String itemLangCode = (String) method.invoke(item);
						if (prefLangCode.equals(itemLangCode)) {
							return item;
						}
					} catch (final Exception e) {
						throw new IllegalArgumentException("Trouble invoking the getLang() method on " + item, e);
					}
				}
			}
			return items.get(0);
		} else {
			return null;
		}
	}

}
