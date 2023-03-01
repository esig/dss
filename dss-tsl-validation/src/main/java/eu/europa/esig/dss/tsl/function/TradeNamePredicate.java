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
package eu.europa.esig.dss.tsl.function;

import java.util.function.Predicate;

/**
 * Predicate which filter official registration identifiers
 */
public class TradeNamePredicate implements Predicate<String> {

	private OfficialRegistrationIdentifierPredicate registrationIdentifier = new OfficialRegistrationIdentifierPredicate();

	/**
	 * Default constructor instantiating OfficialRegistrationIdentifierPredicate
	 */
	public TradeNamePredicate() {
		// empty
	}

	@Override
	public boolean test(String t) {
		return t != null && !registrationIdentifier.test(t);
	}

}
