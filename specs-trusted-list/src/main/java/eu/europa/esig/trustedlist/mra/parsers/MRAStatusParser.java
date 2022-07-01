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
package eu.europa.esig.trustedlist.mra.parsers;

import eu.europa.esig.dss.enumerations.MRAStatus;

public final class MRAStatusParser {

	private MRAStatusParser() {
	}

	public static MRAStatus parse(String v) {
		if (v != null) {
			for (MRAStatus m : MRAStatus.values()) {
				if (m.getUri().equals(v)) {
					return m;
				}
			}
		}
		return null;
	}

	public static String print(MRAStatus m) {
		if (m != null) {
			return m.getUri();
		}
		return null;
	}

}
