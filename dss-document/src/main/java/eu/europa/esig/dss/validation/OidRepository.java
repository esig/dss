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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.QCStatement;

import java.util.HashMap;
import java.util.Map;

/**
 * Contains a map between OIDs and their corresponding descriptions
 */
public class OidRepository {

	/** Map between OIDs and their corresponding descriptions */
	private static final Map<String, String> repository = new HashMap<>();

	static {
		for (OidDescription oid : CertificatePolicy.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
		for (OidDescription oid : QCStatement.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
		for (ExtendedKeyUsage oid : ExtendedKeyUsage.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
	}

	private OidRepository() {
	}

	/**
	 * Gets description corresponding to the given OID
	 *
	 * @param oid {@link String} to get description for
	 * @return {@link String}
	 */
	public static String getDescription(String oid) {
		return repository.get(oid);
	}

}
