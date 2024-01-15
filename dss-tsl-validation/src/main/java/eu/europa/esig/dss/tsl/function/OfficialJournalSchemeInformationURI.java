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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;

/**
 * Filters the Official Journal Scheme information URI
 *
 */
public class OfficialJournalSchemeInformationURI implements LOTLSigningCertificatesAnnouncementSchemeInformationURI {

	/** The OJ URL */
	private final String officialJournalURL;

	/**
	 * Default constructor
	 *
	 * @param officialJournalURL {@link String} OJ URL
	 */
	public OfficialJournalSchemeInformationURI(String officialJournalURL) {
		Objects.requireNonNull(officialJournalURL);
		this.officialJournalURL = officialJournalURL;
	}

	@Override
	public boolean test(NonEmptyMultiLangURIType t) {
		if (t != null && t.getValue() != null) {
			return t.getValue().contains(getOJDomain());
		}
		return false;
	}

	private String getOJDomain() {
		try {
			URL uri = new URL(officialJournalURL);
			return uri.getHost();
		} catch (MalformedURLException e) {
			throw new DSSException("Incorrect format of Official Journal URL [" + officialJournalURL + "] is provided", e);
		}
	}

	@Override
	public String getUri() {
		return officialJournalURL;
	}

}
