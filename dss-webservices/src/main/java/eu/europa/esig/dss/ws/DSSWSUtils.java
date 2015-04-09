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
package eu.europa.esig.dss.ws;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;

/**
 * This is the utility class to handle web services.
 *
 *
 *
 *
 *
 */
public final class DSSWSUtils {

	private DSSWSUtils() {
	}

	public static DSSDocument createDssDocument(final WSDocument wsDocument) {

		if (wsDocument == null) {
			return null;
		}
		final InMemoryDocument dssDocument = new InMemoryDocument(wsDocument.getBytes());
		dssDocument.setName(wsDocument.getName());
		dssDocument.setAbsolutePath(wsDocument.getAbsolutePath());
		final MimeType mimeType = wsDocument.getMimeType();
		dssDocument.setMimeType(mimeType);
		final WSDocument nextWsDocument = wsDocument.getNextDocument();
		if (nextWsDocument != null) {

			final DSSDocument nextDssDocument = createDssDocument(nextWsDocument);
			dssDocument.setNextDocument(nextDssDocument);
		}
		return dssDocument;
	}
}
