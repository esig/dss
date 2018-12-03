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
package eu.europa.esig.dss;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.utils.Utils;

public class RemoteConverter {

	private RemoteConverter() {
	}

	public static List<DSSDocument> toDSSDocuments(List<RemoteDocument> remoteDocuments) {
		if (Utils.isCollectionNotEmpty(remoteDocuments)) {
			List<DSSDocument> dssDocuments = new ArrayList<DSSDocument>();
			for (RemoteDocument remoteDocument : remoteDocuments) {
				if (remoteDocument != null) {
					dssDocuments.add(toDSSDocument(remoteDocument));
				}
			}
			return dssDocuments;
		}
		return null;
	}

	public static DSSDocument toDSSDocument(RemoteDocument remoteDocument) {
		if (remoteDocument.getDigestAlgorithm() != null) {
			DigestDocument digestDocument = new DigestDocument();
			digestDocument.addDigest(remoteDocument.getDigestAlgorithm(), Utils.toBase64(remoteDocument.getBytes()));
			digestDocument.setName(remoteDocument.getName());
			digestDocument.setMimeType(remoteDocument.getMimeType());
			return digestDocument;
		} else {
			return new InMemoryDocument(remoteDocument.getBytes(), remoteDocument.getName(), remoteDocument.getMimeType());
		}
	}

	public static List<RemoteDocument> toRemoteDocuments(List<DSSDocument> originalDocuments) {
		List<RemoteDocument> results = new ArrayList<RemoteDocument>();
		for (DSSDocument originalDocument : originalDocuments) {
			results.add(toRemoteDocument(originalDocument));
		}
		return results;
	}

	public static RemoteDocument toRemoteDocument(DSSDocument originalDocument) {
		return new RemoteDocument(DSSUtils.toByteArray(originalDocument), originalDocument.getMimeType(), originalDocument.getName());
	}

}
