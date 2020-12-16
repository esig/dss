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
package eu.europa.esig.dss.ws.converter;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains utils to convert {@code DSSDocument} to {@code RemoteDocument} and vice versa
 */
public class RemoteDocumentConverter {

	private RemoteDocumentConverter() {
	}

	/**
	 * Converts the given list of {@code remoteDocuments} to a list of {@code DSSDocument}s
	 *
	 * @param remoteDocuments list of {@link RemoteDocument}s
	 * @return list of {@link DSSDocument}s
	 */
	public static List<DSSDocument> toDSSDocuments(List<RemoteDocument> remoteDocuments) {
		if (Utils.isCollectionNotEmpty(remoteDocuments)) {
			List<DSSDocument> dssDocuments = new ArrayList<>();
			for (RemoteDocument remoteDocument : remoteDocuments) {
				DSSDocument dssDocument = toDSSDocument(remoteDocument);
				if (dssDocument != null) {
					dssDocuments.add(dssDocument);
				}
			}
			return dssDocuments;
		}
		return null;
	}

	/**
	 * Converts the given {@code RemoteDocument} to a {@code DSSDocument}
	 *
	 * @param remoteDocument {@link RemoteDocument} to convert
	 * @return {@link DSSDocument}
	 */
	public static DSSDocument toDSSDocument(RemoteDocument remoteDocument) {
		if (remoteDocument == null || Utils.isArrayEmpty(remoteDocument.getBytes())) {
			return null;
		}
		if (remoteDocument.getDigestAlgorithm() != null) {
			DigestDocument digestDocument = new DigestDocument(remoteDocument.getDigestAlgorithm(), Utils.toBase64(remoteDocument.getBytes()));
			digestDocument.setName(remoteDocument.getName());
			return digestDocument;
		} else {
			return new InMemoryDocument(remoteDocument.getBytes(), remoteDocument.getName());
		}
	}

	/**
	 * Converts the given list of {@code originalDocuments} to a list of {@code RemoteDocument}s
	 *
	 * @param originalDocuments list of {@link DSSDocument}s
	 * @return list of {@link RemoteDocument}s
	 */
	public static List<RemoteDocument> toRemoteDocuments(List<DSSDocument> originalDocuments) {
		List<RemoteDocument> results = new ArrayList<>();
		for (DSSDocument originalDocument : originalDocuments) {
			RemoteDocument remoteDocument = toRemoteDocument(originalDocument);
			if (remoteDocument != null) {
				results.add(remoteDocument);
			}
		}
		return results;
	}

	/**
	 * Converts the given {@code DSSDocument} to a {@code RemoteDocument}
	 *
	 * @param originalDocument {@link DSSDocument} to convert
	 * @return {@link RemoteDocument}
	 */
	public static RemoteDocument toRemoteDocument(DSSDocument originalDocument) {
		if (originalDocument == null) {
			return null;
		}
		if (originalDocument instanceof DigestDocument) {
			DigestDocument digestDocument = (DigestDocument) originalDocument;
			Digest digest = digestDocument.getExistingDigest();
			if (digest.getAlgorithm() == null || digest.getValue() == null) {
				throw new DSSRemoteServiceException("Impossible to create a RemoteDocument from a DigestDocument with not defined Digest");
			}
			return new RemoteDocument(digest.getValue(), digest.getAlgorithm(), originalDocument.getName());
		}
		return new RemoteDocument(DSSUtils.toByteArray(originalDocument), originalDocument.getName());
	}

}
