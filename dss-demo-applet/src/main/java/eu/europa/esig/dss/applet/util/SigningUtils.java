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
package eu.europa.esig.dss.applet.util;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.wsclient.signature.DigestAlgorithm;
import eu.europa.esig.dss.wsclient.signature.ObjectFactory;
import eu.europa.esig.dss.wsclient.signature.SignatureService;
import eu.europa.esig.dss.wsclient.signature.SignatureService_Service;
import eu.europa.esig.dss.wsclient.signature.WsDocument;
import eu.europa.esig.dss.wsclient.signature.WsParameters;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public final class SigningUtils {

	private static final Logger logger = LoggerFactory.getLogger(SigningUtils.class);

	private static ObjectFactory FACTORY;

	static {
		System.setProperty("javax.xml.bind.JAXBContext", "com.sun.xml.internal.bind.v2.ContextFactory");
		FACTORY = new ObjectFactory();
	}

	private SigningUtils() {
	}

	/**
	 * @param file
	 * @param parameters
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws DSSException
	 */
	public static DSSDocument signDocument(final String serviceURL, final File file, final WsParameters wsParameters, DSSPrivateKeyEntry privateKey, SignatureTokenConnection tokenConnection) throws DSSException {

		try {

			final WsDocument wsDocument = toWsDocument(file);

			SignatureService_Service.setROOT_SERVICE_URL(serviceURL);
			final SignatureService_Service signatureService_service = new SignatureService_Service();
			final SignatureService signatureServiceImplPort = signatureService_service.getSignatureServiceImplPort();

			final byte[] toBeSignedBytes = signatureServiceImplPort.getDataToSign(wsDocument, wsParameters);

			DigestAlgorithm wsDigestAlgo = wsParameters.getDigestAlgorithm();
			final byte[] encrypted = tokenConnection.sign(toBeSignedBytes, eu.europa.esig.dss.DigestAlgorithm.forName(wsDigestAlgo.name()), privateKey);

			final WsDocument wsSignedDocument = signatureServiceImplPort.signDocument(wsDocument, wsParameters, encrypted);

			final InMemoryDocument inMemoryDocument = toInMemoryDocument(wsSignedDocument);
			return inMemoryDocument;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public static WsDocument toWsDocument(final DSSDocument dssDocument) {
		final WsDocument wsDocument = new WsDocument();
		wsDocument.setBytes(dssDocument.getBytes());
		wsDocument.setName(dssDocument.getName());
		wsDocument.setAbsolutePath(dssDocument.getAbsolutePath());
		final MimeType mimeType = dssDocument.getMimeType();
		final eu.europa.esig.dss.wsclient.signature.MimeType wsMimeType = FACTORY.createMimeType();
		final String mimeTypeString = mimeType.getMimeTypeString();
		wsMimeType.setMimeTypeString(mimeTypeString);
		wsDocument.setMimeType(wsMimeType);
		return wsDocument;
	}

	public static WsDocument toWsDocument(final File file) {
		final DSSDocument dssDocument = new FileDocument(file);
		final WsDocument wsDocument = new WsDocument();
		wsDocument.setBytes(dssDocument.getBytes());
		wsDocument.setName(dssDocument.getName());
		wsDocument.setAbsolutePath(dssDocument.getAbsolutePath());
		final MimeType mimeType = dssDocument.getMimeType();
		final eu.europa.esig.dss.wsclient.signature.MimeType wsMimeType = FACTORY.createMimeType();
		final String mimeTypeString = mimeType.getMimeTypeString();
		wsMimeType.setMimeTypeString(mimeTypeString);
		wsDocument.setMimeType(wsMimeType);
		return wsDocument;
	}

	public static InMemoryDocument toInMemoryDocument(final WsDocument wsSignedDocument) {
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(wsSignedDocument.getBytes());
		inMemoryDocument.setName(wsSignedDocument.getName());
		inMemoryDocument.setAbsolutePath(wsSignedDocument.getAbsolutePath());
		final eu.europa.esig.dss.wsclient.signature.MimeType wsMimeType = wsSignedDocument.getMimeType();
		if (wsMimeType != null) {
			final MimeType mimeType = MimeType.fromMimeTypeString(wsMimeType.getMimeTypeString());
			inMemoryDocument.setMimeType(mimeType);
		} else{
			logger.warn("Mimetype is not filled !");
		}
		return inMemoryDocument;
	}
}
