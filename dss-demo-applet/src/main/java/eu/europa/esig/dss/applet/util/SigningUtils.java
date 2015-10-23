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
import java.net.URL;
import java.security.NoSuchAlgorithmException;

import javax.xml.namespace.QName;
import javax.xml.ws.Service;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.DataToSignDTO;
import eu.europa.esig.dss.signature.SignDocumentDTO;
import eu.europa.esig.dss.signature.SoapDocumentSignatureService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;

public final class SigningUtils {

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
	public static DSSDocument signDocument(final String serviceURL, final File file, final RemoteSignatureParameters remoteParameters, DSSPrivateKeyEntry privateKey, SignatureTokenConnection tokenConnection) throws DSSException {
		try {
			URL wsdlURL = new URL(serviceURL);
			QName SERVICE_NAME = new QName("http://signature.dss.esig.europa.eu/", "SoapDocumentSignatureServiceImplService");
			Service service = Service.create(wsdlURL, SERVICE_NAME);
			SoapDocumentSignatureService signatureService = service.getPort(SoapDocumentSignatureService.class);

			RemoteDocument remoteDocument = new RemoteDocument(new FileDocument(file));

			ToBeSigned toBeSigned = signatureService.getDataToSign(new DataToSignDTO(remoteDocument, remoteParameters));
			SignatureValue signatureValue = tokenConnection.sign(toBeSigned, remoteParameters.getDigestAlgorithm(), privateKey);
			RemoteDocument signedDocument = signatureService.signDocument(new SignDocumentDTO(remoteDocument, remoteParameters, signatureValue));

			final InMemoryDocument inMemoryDocument = toInMemoryDocument(signedDocument);
			return inMemoryDocument;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public static InMemoryDocument toInMemoryDocument(final RemoteDocument remoteDocument) {
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(remoteDocument.getBytes());
		inMemoryDocument.setName(remoteDocument.getName());
		inMemoryDocument.setAbsolutePath(remoteDocument.getAbsolutePath());
		inMemoryDocument.setMimeType(remoteDocument.getMimeType());
		return inMemoryDocument;
	}
}
