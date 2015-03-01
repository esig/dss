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
package eu.europa.ec.markt.dss.applet.util;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.xml.datatype.XMLGregorianCalendar;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.ChainCertificate;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.ws.signature.DSSException_Exception;
import eu.europa.ec.markt.dss.ws.signature.DigestAlgorithm;
import eu.europa.ec.markt.dss.ws.signature.DssTransform;
import eu.europa.ec.markt.dss.ws.signature.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.ws.signature.ObjectFactory;
import eu.europa.ec.markt.dss.ws.signature.Policy;
import eu.europa.ec.markt.dss.ws.signature.SignatureLevel;
import eu.europa.ec.markt.dss.ws.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.ws.signature.SignatureService;
import eu.europa.ec.markt.dss.ws.signature.SignatureService_Service;
import eu.europa.ec.markt.dss.ws.signature.WsChainCertificate;
import eu.europa.ec.markt.dss.ws.signature.WsDocument;
import eu.europa.ec.markt.dss.ws.signature.WsParameters;
import eu.europa.ec.markt.dss.ws.signature.WsdssReference;

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

	private static ObjectFactory FACTORY;

	static {

		System.setProperty("javax.xml.bind.JAXBContext", "com.sun.xml.internal.bind.v2.ContextFactory");
		FACTORY = new ObjectFactory();
	}

	private SigningUtils() {

	}

	/**
	 * @param serviceURL
	 * @param signedFile
	 * @param detachedFile
	 * @param parameters
	 * @return
	 * @throws DSSException
	 */
	public static DSSDocument extendDocument(final String serviceURL, final File signedFile, final File detachedFile, final SignatureParameters parameters) throws DSSException {

		try {

			final WsDocument wsSignedDocument = toWsDocument(signedFile);
			if (detachedFile != null) {

				final DSSDocument detachedContent = new FileDocument(detachedFile);
				parameters.setDetachedContent(detachedContent);
			}

			final WsParameters wsParameters = new WsParameters();

			final String signatureLevelString = parameters.getSignatureLevel().name();
			final SignatureLevel signatureLevel = SignatureLevel.fromValue(signatureLevelString);
			wsParameters.setSignatureLevel(signatureLevel);

			final String signaturePackagingString = parameters.getSignaturePackaging().name();
			SignaturePackaging signaturePackaging = SignaturePackaging.valueOf(signaturePackagingString);
			wsParameters.setSignaturePackaging(signaturePackaging);

			SignatureService_Service.setROOT_SERVICE_URL(serviceURL);
			final SignatureService_Service signatureService_service = new SignatureService_Service();
			final SignatureService signatureServiceImplPort = signatureService_service.getSignatureServiceImplPort();

			final WsDocument wsExtendedDocument = signatureServiceImplPort.extendSignature(wsSignedDocument, wsParameters);

			final InMemoryDocument inMemoryDocument = toInMemoryDocument(wsExtendedDocument);
			return inMemoryDocument;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * @param file
	 * @param parameters
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws DSSException
	 */
	public static DSSDocument signDocument(final String serviceURL, final File file, final SignatureParameters parameters) throws DSSException {

		try {

			final WsDocument wsDocument = toWsDocument(file);

			final WsParameters wsParameters = new WsParameters();

			prepareKeyParameters(parameters, wsParameters);

			prepareCertificateChain(parameters, wsParameters);

			final BLevelParameters bLevelParameters = parameters.bLevel();

			prepareSignaturePolicy(wsParameters, bLevelParameters);

			prepareClaimedSignerRoles(wsParameters, bLevelParameters);

			prepareReferences(parameters, wsParameters);
			wsParameters.setDeterministicId(parameters.getDeterministicId());

			// System.out.println("#@@@@@@@@: " + serviceURL);
			SignatureService_Service.setROOT_SERVICE_URL(serviceURL);
			final SignatureService_Service signatureService_service = new SignatureService_Service();
			final SignatureService signatureServiceImplPort = signatureService_service.getSignatureServiceImplPort();

			final byte[] toBeSignedBytes = signatureServiceImplPort.getDataToSign(wsDocument, wsParameters);

			final DSSPrivateKeyEntry privateKey = parameters.getPrivateKeyEntry();
			final SignatureTokenConnection tokenConnection = parameters.getSigningToken();
			final byte[] encrypted = tokenConnection.sign(toBeSignedBytes, parameters.getDigestAlgorithm(), privateKey);

			final WsDocument wsSignedDocument = signatureServiceImplPort.signDocument(wsDocument, wsParameters, encrypted);

			final InMemoryDocument inMemoryDocument = toInMemoryDocument(wsSignedDocument);
			return inMemoryDocument;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	private static void prepareKeyParameters(SignatureParameters parameters, WsParameters wsParameters) {

		final String signatureLevelString = parameters.getSignatureLevel().name();
		final SignatureLevel signatureLevel = SignatureLevel.fromValue(signatureLevelString);
		wsParameters.setSignatureLevel(signatureLevel);

		final String signaturePackagingString = parameters.getSignaturePackaging().name();
		final SignaturePackaging signaturePackaging = SignaturePackaging.valueOf(signaturePackagingString);
		wsParameters.setSignaturePackaging(signaturePackaging);

		final String encryptionAlgorithmString = parameters.getEncryptionAlgorithm().name();
		final EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.fromValue(encryptionAlgorithmString);
		wsParameters.setEncryptionAlgorithm(encryptionAlgorithm);

		//		System.out.println("####>: " + parameters.getDigestAlgorithm());
		final String digestAlgorithmString = parameters.getDigestAlgorithm().name();
		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.fromValue(digestAlgorithmString);
		wsParameters.setDigestAlgorithm(digestAlgorithm);

		final XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(new Date());
		wsParameters.setSigningDate(xmlGregorianCalendar);
		final byte[] encoded = parameters.getSigningCertificate().getEncoded();
		wsParameters.setSigningCertificateBytes(encoded);
	}

	private static void prepareCertificateChain(SignatureParameters parameters, WsParameters wsParameters) {
		final List<ChainCertificate> certificateChain = parameters.getCertificateChain();
		if (!DSSUtils.isEmpty(certificateChain)) {

			final List<WsChainCertificate> wsChainCertificateList = wsParameters.getChainCertificateList();
			for (final ChainCertificate chainCertificate : certificateChain) {

				final WsChainCertificate wsChainCertificate = new WsChainCertificate();
				final CertificateToken x509Certificate = chainCertificate.getX509Certificate();
				wsChainCertificate.setX509Certificate(x509Certificate.getEncoded());
				wsChainCertificate.setSignedAttribute(chainCertificate.isSignedAttribute());
				wsChainCertificateList.add(wsChainCertificate);
			}
		}
	}

	private static void prepareClaimedSignerRoles(WsParameters wsParameters, BLevelParameters bLevelParameters) {
		final List<String> claimedSignerRoles = bLevelParameters.getClaimedSignerRoles();
		if (claimedSignerRoles != null) {
			for (final String claimedSignerRole : claimedSignerRoles) {

				final List<String> wsClaimedSignerRoles = wsParameters.getClaimedSignerRole();
				wsClaimedSignerRoles.add(claimedSignerRole);
			}
		}
	}

	private static void prepareSignaturePolicy(WsParameters wsParameters, BLevelParameters bLevelParameters) {
		final BLevelParameters.Policy signaturePolicy = bLevelParameters.getSignaturePolicy();
		if (signaturePolicy != null) {

			final Policy policy = new Policy();
			policy.setId(signaturePolicy.getId());
			final String policyDigestAlgorithmString = signaturePolicy.getDigestAlgorithm().name();
			final DigestAlgorithm wsDigestAlgorithm = DigestAlgorithm.valueOf(policyDigestAlgorithmString);
			policy.setDigestAlgorithm(wsDigestAlgorithm);
			final byte[] digestValue = signaturePolicy.getDigestValue();
			policy.setDigestValue(digestValue);
			wsParameters.setSignaturePolicy(policy);
		}
	}

	/**
	 * @param parameters
	 * @param wsParameters
	 */
	private static void prepareReferences(final SignatureParameters parameters, final WsParameters wsParameters) {

		final List<WsdssReference> wsDssReferences = wsParameters.getReferences();
		final List<DSSReference> dssReferences = parameters.getReferences();
		if (dssReferences == null) {
			return;
		}
		for (final DSSReference dssReference : dssReferences) {

			final WsdssReference wsDssReference = FACTORY.createWsdssReference();
			wsDssReference.setId(dssReference.getId());
			wsDssReference.setType(dssReference.getType());
			wsDssReference.setUri(dssReference.getUri());
			final String name = dssReference.getDigestMethodAlgorithm().getName();
			final DigestAlgorithm value = DigestAlgorithm.fromValue(name);
			wsDssReference.setDigestMethodAlgorithm(value);
			final DSSDocument contents = dssReference.getContents();
			wsDssReference.setContents(toWsDocument(contents));

			final List<DSSTransform> dssTransforms = dssReference.getTransforms();
			if (dssTransforms != null) {

				for (DSSTransform dssTransform : dssTransforms) {

					final DssTransform wsDssTransform = FACTORY.createDssTransform();
					wsDssTransform.setElementName(dssTransform.getElementName());
					wsDssTransform.setTextContent(dssTransform.getTextContent());
					wsDssTransform.setNamespace(dssTransform.getNamespace());
					wsDssTransform.setAlgorithm(dssTransform.getAlgorithm());
					final List<DssTransform> wsDssTransforms = wsDssReference.getTransforms();
					wsDssTransforms.add(wsDssTransform);
				}
			}
			wsDssReferences.add(wsDssReference);
		}
	}

	public static WsDocument toWsDocument(final DSSDocument dssDocument) {

		final WsDocument wsDocument = new WsDocument();
		wsDocument.setBytes(dssDocument.getBytes());
		wsDocument.setName(dssDocument.getName());
		wsDocument.setAbsolutePath(dssDocument.getAbsolutePath());
		final MimeType mimeType = dssDocument.getMimeType();
		final eu.europa.ec.markt.dss.ws.signature.MimeType wsMimeType = FACTORY.createMimeType();
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
		final eu.europa.ec.markt.dss.ws.signature.MimeType wsMimeType = FACTORY.createMimeType();
		final String mimeTypeString = mimeType.getMimeTypeString();
		wsMimeType.setMimeTypeString(mimeTypeString);
		wsDocument.setMimeType(wsMimeType);
		return wsDocument;
	}

	public static InMemoryDocument toInMemoryDocument(final WsDocument wsSignedDocument) {

		final InMemoryDocument inMemoryDocument = new InMemoryDocument(wsSignedDocument.getBytes());
		inMemoryDocument.setName(wsSignedDocument.getName());
		inMemoryDocument.setAbsolutePath(wsSignedDocument.getAbsolutePath());
		final eu.europa.ec.markt.dss.ws.signature.MimeType wsMimeType = wsSignedDocument.getMimeType();
		final MimeType mimeType = MimeType.fromMimeTypeString(wsMimeType.getMimeTypeString());
		inMemoryDocument.setMimeType(mimeType);
		return inMemoryDocument;
	}
}
