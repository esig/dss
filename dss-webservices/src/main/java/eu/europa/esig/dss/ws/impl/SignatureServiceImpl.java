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
package eu.europa.esig.dss.ws.impl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.jws.WebService;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.ChainCertificate;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.ws.DSSWSUtils;
import eu.europa.esig.dss.ws.SignatureService;
import eu.europa.esig.dss.ws.WSChainCertificate;
import eu.europa.esig.dss.ws.WSDSSReference;
import eu.europa.esig.dss.ws.WSDocument;
import eu.europa.esig.dss.ws.WSParameters;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureForm;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * Implementation of the Interface for the Contract of the Signature Web Service.
 *
 *
 */

@WebService(endpointInterface = "eu.europa.esig.dss.ws.SignatureService", serviceName = "SignatureService")
public class SignatureServiceImpl implements SignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureServiceImpl.class);

	private DocumentSignatureService<XAdESSignatureParameters> xadesService;

	private DocumentSignatureService<CAdESSignatureParameters> cadesService;

	private DocumentSignatureService<PAdESSignatureParameters> padesService;

	private DocumentSignatureService<ASiCSignatureParameters> asicService;

	/**
	 * @param xadesService the xadesService to set
	 */
	public void setXadesService(DocumentSignatureService<XAdESSignatureParameters> xadesService) {
		this.xadesService = xadesService;
	}

	/**
	 * @param cadesService the cadesService to set
	 */
	public void setCadesService(DocumentSignatureService<CAdESSignatureParameters> cadesService) {
		this.cadesService = cadesService;
	}

	/**
	 * @param padesService the padesService to set
	 */
	public void setPadesService(DocumentSignatureService<PAdESSignatureParameters> padesService) {
		this.padesService = padesService;
	}

	/**
	 * @param asicService the asicService to set
	 */
	public void setAsicService(DocumentSignatureService<ASiCSignatureParameters> asicService) {
		this.asicService = asicService;
	}

	private DocumentSignatureService getServiceForSignatureLevel(final SignatureLevel signatureLevel) {
		SignatureForm signatureForm = signatureLevel.getSignatureForm();
		switch (signatureForm) {
			case XAdES:
				return xadesService;
			case CAdES:
				return cadesService;
			case PAdES:
				return padesService;
			case ASiC_E:
			case ASiC_S:
				return asicService;
			default:
				throw new IllegalArgumentException("Unrecognized format " + signatureLevel);
		}
	}

	private AbstractSignatureParameters createParameters(final WSParameters wsParameters) throws DSSException {
		if (wsParameters == null) {
			return null;
		}

		SignatureForm signatureForm = wsParameters.getSignatureLevel().getSignatureForm();
		AbstractSignatureParameters params = null;
		switch (signatureForm) {
			case XAdES :
				params = new XAdESSignatureParameters();
				break;
			case CAdES :
				params = new CAdESSignatureParameters();
				break;
			case PAdES :
				PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
				padesParams.setSignatureSize(9472 * 2); // double reserved space for signature
				params = padesParams;
				break;
			case ASiC_E:
			case ASiC_S:
				params = new ASiCSignatureParameters();
				break;
			default:
				throw new IllegalArgumentException("Unrecognized format " + signatureForm);
		}

		setSignatureLevel(wsParameters, params);

		setSignaturePackaging(wsParameters, params);

		setEncryptionAlgorithm(wsParameters, params);

		setDigestAlgorithm(wsParameters, params);

		setSigningDate(wsParameters, params);

		setSigningCertificateAndChain(wsParameters, params);

		setSignWithExpiredCertificate(wsParameters, params);

		setSignaturePolicy(wsParameters, params);

		setClaimedSignerRole(wsParameters, params);

		setContentIdentifierPrefix(wsParameters, params);
		setContentIdentifierSuffix(wsParameters, params);

		setCommitmentTypeIndication(wsParameters, params);

		setSignerLocation(wsParameters, params);

		if (SignatureForm.XAdES.equals(signatureForm)){
			setSignedInfoCanonicalizationMethod(wsParameters, (XAdESSignatureParameters) params);
			setReferences(wsParameters, (XAdESSignatureParameters) params);
		}

		if (SignatureForm.ASiC_E.equals(signatureForm) || SignatureForm.ASiC_S.equals(signatureForm)){
			setAsicSignatureForm(wsParameters, (ASiCSignatureParameters) params);
			setAsicMimeType(wsParameters,  (ASiCSignatureParameters) params);
			setAsicZipComment(wsParameters,  (ASiCSignatureParameters) params);
			setAsicEnclosedSignature(wsParameters,  (ASiCSignatureParameters) params);
		}

		return params;
	}

	private void setSignaturePolicy(WSParameters wsParameters, AbstractSignatureParameters params) {
		final Policy signaturePolicy = wsParameters.getSignaturePolicy();
		params.bLevel().setSignaturePolicy(signaturePolicy);
	}

	private void setSignerLocation(WSParameters wsParameters, AbstractSignatureParameters params) {
		final BLevelParameters.SignerLocation signerLocation = wsParameters.getSignerLocation();
		params.bLevel().setSignerLocation(signerLocation);
	}

	private void setCommitmentTypeIndication(WSParameters wsParameters, AbstractSignatureParameters params) {
		final List<String> commitmentTypeIndication = wsParameters.getCommitmentTypeIndication();
		params.bLevel().setCommitmentTypeIndications(commitmentTypeIndication);
	}

	private void setContentIdentifierSuffix(WSParameters wsParameters, AbstractSignatureParameters params) {
		final String contentIdentifierSuffix = wsParameters.getContentIdentifierSuffix();
		params.bLevel().setContentIdentifierSuffix(contentIdentifierSuffix);
	}

	private void setContentIdentifierPrefix(WSParameters wsParameters, AbstractSignatureParameters params) {
		final String contentIdentifierPrefix = wsParameters.getContentIdentifierPrefix();
		params.bLevel().setContentIdentifierPrefix(contentIdentifierPrefix);
	}

	private void setSignedInfoCanonicalizationMethod(WSParameters wsParameters, XAdESSignatureParameters params) {
		final String signedInfoCanonicalizationMethod = wsParameters.getSignedInfoCanonicalizationMethod();
		params.setSignedInfoCanonicalizationMethod(signedInfoCanonicalizationMethod);
	}

	private void setEncryptionAlgorithm(WSParameters wsParameters, AbstractSignatureParameters params) {
		final EncryptionAlgorithm encryptionAlgorithm = wsParameters.getEncryptionAlgorithm();
		params.setEncryptionAlgorithm(encryptionAlgorithm);
	}

	private void setDigestAlgorithm(final WSParameters wsParameters, final AbstractSignatureParameters params) {
		final DigestAlgorithm digestAlgorithm = wsParameters.getDigestAlgorithm();
		params.setDigestAlgorithm(digestAlgorithm);
	}

	private void setClaimedSignerRole(final WSParameters wsParameters, final AbstractSignatureParameters params) {
		final List<String> claimedSignerRoles = wsParameters.getClaimedSignerRole();
		if (claimedSignerRoles != null) {
			for (final String claimedSignerRole : claimedSignerRoles) {
				params.bLevel().addClaimedSignerRole(claimedSignerRole);
			}
		}
	}

	private void setSigningCertificateAndChain(final WSParameters wsParameters, final AbstractSignatureParameters params) {
		final byte[] signingCertBytes = wsParameters.getSigningCertificateBytes();
		if (signingCertBytes == null) {
			return;
		}
		final CertificateToken x509SigningCertificate = DSSUtils.loadCertificate(signingCertBytes);
		params.setSigningCertificate(x509SigningCertificate);

		final List<ChainCertificate> chainCertificates = new ArrayList<ChainCertificate>();
		chainCertificates.add(new ChainCertificate(x509SigningCertificate, true));
		final List<WSChainCertificate> wsChainCertificateList = wsParameters.getChainCertificateList();
		if (CollectionUtils.isNotEmpty(wsChainCertificateList)) {
			for (final WSChainCertificate wsChainCertificate : wsChainCertificateList) {
				final CertificateToken x509Certificate = DSSUtils.loadCertificate(wsChainCertificate.getX509Certificate());
				final ChainCertificate chainCertificate = new ChainCertificate(x509Certificate, wsChainCertificate.isSignedAttribute());
				if (!chainCertificates.contains(chainCertificate)) {
					chainCertificates.add(chainCertificate);
				}
			}
		}
		params.setCertificateChain(chainCertificates);
	}

	/**
	 * Allows to change the default behaviour regarding the use of an expired certificate.
	 *
	 * @param wsParameters
	 * @param params
	 */
	private void setSignWithExpiredCertificate(final WSParameters wsParameters, final AbstractSignatureParameters params) {
		final boolean signWithExpiredCertificate = wsParameters.getSignWithExpiredCertificate();
		params.setSignWithExpiredCertificate(signWithExpiredCertificate);
	}

	private void setSigningDate(final WSParameters wsParameters, final AbstractSignatureParameters params) {
		final Date signingDate = wsParameters.getSigningDate();
		params.bLevel().setSigningDate(signingDate);
	}

	private void setSignaturePackaging(final WSParameters wsParameters, final AbstractSignatureParameters params) {
		final SignaturePackaging signaturePackaging = wsParameters.getSignaturePackaging();
		params.setSignaturePackaging(signaturePackaging);
	}

	private void setSignatureLevel(final WSParameters wsParameters, final AbstractSignatureParameters params) {
		final SignatureLevel signatureLevel = wsParameters.getSignatureLevel();
		params.setSignatureLevel(signatureLevel);
	}

	private void setReferences(final WSParameters wsParameters, final XAdESSignatureParameters params) {
		final List<WSDSSReference> wsReferences = wsParameters.getReferences();
		if (wsReferences == null) {
			return;
		}
		final List<DSSReference> dssReferences = new ArrayList<DSSReference>();
		for (final WSDSSReference wsDssReference : wsReferences) {

			final DSSReference dssReference = new DSSReference();
			dssReference.setId(wsDssReference.getId());
			dssReference.setType(wsDssReference.getType());
			dssReference.setUri(wsDssReference.getUri());
			dssReference.setDigestMethodAlgorithm(wsDssReference.getDigestMethodAlgorithm());
			final DSSDocument contentsDssDocument = DSSWSUtils.createDssDocument(wsDssReference.getContents());
			dssReference.setContents(contentsDssDocument);
			dssReference.setTransforms(wsDssReference.getTransforms());
			dssReferences.add(dssReference);
		}
		params.setReferences(dssReferences);
	}

	private void setAsicZipComment(final WSParameters wsParameters, final ASiCSignatureParameters params) {
		params.aSiC().setZipComment(wsParameters.getAsicZipComment());
	}

	private void setAsicMimeType(final WSParameters wsParameters, final ASiCSignatureParameters params) {
		params.aSiC().setMimeType(wsParameters.getAsicMimeType());
	}

	private void setAsicSignatureForm(final WSParameters wsParameters, final ASiCSignatureParameters params) {
		params.aSiC().setUnderlyingForm(wsParameters.getAsicSignatureForm());
	}

	private void setAsicEnclosedSignature(final WSParameters wsParameters, final ASiCSignatureParameters params) {
		final DSSDocument dssDocument = DSSWSUtils.createDssDocument(wsParameters.getAsicEnclosedSignature());
		params.aSiC().setEnclosedSignature(dssDocument);
	}

	@Override
	public byte[] getDataToSign(final WSDocument wsDocument, final WSParameters wsParameters) throws DSSException {
		String exceptionMessage;
		try {
			if (LOG.isInfoEnabled()) {
				LOG.info("WsGetDataToSign: begin");
			}
			final AbstractSignatureParameters params = createParameters(wsParameters);
			final DSSDocument dssDocument = DSSWSUtils.createDssDocument(wsDocument);

			final DocumentSignatureService service = getServiceForSignatureLevel(params.getSignatureLevel());
			ToBeSigned dataToSign = service.getDataToSign(dssDocument, params);
			if (LOG.isInfoEnabled()) {
				LOG.info("WsGetDataToSign: end");
			}
			return dataToSign.getBytes();
		} catch (Throwable e) {
			exceptionMessage = e.getMessage();
			LOG.error("WsGetDataToSign: ended with exception", e);
			throw new DSSException(exceptionMessage);
		}
	}

	@Override
	public WSDocument signDocument(final WSDocument wsDocument, final WSParameters wsParameters, final byte[] signatureValue) throws DSSException {
		String exceptionMessage;
		try {
			if (LOG.isInfoEnabled()) {
				LOG.info("WsSignDocument: begin");
			}
			final AbstractSignatureParameters params = createParameters(wsParameters);
			final DSSDocument dssDocument = DSSWSUtils.createDssDocument(wsDocument);
			final DocumentSignatureService service = getServiceForSignatureLevel(params.getSignatureLevel());

			SignatureValue value = new SignatureValue();
			value.setValue(signatureValue);
			final DSSDocument signatureDssDocument = service.signDocument(dssDocument, params, value);

			WSDocument SignatureWsDocument = new WSDocument(signatureDssDocument);
			if (LOG.isInfoEnabled()) {
				LOG.info("WsSignDocument: end");
			}
			return SignatureWsDocument;
		} catch (Throwable e) {
			exceptionMessage = e.getMessage();
			LOG.error("WsSignDocument: ended with exception", e);
			throw new DSSException(exceptionMessage);
		}
	}

	@Override
	public WSDocument extendSignature(final WSDocument wsDocument, final WSParameters wsParameters) throws DSSException {
		String exceptionMessage;
		try {
			if (LOG.isInfoEnabled()) {
				LOG.info("WsExtendSignature: begin");
			}
			final AbstractSignatureParameters params = createParameters(wsParameters);
			final DSSDocument dssDocument = DSSWSUtils.createDssDocument(wsDocument);
			final DocumentSignatureService service = getServiceForSignatureLevel(params.getSignatureLevel());
			final DSSDocument signatureDssDocument = service.extendDocument(dssDocument, params);
			final WSDocument signatureWsDocument = new WSDocument(signatureDssDocument);
			if (LOG.isInfoEnabled()) {
				LOG.info("WsExtendSignature: end");
			}
			return signatureWsDocument;
		} catch (Throwable e) {
			exceptionMessage = e.getMessage();
			LOG.error("WsExtendSignature: end with exception", e);
			throw new DSSException(exceptionMessage);
		}
	}
}