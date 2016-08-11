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
package eu.europa.esig.dss.signature;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.RemoteCertificate;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

@SuppressWarnings("serial")
public class RemoteDocumentSignatureServiceImpl implements RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> {

	private static final Logger logger = LoggerFactory.getLogger(RemoteDocumentSignatureServiceImpl.class);

	private DocumentSignatureService<XAdESSignatureParameters> xadesService;

	private DocumentSignatureService<CAdESSignatureParameters> cadesService;

	private DocumentSignatureService<PAdESSignatureParameters> padesService;

	private DocumentSignatureService<ASiCSignatureParameters> asicService;

	public void setXadesService(DocumentSignatureService<XAdESSignatureParameters> xadesService) {
		this.xadesService = xadesService;
	}

	public void setCadesService(DocumentSignatureService<CAdESSignatureParameters> cadesService) {
		this.cadesService = cadesService;
	}

	public void setPadesService(DocumentSignatureService<PAdESSignatureParameters> padesService) {
		this.padesService = padesService;
	}

	public void setAsicService(DocumentSignatureService<ASiCSignatureParameters> asicService) {
		this.asicService = asicService;
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getServiceForSignatureLevel(RemoteSignatureParameters parameters) {
		SignatureLevel signatureLevel = parameters.getSignatureLevel();
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
			throw new DSSException("Unrecognized format " + signatureLevel);
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public ToBeSigned getDataToSign(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) throws DSSException {
		logger.info("GetDataToSign in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignatureLevel(remoteParameters);
		DSSDocument dssDocument = createDSSDocument(remoteDocument);
		ToBeSigned dataToSign = service.getDataToSign(dssDocument, parameters);
		logger.info("GetDataToSign is finished");
		return dataToSign;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public DSSDocument signDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, SignatureValue signatureValue)
			throws DSSException {
		logger.info("SignDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignatureLevel(remoteParameters);
		DSSDocument dssDocument = createDSSDocument(remoteDocument);
		DSSDocument signDocument = service.signDocument(dssDocument, parameters, signatureValue);
		logger.info("SignDocument is finished");
		return signDocument;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public DSSDocument extendDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) throws DSSException {
		logger.info("ExtendDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignatureLevel(remoteParameters);
		DSSDocument dssDocument = createDSSDocument(remoteDocument);
		DSSDocument extendDocument = service.extendDocument(dssDocument, parameters);
		logger.info("ExtendDocument is finished");
		return extendDocument;
	}

	private AbstractSignatureParameters createParameters(RemoteSignatureParameters remoteParameters) {
		AbstractSignatureParameters parameters = null;

		SignatureForm signatureForm = remoteParameters.getSignatureLevel().getSignatureForm();
		switch (signatureForm) {
		case CAdES:
			parameters = new CAdESSignatureParameters();
			break;
		case PAdES:
			PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
			padesParams.setSignatureSize(9472 * 2); // double reserved space for signature
			parameters = padesParams;
			break;
		case XAdES:
			parameters = new XAdESSignatureParameters();
			break;
		case ASiC_E:
		case ASiC_S:
			ASiCSignatureParameters aSiCParameters = new ASiCSignatureParameters();
			aSiCParameters.aSiC().setUnderlyingForm(remoteParameters.getUnderlyingASiCForm());
			parameters = aSiCParameters;
			break;
		default:
			throw new DSSException("Unsupported signature form : " + signatureForm);
		}

		fillParameters(parameters, remoteParameters);

		return parameters;
	}

	private void fillParameters(AbstractSignatureParameters parameters, RemoteSignatureParameters remoteParameters) {
		parameters.setBLevelParams(remoteParameters.bLevel());
		parameters.setDetachedContent(createDSSDocument(remoteParameters.getDetachedContent()));
		parameters.setDigestAlgorithm(remoteParameters.getDigestAlgorithm());
		parameters.setEncryptionAlgorithm(remoteParameters.getEncryptionAlgorithm());
		parameters.setSignatureLevel(remoteParameters.getSignatureLevel());
		parameters.setSignaturePackaging(remoteParameters.getSignaturePackaging());
		parameters.setSignatureTimestampParameters(remoteParameters.getSignatureTimestampParameters());
		parameters.setArchiveTimestampParameters(remoteParameters.getArchiveTimestampParameters());
		parameters.setContentTimestampParameters(remoteParameters.getContentTimestampParameters());
		parameters.setSignWithExpiredCertificate(remoteParameters.isSignWithExpiredCertificate());

		RemoteCertificate signingCertificate = remoteParameters.getSigningCertificate();
		if (signingCertificate != null) { // extends do not require signing certificate
			CertificateToken loadCertificate = DSSUtils.loadCertificate(signingCertificate.getEncodedCertificate());
			parameters.setSigningCertificate(loadCertificate);
		}

		List<RemoteCertificate> remoteCertificateChain = remoteParameters.getCertificateChain();
		if (Utils.isCollectionNotEmpty(remoteCertificateChain)) {
			Set<CertificateToken> certificateChain = new HashSet<CertificateToken>();
			for (RemoteCertificate remoteCertificate : remoteCertificateChain) {
				certificateChain.add(DSSUtils.loadCertificate(remoteCertificate.getEncodedCertificate()));
			}
			parameters.setCertificateChain(certificateChain);
		}
	}

	private DSSDocument createDSSDocument(RemoteDocument remoteDocument) {
		if (remoteDocument != null) {
			InMemoryDocument dssDocument = new InMemoryDocument(remoteDocument.getBytes());
			dssDocument.setMimeType(remoteDocument.getMimeType());
			dssDocument.setAbsolutePath(remoteDocument.getAbsolutePath());
			dssDocument.setName(remoteDocument.getName());
			return dssDocument;
		}
		return null;
	}

}
