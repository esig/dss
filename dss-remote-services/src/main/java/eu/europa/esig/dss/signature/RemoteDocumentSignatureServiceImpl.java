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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteConverter;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

@SuppressWarnings("serial")
public class RemoteDocumentSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteDocumentSignatureServiceImpl.class);

	private DocumentSignatureService<XAdESSignatureParameters> xadesService;

	private DocumentSignatureService<CAdESSignatureParameters> cadesService;

	private DocumentSignatureService<PAdESSignatureParameters> padesService;

	private DocumentSignatureService<ASiCWithXAdESSignatureParameters> asicWithXAdESService;

	private DocumentSignatureService<ASiCWithCAdESSignatureParameters> asicWithCAdESService;

	public void setXadesService(DocumentSignatureService<XAdESSignatureParameters> xadesService) {
		this.xadesService = xadesService;
	}

	public void setCadesService(DocumentSignatureService<CAdESSignatureParameters> cadesService) {
		this.cadesService = cadesService;
	}

	public void setPadesService(DocumentSignatureService<PAdESSignatureParameters> padesService) {
		this.padesService = padesService;
	}

	public void setAsicWithXAdESService(DocumentSignatureService<ASiCWithXAdESSignatureParameters> asicWithXAdESService) {
		this.asicWithXAdESService = asicWithXAdESService;
	}

	public void setAsicWithCAdESService(DocumentSignatureService<ASiCWithCAdESSignatureParameters> asicWithCAdESService) {
		this.asicWithCAdESService = asicWithCAdESService;
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getServiceForSignature(RemoteSignatureParameters parameters) {
		ASiCContainerType asicContainerType = parameters.getAsicContainerType();
		SignatureLevel signatureLevel = parameters.getSignatureLevel();
		SignatureForm signatureForm = signatureLevel.getSignatureForm();
		if (asicContainerType != null) {
			switch (signatureForm) {
			case XAdES:
				return asicWithXAdESService;
			case CAdES:
				return asicWithCAdESService;
			default:
				throw new DSSException("Unrecognized format (XAdES or CAdES are allowed with ASiC) : " + signatureForm);
			}
		} else {
			switch (signatureForm) {
			case XAdES:
				return xadesService;
			case CAdES:
				return cadesService;
			case PAdES:
				return padesService;
			default:
				throw new DSSException("Unrecognized format " + signatureLevel);
			}
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public ToBeSigned getDataToSign(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
		LOG.info("GetDataToSign in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteConverter.toDSSDocument(remoteDocument);
		ToBeSigned dataToSign = service.getDataToSign(dssDocument, parameters);
		LOG.info("GetDataToSign is finished");
		return dataToSign;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument signDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, SignatureValue signatureValue) {
		LOG.info("SignDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteConverter.toDSSDocument(remoteDocument);
		DSSDocument signDocument = (DSSDocument) service.signDocument(dssDocument, parameters, signatureValue);
		LOG.info("SignDocument is finished");
		return RemoteConverter.toRemoteDocument(signDocument);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument extendDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
		LOG.info("ExtendDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteConverter.toDSSDocument(remoteDocument);
		DSSDocument extendDocument = (DSSDocument) service.extendDocument(dssDocument, parameters);
		LOG.info("ExtendDocument is finished");
		return RemoteConverter.toRemoteDocument(extendDocument);
	}

}
