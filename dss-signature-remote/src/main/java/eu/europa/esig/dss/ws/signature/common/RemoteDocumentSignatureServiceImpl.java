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
package eu.europa.esig.dss.ws.signature.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

@SuppressWarnings("serial")
public class RemoteDocumentSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteDocumentSignatureService {

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
	public ToBeSignedDTO getDataToSign(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
		LOG.info("GetDataToSign in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		ToBeSigned dataToSign = service.getDataToSign(dssDocument, parameters);
		LOG.info("GetDataToSign is finished");
		return DTOConverter.toToBeSignedDTO(dataToSign);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument signDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO) {
		LOG.info("SignDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		DSSDocument signDocument = (DSSDocument) service.signDocument(dssDocument, parameters, toSignatureValue(signatureValueDTO));
		LOG.info("SignDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(signDocument);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument extendDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
		LOG.info("ExtendDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		DSSDocument extendDocument = (DSSDocument) service.extendDocument(dssDocument, parameters);
		LOG.info("ExtendDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(extendDocument);
	}

}
