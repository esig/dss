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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

@SuppressWarnings("serial")
public class RemoteMultipleDocumentsSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteMultipleDocumentsSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteMultipleDocumentsSignatureServiceImpl.class);

	private MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> xadesService;

	private MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> asicWithCAdESService;

	private MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> asicWithXAdESService;

	public void setXadesService(MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> xadesService) {
		this.xadesService = xadesService;
	}

	public void setAsicWithCAdESService(MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> asicWithCAdESService) {
		this.asicWithCAdESService = asicWithCAdESService;
	}

	public void setAsicWithXAdESService(MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> asicWithXAdESService) {
		this.asicWithXAdESService = asicWithXAdESService;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public ToBeSignedDTO getDataToSign(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters) {
		LOG.info("GetDataToSign in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		List<DSSDocument> dssDocuments = RemoteDocumentConverter.toDSSDocuments(toSignDocuments);
		ToBeSigned dataToSign = service.getDataToSign(dssDocuments, parameters);
		LOG.info("GetDataToSign is finished");
		return DTOConverter.toToBeSignedDTO(dataToSign);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public RemoteDocument signDocument(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO) {
		LOG.info("SignDocument in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		List<DSSDocument> dssDocuments = RemoteDocumentConverter.toDSSDocuments(toSignDocuments);
		DSSDocument signDocument = (DSSDocument) service.signDocument(dssDocuments, parameters, toSignatureValue(signatureValueDTO));
		LOG.info("SignDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(signDocument);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public RemoteDocument extendDocument(RemoteDocument toExtendDocument, RemoteSignatureParameters remoteParameters) {
		LOG.info("ExtendDocument in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(toExtendDocument);
		DSSDocument extendDocument = (DSSDocument) service.extendDocument(dssDocument, parameters);
		LOG.info("ExtendDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(extendDocument);
	}

	@SuppressWarnings("rawtypes")
	private MultipleDocumentsSignatureService getServiceForSignature(RemoteSignatureParameters parameters) {
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
			if (SignatureForm.XAdES == signatureForm) {
				return xadesService;
			} else {
				throw new DSSException("Unrecognized format (XAdES or CAdES are allowed with ASiC or XAdES) : " + signatureForm);
			}
		}
	}

}
