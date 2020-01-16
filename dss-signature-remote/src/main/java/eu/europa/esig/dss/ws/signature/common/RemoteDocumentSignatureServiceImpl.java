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

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

@SuppressWarnings("serial")
public class RemoteDocumentSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteDocumentSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteDocumentSignatureServiceImpl.class);

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> xadesService;

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> cadesService;

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> padesService;

	private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> asicWithXAdESService;

	private DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> asicWithCAdESService;

	public void setXadesService(DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> xadesService) {
		this.xadesService = xadesService;
	}

	public void setCadesService(DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> cadesService) {
		this.cadesService = cadesService;
	}

	public void setPadesService(DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> padesService) {
		this.padesService = padesService;
	}

	public void setAsicWithXAdESService(DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> asicWithXAdESService) {
		this.asicWithXAdESService = asicWithXAdESService;
	}

	public void setAsicWithCAdESService(DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> asicWithCAdESService) {
		this.asicWithCAdESService = asicWithCAdESService;
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getServiceForSignature(SignatureForm signatureForm, ASiCContainerType asicContainerType) {
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
					throw new DSSException("Unrecognized format " + signatureForm);
				}
		}
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getServiceForTimestamp(TimestampContainerForm timestampContainerForm) {
		if (timestampContainerForm != null) {
			switch(timestampContainerForm) {
				case PDF:
					return padesService;
				case ASiC_E:
				case ASiC_S:
					return asicWithCAdESService;
				default:
					throw new DSSException("Unrecognized format (only PDF, ASiC-E and ASiC-S are allowed) : " + timestampContainerForm);
			}
		} else {
			throw new DSSException("The timestampContainerForm must be defined!");
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public ToBeSignedDTO getDataToSign(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
		Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
		LOG.info("GetDataToSign in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters.getSignatureLevel().getSignatureForm(), remoteParameters.getAsicContainerType());
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		ToBeSigned dataToSign = service.getDataToSign(dssDocument, parameters);
		LOG.info("GetDataToSign is finished");
		return DTOConverter.toToBeSignedDTO(dataToSign);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument signDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO) {
		Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
		LOG.info("SignDocument in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters.getSignatureLevel().getSignatureForm(), remoteParameters.getAsicContainerType());
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		DSSDocument signDocument = service.signDocument(dssDocument, parameters, toSignatureValue(signatureValueDTO));
		LOG.info("SignDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(signDocument);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument extendDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
		Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
		LOG.info("ExtendDocument in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		DocumentSignatureService service = getServiceForSignature(remoteParameters.getSignatureLevel().getSignatureForm(), remoteParameters.getAsicContainerType());
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		DSSDocument extendDocument = service.extendDocument(dssDocument, parameters);
		LOG.info("ExtendDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(extendDocument);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument timestamp(RemoteDocument remoteDocument, RemoteTimestampParameters remoteParameters) {
		Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getTimestampContainerForm(), "signatureForm must be defined!");
		LOG.info("Timestamp document in process...");
		TimestampParameters parameters = toTimestampParameters(remoteParameters);
		DocumentSignatureService service = getServiceForTimestamp(remoteParameters.getTimestampContainerForm());
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		DSSDocument timestampedDocument = service.timestamp(dssDocument, parameters);
		LOG.info("Timestamp document is finished");
		return RemoteDocumentConverter.toRemoteDocument(timestampedDocument);
	}

}
