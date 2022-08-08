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

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * The remote signature service implementation
 */
@SuppressWarnings("serial")
public class RemoteDocumentSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteDocumentSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteDocumentSignatureServiceImpl.class);

	/** XAdES signature service */
	private XAdESService xadesService;

	/** CAdES signature service */
	private CAdESService cadesService;

	/** PAdES signature service */
	private PAdESService padesService;

	/** JAdES signature service */
	private JAdESService jadesService;

	/** ASiC with XAdES signature service */
	private ASiCWithXAdESService asicWithXAdESService;

	/** ASiC with CAdES signature service */
	private ASiCWithCAdESService asicWithCAdESService;

	/**
	 * Default constructor instantiating object with null services
	 */
	public RemoteDocumentSignatureServiceImpl() {
	}

	/**
	 * Sets the XAdES signature service
	 *
	 * @param xadesService {@link XAdESService}
	 */
	public void setXadesService(XAdESService xadesService) {
		this.xadesService = xadesService;
	}

	/**
	 * Sets the CAdES signature service
	 *
	 * @param cadesService {@link CAdESService}
	 */
	public void setCadesService(CAdESService cadesService) {
		this.cadesService = cadesService;
	}

	/**
	 * Sets the PAdES signature service
	 *
	 * @param padesService {@link PAdESService}
	 */
	public void setPadesService(PAdESService padesService) {
		this.padesService = padesService;
	}

	/**
	 * Sets the JAdES signature service
	 *
	 * @param jadesService {@link JAdESService}
	 */
	public void setJadesService(JAdESService jadesService) {
		this.jadesService = jadesService;
	}

	/**
	 * Sets the ASiC with XAdES signature service
	 *
	 * @param asicWithXAdESService {@link ASiCWithXAdESService}
	 */
	public void setAsicWithXAdESService(ASiCWithXAdESService asicWithXAdESService) {
		this.asicWithXAdESService = asicWithXAdESService;
	}

	/**
	 * Sets the ASiC with CAdES signature service
	 *
	 * @param asicWithCAdESService {@link ASiCWithCAdESService}
	 */
	public void setAsicWithCAdESService(ASiCWithCAdESService asicWithCAdESService) {
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
					throw new UnsupportedOperationException("Unrecognized format (XAdES or CAdES are allowed with ASiC) : " + signatureForm);
				}
		} else {
			switch (signatureForm) {
				case XAdES:
					return xadesService;
				case CAdES:
					return cadesService;
				case PAdES:
					return padesService;
				case JAdES:
					return jadesService;
				default:
					throw new UnsupportedOperationException("Unrecognized format " + signatureForm);
				}
		}
	}

	@SuppressWarnings("rawtypes")
	private CounterSignatureService getServiceForCounterSignature(SignatureForm signatureForm, ASiCContainerType asicContainerType) {
		if (asicContainerType != null) {
			switch (signatureForm) {
				case XAdES:
					return asicWithXAdESService;
				case CAdES:
					return asicWithCAdESService;
				default:
					throw new UnsupportedOperationException("Unrecognized format (XAdES or CAdES are allowed with ASiC) : " + signatureForm);
				}
		} else {
			switch (signatureForm) {
				case XAdES:
					return xadesService;
				case CAdES:
					return cadesService;
				case PAdES:
					throw new UnsupportedOperationException(String.format("The Counter Signature is not supported with %s", signatureForm));
				case JAdES:
					return jadesService;
				default:
					throw new UnsupportedOperationException("Unrecognized format " + signatureForm);
			}
		}
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getServiceForTimestamp(TimestampContainerForm timestampContainerForm) {
		Objects.requireNonNull(timestampContainerForm, "The timestampContainerForm must be defined!");
		switch(timestampContainerForm) {
			case PDF:
				return padesService;
			case ASiC_E:
			case ASiC_S:
				return asicWithCAdESService;
			default:
				throw new UnsupportedOperationException("Unrecognized format (only PDF, ASiC-E and ASiC-S are allowed) : " + timestampContainerForm);
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

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public ToBeSignedDTO getDataToBeCounterSigned(RemoteDocument signatureDocument,
			RemoteSignatureParameters remoteParameters) {
		Objects.requireNonNull(signatureDocument, "signatureDocument must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
		LOG.info("GetDataToCounterSign in process...");
		SerializableCounterSignatureParameters counterSignatureParameters = createCounterSignatureParameters(remoteParameters);
		CounterSignatureService counterSignatureService = getServiceForCounterSignature(
				remoteParameters.getSignatureLevel().getSignatureForm(), remoteParameters.getAsicContainerType());
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(signatureDocument);
		ToBeSigned dataToSign = counterSignatureService.getDataToBeCounterSigned(dssDocument, counterSignatureParameters);
		LOG.info("GetDataToCounterSign is finished");
		return DTOConverter.toToBeSignedDTO(dataToSign);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public RemoteDocument counterSignSignature(RemoteDocument signatureDocument, RemoteSignatureParameters remoteParameters,
			SignatureValueDTO signatureValueDTO) {
		Objects.requireNonNull(signatureDocument, "signatureDocument must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
		LOG.info("CounterSignDocument in process...");
		SerializableCounterSignatureParameters parameters = createCounterSignatureParameters(remoteParameters);
		CounterSignatureService counterSignatureService = getServiceForCounterSignature(
				remoteParameters.getSignatureLevel().getSignatureForm(), remoteParameters.getAsicContainerType());
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(signatureDocument);
		DSSDocument signDocument = counterSignatureService.counterSignSignature(dssDocument, parameters,
				toSignatureValue(signatureValueDTO));
		LOG.info("CounterSignDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(signDocument);
	}

}
