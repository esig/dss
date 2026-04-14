/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;
import eu.europa.esig.dss.extension.SignedDocumentExtender;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
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

import java.util.List;
import java.util.Objects;

/**
 * WebService for multiple document signing
 *
 */
@SuppressWarnings("serial")
public class RemoteMultipleDocumentsSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteMultipleDocumentsSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteMultipleDocumentsSignatureServiceImpl.class);

	/** XAdES multiple signature service */
	private XAdESService xadesService;

	/** JAdES multiple signature service */
	private JAdESService jadesService;

	/** ASiC with XAdES multiple signature service */
	private ASiCWithXAdESService asicWithXAdESService;

	/** ASiC with CAdES multiple signature service */
	private ASiCWithCAdESService asicWithCAdESService;

	/**
	 * Default constructor instantiating object with null services
	 */
	public RemoteMultipleDocumentsSignatureServiceImpl() {
		// empty
	}

	/**
	 * Sets the XAdES multiple signature service
	 *
	 * @param xadesService {@link XAdESService}
	 */
	public void setXadesService(XAdESService xadesService) {
		this.xadesService = xadesService;
	}

	/**
	 * Sets the JAdES multiple signature service
	 *
	 * @param jadesService {@link JAdESService}
	 */
	public void setJadesService(JAdESService jadesService) {
		this.jadesService = jadesService;
	}

	/**
	 * Sets the ASiC with XAdES multiple signature service
	 *
	 * @param asicWithXAdESService {@link ASiCWithXAdESService}
	 */
	public void setAsicWithXAdESService(ASiCWithXAdESService asicWithXAdESService) {
		this.asicWithXAdESService = asicWithXAdESService;
	}

	/**
	 * Sets the ASiC with CAdES multiple signature service
	 *
	 * @param asicWithCAdESService {@link ASiCWithCAdESService}
	 */
	public void setAsicWithCAdESService(ASiCWithCAdESService asicWithCAdESService) {
		this.asicWithCAdESService = asicWithCAdESService;
	}

	@SuppressWarnings("rawtypes")
	private MultipleDocumentsSignatureService getServiceForSignature(SignatureForm signatureForm, ASiCContainerType asicContainerType) {
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
				case JAdES:
					return jadesService;
				default:
					throw new UnsupportedOperationException("Unrecognized format " +
							"(only XAdES and JAdES are allowed for multiple documents signing) : " + signatureForm);
			}
		}
	}

	@SuppressWarnings("rawtypes")
	private MultipleDocumentsSignatureService getServiceForTimestamp(TimestampContainerForm timestampContainerForm) {
		Objects.requireNonNull(timestampContainerForm, "The timestampContainerForm must be defined!");
		switch(timestampContainerForm) {
			case ASiC_E:
			case ASiC_S:
				return asicWithCAdESService;
			default:
				throw new UnsupportedOperationException(String.format("The format '%s' is not recognized or not allowed "
						+ "(only ASiC-E and ASiC-S are allowed for a multiple document timestamping)!",
						timestampContainerForm.getReadable()));
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public ToBeSignedDTO getDataToSign(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters) {
		Objects.requireNonNull(toSignDocuments, "toSignDocuments must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
		LOG.info("GetDataToSign in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters.getSignatureLevel().getSignatureForm(), remoteParameters.getAsicContainerType());
		List<DSSDocument> dssDocuments = RemoteDocumentConverter.toDSSDocuments(toSignDocuments);
		ToBeSigned dataToSign = service.getDataToSign(dssDocuments, parameters);
		LOG.info("GetDataToSign is finished");
		return DTOConverter.toToBeSignedDTO(dataToSign);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public RemoteDocument signDocument(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO) {
		Objects.requireNonNull(toSignDocuments, "toSignDocuments must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
		LOG.info("SignDocument in process...");
		SerializableSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters.getSignatureLevel().getSignatureForm(), remoteParameters.getAsicContainerType());
		List<DSSDocument> dssDocuments = RemoteDocumentConverter.toDSSDocuments(toSignDocuments);
		DSSDocument signDocument = service.signDocument(dssDocuments, parameters, toSignatureValue(signatureValueDTO));
		LOG.info("SignDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(signDocument);
	}

	@Override
	@Deprecated
	public RemoteDocument extendDocument(RemoteDocument toExtendDocument, RemoteSignatureParameters remoteParameters) {
		return extendDocument(toExtendDocument, null, remoteParameters);
	}

	@Override
	public RemoteDocument extendDocument(RemoteDocument remoteDocument, SignatureProfile signatureProfile, RemoteSignatureParameters remoteParameters) throws DSSException {
		Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
		if (signatureProfile == null && (remoteParameters == null || remoteParameters.getSignatureLevel() == null)) {
			throw new NullPointerException("One of the signatureProfile or remoteParameters.signatureLevel must be defined!");
		}
		LOG.info("ExtendDocument in process...");

		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		SignedDocumentExtender documentExtender = SignedDocumentExtender.fromDocument(dssDocument);
		documentExtender.setServices(xadesService, jadesService, asicWithXAdESService, asicWithCAdESService);

		SignatureForm signatureForm = documentExtender.getSignatureForm();
		SerializableSignatureParameters signatureParameters;
		if (remoteParameters == null) {
			signatureParameters = null;
		} else if (documentExtender.isASiC()) {
			signatureParameters = getASiCSignatureParameters(null, signatureForm);
		} else {
			signatureParameters = getSignatureParameters(signatureForm, remoteParameters);
		}
		fillParameters(signatureParameters, remoteParameters, signatureForm);

		if (signatureProfile == null) {
			signatureProfile = remoteParameters.getSignatureLevel().getSignatureProfile();
			LOG.info("Target signature profile has been derived from the RemoteSignatureParameters : {}. " +
					"SignatureProfile is to be required in future versions.", signatureProfile);
		} else if (remoteParameters != null && remoteParameters.getSignatureLevel() != null) {
			LOG.warn("Both SignatureProfile and RemoteSignatureParameters.SignatureLevel are defined. The SignatureProfile will be used : {}", signatureProfile);
		}

		DSSDocument extendDocument = documentExtender.extendDocument(signatureProfile, signatureParameters);
		LOG.info("ExtendDocument is finished");
		return RemoteDocumentConverter.toRemoteDocument(extendDocument);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public RemoteDocument timestamp(List<RemoteDocument> toTimestampDocuments, RemoteTimestampParameters remoteParameters) {
		Objects.requireNonNull(toTimestampDocuments, "remoteDocument must be defined!");
		Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
		Objects.requireNonNull(remoteParameters.getTimestampContainerForm(), "timestampContainerForm must be defined!");
		LOG.info("Timestamp document in process...");
		TimestampParameters parameters = toTimestampParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForTimestamp(remoteParameters.getTimestampContainerForm());
		List<DSSDocument> dssDocuments = RemoteDocumentConverter.toDSSDocuments(toTimestampDocuments);
		DSSDocument timestampedDocument = service.timestamp(dssDocuments, parameters);
		LOG.info("Timestamp document is finished");
		return RemoteDocumentConverter.toRemoteDocument(timestampedDocument);
	}

}
