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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteConverter;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

@SuppressWarnings("serial")
public class RemoteMultipleDocumentsSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteMultipleDocumentsSignatureService<RemoteDocument, RemoteSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteMultipleDocumentsSignatureServiceImpl.class);

	private MultipleDocumentsSignatureService<XAdESSignatureParameters> xadesService;

	private MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters> asicWithCAdESService;

	private MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters> asicWithXAdESService;

	public void setXadesService(MultipleDocumentsSignatureService<XAdESSignatureParameters> xadesService) {
		this.xadesService = xadesService;
	}

	public void setAsicWithCAdESService(MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters> asicWithCAdESService) {
		this.asicWithCAdESService = asicWithCAdESService;
	}

	public void setAsicWithXAdESService(MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters> asicWithXAdESService) {
		this.asicWithXAdESService = asicWithXAdESService;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public ToBeSigned getDataToSign(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters) {
		LOG.info("GetDataToSign in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		List<DSSDocument> dssDocuments = RemoteConverter.toDSSDocuments(toSignDocuments);
		ToBeSigned dataToSign = service.getDataToSign(dssDocuments, parameters);
		LOG.info("GetDataToSign is finished");
		return dataToSign;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public RemoteDocument signDocument(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters, SignatureValue signatureValue) {
		LOG.info("SignDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		List<DSSDocument> dssDocuments = RemoteConverter.toDSSDocuments(toSignDocuments);
		DSSDocument signDocument = (DSSDocument) service.signDocument(dssDocuments, parameters, signatureValue);
		LOG.info("SignDocument is finished");
		return RemoteConverter.toRemoteDocument(signDocument);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public RemoteDocument extendDocument(RemoteDocument toExtendDocument, RemoteSignatureParameters remoteParameters) {
		LOG.info("ExtendDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = RemoteConverter.toDSSDocument(toExtendDocument);
		DSSDocument extendDocument = (DSSDocument) service.extendDocument(dssDocument, parameters);
		LOG.info("ExtendDocument is finished");
		return RemoteConverter.toRemoteDocument(extendDocument);
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
