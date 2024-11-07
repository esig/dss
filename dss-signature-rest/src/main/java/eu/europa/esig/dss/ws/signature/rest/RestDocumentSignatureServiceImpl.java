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
package eu.europa.esig.dss.ws.signature.rest;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureService;
import eu.europa.esig.dss.ws.signature.dto.CounterSignSignatureDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToBeCounterSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.TimestampOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.rest.client.RestDocumentSignatureService;

/**
 * REST implementation of the remote signature service
 *
 */
@SuppressWarnings("serial")
public class RestDocumentSignatureServiceImpl implements RestDocumentSignatureService {

	/** The service to use */
	private RemoteDocumentSignatureService service;

	/**
	 * Default construction instantiating object with null RemoteDocumentSignatureService
	 */
	public RestDocumentSignatureServiceImpl() {
		// empty
	}

	/**
	 * Sets the remote signature service
	 *
	 * @param service {@link RemoteDocumentSignatureService}
	 */
	public void setService(RemoteDocumentSignatureService service) {
		this.service = service;
	}

	@Override
	public ToBeSignedDTO getDataToSign(DataToSignOneDocumentDTO dataToSignDto) {
		return service.getDataToSign(dataToSignDto.getToSignDocument(), dataToSignDto.getParameters());
	}

	@Override
	public RemoteDocument signDocument(SignOneDocumentDTO signDocumentDto) {
		return service.signDocument(signDocumentDto.getToSignDocument(), signDocumentDto.getParameters(), signDocumentDto.getSignatureValue());
	}

	@Override
	public RemoteDocument extendDocument(ExtendDocumentDTO extendDocumentDto) {
		return service.extendDocument(extendDocumentDto.getToExtendDocument(), extendDocumentDto.getParameters());
	}

	@Override
	public RemoteDocument timestampDocument(TimestampOneDocumentDTO timestampDocument) {
		return service.timestamp(timestampDocument.getToTimestampDocument(), timestampDocument.getTimestampParameters());
	}

	@Override
	public ToBeSignedDTO getDataToBeCounterSigned(DataToBeCounterSignedDTO dataToBeCounterSigned) {
		return service.getDataToBeCounterSigned(dataToBeCounterSigned.getSignatureDocument(), dataToBeCounterSigned.getParameters());
	}

	@Override
	public RemoteDocument counterSignSignature(CounterSignSignatureDTO counterSignSignature) {
		return service.counterSignSignature(counterSignSignature.getSignatureDocument(),
				counterSignSignature.getParameters(), counterSignSignature.getSignatureValue());
	}

}
