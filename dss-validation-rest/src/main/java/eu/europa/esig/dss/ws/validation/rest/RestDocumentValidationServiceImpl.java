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
package eu.europa.esig.dss.ws.validation.rest;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.ws.validation.rest.client.RestDocumentValidationService;

import java.util.List;

/**
 * REST implementation of the validation service
 */
@SuppressWarnings("serial")
public class RestDocumentValidationServiceImpl implements RestDocumentValidationService {

	/** The validation service to use */
	private RemoteDocumentValidationService validationService;

	/**
	 * Default construction instantiating object with null RemoteDocumentValidationService
	 */
	public RestDocumentValidationServiceImpl() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param validationService {@link RemoteDocumentValidationService}
	 */
	public void setValidationService(RemoteDocumentValidationService validationService) {
		this.validationService = validationService;
	}
	
	@Override
	public WSReportsDTO validateSignature(DataToValidateDTO dataToValidate) {
		return validationService.validateDocument(dataToValidate);
	}

	@Override
	public List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate) {
		return validationService.getOriginalDocuments(dataToValidate);
	}

}
