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
package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.DataToValidateDTO;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

@SuppressWarnings("serial")
public class SoapDocumentValidationServiceImpl implements SoapDocumentValidationService {

	private RemoteDocumentValidationService validationService;

	public void setValidationService(RemoteDocumentValidationService validationService) {
		this.validationService = validationService;
	}

	@Override
	public WSReportsDTO validateSignature(DataToValidateDTO dataToValidate) {
		ReportsDTO reportsDTO = validationService.validateDocument(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocuments(),
				dataToValidate.getPolicy());
		return new WSReportsDTO(reportsDTO.getDiagnosticData(), reportsDTO.getSimpleReport(), reportsDTO.getDetailedReport(), 
				reportsDTO.getEtsiValidationReport());
	}

	@Override
	public List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate) {
		return validationService.getOriginalDocuments(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocuments(),
				dataToValidate.getSignatureId());
	}

}
