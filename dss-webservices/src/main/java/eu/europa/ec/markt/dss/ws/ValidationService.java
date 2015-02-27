/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.ws;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import org.apache.cxf.annotations.WSDLDocumentation;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.ws.report.WSValidationReport;

/**
 * Interface for the Contract of the Validation Web Service.
 *
 * @version $Revision$ - $Date$
 */

@WebService
@WSDLDocumentation("The validation web service allows to validate any kind of signature form. The validation process is based on ETSI TS 102853 and is driven by the validation " +
      "policy containing a set of rules. As result three states can be returned: VALID, INDETERMINATE OR INVALID. These states are accompanied by sub-indications and some other " +
      "information. The result is represented through three reports: simple validation report with the final result, detailed validation report with the result of each rule and " +
      "the diagnostic data.")
public interface ValidationService {

    /**
     * This web service operation validates a document and returns a detailed validation report.
     *
     * @param document        the document that shall be validated
     * @param detachedContent The original document before signing (used to verify detached signature)
     * @param policy          validation policy rules
     * @return the validation report
     * @throws DSSException
     */
    @WebResult(name = "response")
    @WSDLDocumentation("This method validates the document containing the signature(s). It takes four parameters: document with signature(s), " +
          "the signed document in case of detached signature (can be null), the document containing the specific validation policy (default policy is used when null) and a flag " +
          "to say if diagnostic data must be returned by the method.")
    WSValidationReport validateDocument(@WebParam(name = "document") final WSDocument document, @WebParam(name = "detachedContent") WSDocument detachedContent,
                                        @WebParam(name = "policy") final WSDocument policy, @WebParam(name = "diagnosticDataToBeReturned")

    boolean diagnosticDataToBeReturned) throws DSSException;
}