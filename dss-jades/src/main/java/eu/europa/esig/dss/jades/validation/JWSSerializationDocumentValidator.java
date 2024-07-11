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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSDocument;

//@formatter:off
/**
 * This class performs validation of a JWS Serialization or Flattened signature format.
 *
 * {
 *
 * "payload":"payload contents",
 *
 * "signatures":[
 *
 * {"protected":"integrity-protected header 1 contents",
 * "header":non-integrity-protected header 1 contents, 
 * "signature":"signature 1 contents"},
 *
 * ...
 *
 * {"protected":"integrity-protected header N contents",
 * "header":non-integrity-protected header N contents, 
 * "signature":"signature N contents"}
 *
 * ]
 *
 * }
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
//@formatter:on
public class JWSSerializationDocumentValidator extends AbstractJWSDocumentValidator {

    /**
     * Empty constructor
     */
    public JWSSerializationDocumentValidator() {
        super(new JWSSerializationAnalyzerValidator());
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to validate
     */
    public JWSSerializationDocumentValidator(DSSDocument document) {
        super(new JWSSerializationAnalyzerValidator(document));
    }

    @Override
    public JWSSerializationAnalyzerValidator getDocumentAnalyzer() {
        return (JWSSerializationAnalyzerValidator) super.getDocumentAnalyzer();
    }

}