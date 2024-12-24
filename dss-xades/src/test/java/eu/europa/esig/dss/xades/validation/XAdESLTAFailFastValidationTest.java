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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLTAFailFastValidationTest extends XAdESLTATest {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);
        documentValidator.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);
        return documentValidator;
    }

    @Override
    public void validate() {
        Exception exception = assertThrows(AlertException.class, super::validate);
        assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));
    }

}
