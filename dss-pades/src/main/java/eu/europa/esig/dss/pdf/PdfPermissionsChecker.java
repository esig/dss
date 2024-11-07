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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.alert.status.MessageStatus;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.alerts.ProtectedDocumentExceptionOnStatusAlert;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * This class is used to verify permissions of a PDF document and to check whether modifications are allowed
 *
 */
public class PdfPermissionsChecker {

    private static final Logger LOG = LoggerFactory.getLogger(PdfPermissionsChecker.class);

    /**
     * This variable indicates a behavior for creation of a new signature
     * in a document that does not permit a new signature creation
     *
     * Default : ProtectedDocumentExceptionOnStatusAlert -
     *                 throws the {@code eu.europa.esig.dss.pades.exception.ProtectedDocumentException} exception
     */
    private StatusAlert alertOnForbiddenSignatureCreation = new ProtectedDocumentExceptionOnStatusAlert();

    /**
     * Default constructor to instantiate the checker
     */
    public PdfPermissionsChecker() {
        // empty
    }

    /**
     * Sets a behavior to follow when creating a new signature in a document that forbids creation of new signatures
     *
     * Default : ExceptionOnStatusAlert - throw the exception
     *
     * @param alertOnForbiddenSignatureCreation {@link StatusAlert} to execute
     */
    public void setAlertOnForbiddenSignatureCreation(StatusAlert alertOnForbiddenSignatureCreation) {
        this.alertOnForbiddenSignatureCreation = alertOnForbiddenSignatureCreation;
    }

    /**
     * This method checks if the document has the necessary permissions for the signature operation
     *
     * @param documentReader {@link PdfDocumentReader}
     * @param fieldParameters {@link SignatureFieldParameters}
     */
    public void checkDocumentPermissions(PdfDocumentReader documentReader, SignatureFieldParameters fieldParameters) {
        if (!documentReader.isEncrypted() || documentReader.isOpenWithOwnerAccess()) {
            // permissions are applied only for encrypted documents with user-access
            return;
        }
        if (isSignatureFieldFillIn(fieldParameters)) {
            if (!documentReader.canFillSignatureForm()) {
                alertOnForbiddenSignatureCreation("PDF Permissions dictionary does not allow fill in interactive form fields, " +
                        "including existing signature fields when document is open with user-access!");
            }
        } else if (!documentReader.canCreateSignatureField()) {
            alertOnForbiddenSignatureCreation("PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
                    "including signature fields when document is open with user-access!");
        }
    }

    private boolean isSignatureFieldFillIn(SignatureFieldParameters fieldParameters) {
        return fieldParameters.getFieldId() != null;
    }

    /**
     * This method verifies whether a new signature is permitted
     *
     * @param documentReader {@link PdfDocumentReader}
     * @param fieldParameters {@link SignatureFieldParameters}
     */
    public void checkSignatureRestrictionDictionaries(PdfDocumentReader documentReader, SignatureFieldParameters fieldParameters) {
        final CertificationPermission certificationPermission = documentReader.getCertificationPermission();
        if (isDocumentChangeForbidden(certificationPermission)) {
            alertOnForbiddenSignatureCreation("DocMDP dictionary does not permit a new signature creation!");
        }
        if (documentReader.isUsageRightsSignaturePresent()) {
            /*
             * Deprecated. See ISO 32000-2:
             *
             * When a usage rights signature is present, it is up to the PDF processor or
             * to the signature handler to process it or not.
             */
            LOG.info("A usage rights signature is present. The feature is deprecated and the entry is not handled.");
        }

        try {
            String signatureFieldId = fieldParameters.getFieldId();

            Map<PdfSignatureDictionary, List<PdfSignatureField>> sigDictionaries = documentReader.extractSigDictionaries();
            for (PdfSignatureDictionary signatureDictionary : sigDictionaries.keySet()) {
                SigFieldPermissions fieldMDP = signatureDictionary.getFieldMDP();
                if (fieldMDP != null && isSignatureFieldCreationForbidden(fieldMDP, signatureFieldId)) {
                    alertOnForbiddenSignatureCreation("FieldMDP dictionary does not permit a new signature creation!");
                }
            }

            for (List<PdfSignatureField> signatureFieldList : sigDictionaries.values()) {
                for (PdfSignatureField signatureField : signatureFieldList) {
                    SigFieldPermissions lockDict = signatureField.getLockDictionary();
                    if (lockDict != null && lockDict.getCertificationPermission() != null &&
                            isSignatureFieldCreationForbidden(lockDict, signatureFieldId)) {
                        alertOnForbiddenSignatureCreation("Lock dictionary does not permit a new signature creation!");
                    }
                }
            }

        } catch (IOException e) {
            LOG.warn("An error occurred while reading signature dictionary entries : {}", e.getMessage(), e);
        }
    }

    private boolean isDocumentChangeForbidden(CertificationPermission certificationPermission) {
        return CertificationPermission.NO_CHANGE_PERMITTED.equals(certificationPermission);
    }

    private void alertOnForbiddenSignatureCreation(String message) {
        MessageStatus status = new MessageStatus();
        status.setMessage(String.format("The creation of new signatures is not permitted in the current document. Reason : %s", message));
        alertOnForbiddenSignatureCreation.alert(status);
    }

    private boolean isSignatureFieldCreationForbidden(SigFieldPermissions sigFieldPermissions, String signatureFieldId) {
        switch (sigFieldPermissions.getAction()) {
            case ALL:
                return true;
            case INCLUDE:
                if (Utils.isStringEmpty(signatureFieldId)) {
                    return false;
                }
                if (sigFieldPermissions.getFields().contains(signatureFieldId)) {
                    return true;
                }
                break;
            case EXCLUDE:
                if (Utils.isStringEmpty(signatureFieldId)) {
                    return true;
                }
                if (!sigFieldPermissions.getFields().contains(signatureFieldId)) {
                    return true;
                }
                break;
            default:
                throw new UnsupportedOperationException(
                        String.format("The action value '%s' is not supported!", sigFieldPermissions.getAction()));
        }
        CertificationPermission certificationPermission = sigFieldPermissions.getCertificationPermission();
        return CertificationPermission.NO_CHANGE_PERMITTED.equals(certificationPermission);
    }

}
