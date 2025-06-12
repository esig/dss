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
package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class is used to create a meaningful name for document depending
 * on its original name and the signing operation.
 *
 */
public class FileNameBuilder {

    /** Represents a container prefix string */
    private static final String CONTAINER_PREFIX = "container";

    /** Represents a document prefix string */
    private static final String DOCUMENT_PREFIX = "document";

    /** Represents a signed document suffix string */
    private static final String SIGNED_SUFFIX = "-signed";

    /** Represents a counter-signed document suffix string */
    private static final String COUNTER_SIGNED_SUFFIX = "-counter-signed";

    /** Represents a timestamped document suffix string */
    private static final String TIMESTAMPED_SUFFIX = "-timestamped";

    /** Represents an extended document suffix string */
    private static final String EXTENDED_SUFFIX = "-extended";

    /** Represents a document with added signature-policy-store suffix string */
    private static final String SIGNATURE_POLICY_STORE_SUFFIX = "-sig-policy-store";

    /** Represents a document with added evidence-record suffix string */
    private static final String EVIDENCE_RECORD_SUFFIX = "-preserved";

    /** Filename extension for an enveloping CMS signature */
    private static final String P7M_EXTENSION = "p7m";

    /** Filename extension for a detached CMS signature */
    private static final String P7S_EXTENSION = "p7s";

    /** The original document filename */
    private String originalFilename;

    /** The performed signing-operation */
    private SigningOperation signingOperation;

    /** The final signature level */
    private SignatureLevel signatureLevel;

    /** The signature packaging */
    private SignaturePackaging signaturePackaging;

    /** The target document MimeType (used for extension definition) */
    private MimeType mimeType;

    /**
     * Default constructor to instantiate the builder
     */
    public FileNameBuilder() {
        // empty
    }

    /**
     * Sets the original filename of the document
     *
     * @param originalFilename {@link String}
     * @return this {@link FileNameBuilder}
     */
    public FileNameBuilder setOriginalFilename(String originalFilename) {
        this.originalFilename = originalFilename;
        return this;
    }

    /**
     * Sets the performed signing operation type
     *
     * @param signingOperation {@link SigningOperation}
     * @return this {@link FileNameBuilder}
     */
    public FileNameBuilder setSigningOperation(SigningOperation signingOperation) {
        this.signingOperation = signingOperation;
        return this;
    }

    /**
     * Sets the final signature level
     *
     * @param signatureLevel {@link SignatureLevel}
     * @return this {@link FileNameBuilder}
     */
    public FileNameBuilder setSignatureLevel(SignatureLevel signatureLevel) {
        this.signatureLevel = signatureLevel;
        return this;
    }

    /**
     * Sets the signature packaging
     *
     * @param signaturePackaging {@link SignaturePackaging}
     * @return this {@link FileNameBuilder}
     */
    public FileNameBuilder setSignaturePackaging(SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
        return this;
    }

    /**
     * Sets the document mimetype
     *
     * @param mimeType {@link MimeType}
     * @return this {@link FileNameBuilder}
     */
    public FileNameBuilder setMimeType(MimeType mimeType) {
        this.mimeType = mimeType;
        return this;
    }

    /**
     * Generates and returns a final name for the document to create
     *
     * @return {@link String} the document filename
     */
    public String build() {
        StringBuilder finalName = new StringBuilder();

        String originalName;
        if (isContainerMimeType(mimeType)) {
            originalName = CONTAINER_PREFIX;
        } else {
            originalName = originalFilename;
        }

        String originalExtension = Utils.EMPTY_STRING;
        if (Utils.isStringNotEmpty(originalName)) {
            originalExtension = Utils.getFileNameExtension(originalName);
            if (Utils.isStringNotEmpty(originalExtension)) {
                // remove extension
                originalName = originalName.substring(0, originalName.length() - originalExtension.length() - 1);
            }
            finalName.append(originalName);

        } else {
            finalName.append(DOCUMENT_PREFIX);
        }

        if (signingOperation != null) {
            switch (signingOperation) {
                case SIGN:
                    finalName.append(SIGNED_SUFFIX);
                    break;
                case COUNTER_SIGN:
                    finalName.append(COUNTER_SIGNED_SUFFIX);
                    break;
                case TIMESTAMP:
                    finalName.append(TIMESTAMPED_SUFFIX);
                    break;
                case EXTEND:
                    finalName.append(EXTENDED_SUFFIX);
                    break;
                case ADD_SIG_POLICY_STORE:
                    finalName.append(SIGNATURE_POLICY_STORE_SUFFIX);
                    break;
                case ADD_EVIDENCE_RECORD:
                    finalName.append(EVIDENCE_RECORD_SUFFIX);
                    break;
                default:
                    throw new DSSException(String.format("The following operation '%s' is not supported!", signingOperation));
            }
        }

        if (signatureLevel != null) {
            finalName.append('-');
            finalName.append(Utils.lowerCase(signatureLevel.name().replace("_", "-")));
        }

        String extension = getFileExtensionString(signatureLevel, signaturePackaging, mimeType);
        extension = Utils.isStringNotBlank(extension) ? extension : originalExtension;
        if (Utils.isStringNotBlank(extension)) {
            finalName.append('.');
            finalName.append(extension);
        }

        return finalName.toString();
    }

    private boolean isContainerMimeType(MimeType mimeType) {
        return MimeTypeEnum.ASICS.equals(mimeType) || MimeTypeEnum.ASICE.equals(mimeType);
    }

    private String getFileExtensionString(SignatureLevel level, SignaturePackaging packaging, MimeType mimeType) {
        if (mimeType != null) {
            return mimeType.getExtension();

        } else if (level != null) {
            SignatureForm signatureForm = level.getSignatureForm();
            switch (signatureForm) {
                case XAdES:
                    return MimeTypeEnum.XML.getExtension();
                case CAdES:
                    if (packaging != null) {
                        return SignaturePackaging.DETACHED.equals(packaging) ? P7S_EXTENSION : P7M_EXTENSION;
                    }
                    break; // return empty
                case PAdES:
                    return MimeTypeEnum.PDF.getExtension();
                case JAdES:
                    return MimeTypeEnum.JSON.getExtension();
                default:
                    throw new DSSException(String.format("Unable to generate a full document name! " +
                            "The SignatureForm %s is not supported.", signatureForm));
            }
        }
        return Utils.EMPTY_STRING;
    }

}
