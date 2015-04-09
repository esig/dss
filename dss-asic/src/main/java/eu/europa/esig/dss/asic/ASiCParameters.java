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
package eu.europa.esig.dss.asic;

import java.io.Serializable;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.x509.SignatureForm;

/**
 * This class regroups the signature parameters related to ASiC form.
 *
 */
public class ASiCParameters implements Serializable {

	/**
	 * Indicates if the ZIP comment should be used to store the signed content mime-type.
	 */
	private boolean zipComment = false;

	/**
	 * Indicates the mime-type to be set within the mimetype file. If null the stored mime-type is that of the signed content.
	 */
	private String mimeType = null;

	/**
	 * The default signature form to use within the ASiC containers.
	 */
	private SignatureForm underlyingForm = SignatureForm.XAdES;

	/**
	 * The form of the container -S or -E.
	 */
	SignatureForm containerForm;

	/**
	 * This variable contains already enclosed signature(s) when appending a new one.
	 */
	private DSSDocument enclosedSignature;

	/**
	 * This property allows to provide a specific signature file name in the case of an ASiC-E container.
	 */
	private String signatureFileName;

	/**
	 * Default constructor
	 */
	public ASiCParameters() {
	}

	/**
	 * A copy constructor.
	 *
	 * @param source {@code ASiCParameters}
	 */
	public ASiCParameters(final ASiCParameters source) {

		zipComment = source.zipComment;
		mimeType = source.mimeType;
		underlyingForm = source.underlyingForm;
		containerForm = source.containerForm;
		enclosedSignature = source.enclosedSignature;
		signatureFileName = source.signatureFileName;
	}

	/**
	 * Indicates if the ZIP comment must include the mime-type.
	 *
	 * @return {@code boolean}
	 */
	public boolean isZipComment() {
		return zipComment;
	}

	/**
	 * This method allows to indicate if the zip comment will contain the mime type.
	 *
	 * @param zipComment
	 */
	public void setZipComment(final boolean zipComment) {
		this.zipComment = zipComment;
	}

	public String getMimeType() {
		return mimeType;
	}

	/**
	 * This method allows to set the mime-type within the mimetype file.
	 *
	 * @param mimeType the mimetype to  store
	 */
	public void setMimeType(final String mimeType) {
		this.mimeType = mimeType;
	}

	public SignatureForm getUnderlyingForm() {
		return underlyingForm;
	}

	/**
	 * Sets the signature form associated with an ASiC container. Only two forms are acceptable: XAdES and CAdES.
	 *
	 * @param underlyingForm signature form to associate with the ASiC container.
	 */
	public void setUnderlyingForm(final SignatureForm underlyingForm) {
		this.underlyingForm = underlyingForm;
	}

	/**
	 * @return the {@code SignatureForm} of the ASiC container
	 */
	public SignatureForm getContainerForm() {
		return containerForm;
	}

	/**
	 * This method allows to set the already existing signature. It is used when re-sign the ASIC-S container.
	 *
	 * @param signature extracted from the already existing container.
	 */
	public void setEnclosedSignature(final DSSDocument signature) {
		this.enclosedSignature = signature;
	}

	/**
	 * This method returns the already existing signature within a container.
	 *
	 * @return {@code DSSDocument} representing a signature
	 */
	public DSSDocument getEnclosedSignature() {
		return enclosedSignature;
	}

	/**
	 * This method returns the name of the signature file to use with ASiC-E container.
	 *
	 * @return signature file name
	 */
	public String getSignatureFileName() {
		return signatureFileName;
	}

	/**
	 * This method allows to set the signature file name to use with ASiC-E container.
	 *
	 * @param signatureFileName signature file name
	 */
	public void setSignatureFileName(final String signatureFileName) {
		this.signatureFileName = signatureFileName;
	}
}
