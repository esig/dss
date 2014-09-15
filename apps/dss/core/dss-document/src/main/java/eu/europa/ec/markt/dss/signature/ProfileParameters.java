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

package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.cades.CAdESService;
import eu.europa.ec.markt.dss.signature.xades.SignatureBuilder;
import eu.europa.ec.markt.dss.signature.xades.XAdESLevelBaselineB;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;

/**
 * This class This class manages the internal variables used in the process of creating of a signature and which allows to
 * accelerate the generation.<br>
 * ! This class must be derived to  take also into account other formats then XAdES
 */
public class ProfileParameters {

	private XAdESLevelBaselineB profile;

	/**
	 * Returns the current Profile used to generate the signature or its extension
	 *
	 * @return
	 */
	public XAdESLevelBaselineB getProfile() {

		return profile;
	}

	/**
	 * Sets the current Profile used to generate the signature or its extension
	 *
	 * @return
	 */
	public void setProfile(XAdESLevelBaselineB profile) {

		this.profile = profile;
	}

	/*
	 * The builder used to create the signature structure. Currently used only for XAdES.
	 */
	private SignatureBuilder builder;

	public SignatureBuilder getBuilder() {

		return builder;
	}

	public void setBuilder(SignatureBuilder builder) {

		this.builder = builder;
	}

	/*
	 * The type of operation to perform.
	 */
	public static enum Operation {

		SIGNING, EXTENDING
	}

	/*
	 * Indicates the type of the operation to be done
	 */ Operation operationKind;

	public Operation getOperationKind() {

		return operationKind;
	}

	public void setOperationKind(Operation operationKind) {

		this.operationKind = operationKind;
	}

	/*
	 * This is the underlying service used within the ASiC signature generation process.
	 */
	private DocumentSignatureService underlyingASiCService;

	/**
	 * Returns the underlying {@code DocumentSignatureService} to use within the ASiC signature process.
	 *
	 * @param certificateVerifier the certificate verifier to use with the signature service.
	 * @param signatureForm       This is the form of the underlying ASiC signature. Only XAdES ans CAdES forms are acceptable.
	 * @return the underlying ASiC signature service.
	 */
	public DocumentSignatureService getUnderlyingASiCService(final CertificateVerifier certificateVerifier, final SignatureForm signatureForm) {

		if (underlyingASiCService == null) {

			if (signatureForm == SignatureForm.XAdES) {

				underlyingASiCService = new XAdESService(certificateVerifier);
			} else if (signatureForm == SignatureForm.CAdES) {

				underlyingASiCService = new CAdESService(certificateVerifier);
			} else {
				throw new DSSException("Unsupported parameter value: only XAdES and CAdES forms are acceptable!");
			}
		}
		return underlyingASiCService;
	}
}
