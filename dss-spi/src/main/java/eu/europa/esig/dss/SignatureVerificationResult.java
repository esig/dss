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
package eu.europa.esig.dss;

import eu.europa.esig.dss.x509.CertificateToken;

public class SignatureVerificationResult {

	private boolean valid;

	private CertificateToken issuer;

	protected String signatureInvalidityReason = "";

	protected SignatureAlgorithm algorithmUsedToSignToken;

	public SignatureVerificationResult() {
	}

	public SignatureVerificationResult(boolean valid, CertificateToken issuer, String signatureInvalidityReason, SignatureAlgorithm algorithmUsedToSignToken) {
		this.valid = valid;
		this.issuer = issuer;
		this.signatureInvalidityReason = signatureInvalidityReason;
		this.algorithmUsedToSignToken = algorithmUsedToSignToken;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("[");
		if(valid) {
			builder.append("VALID");
		} else {
			builder.append("INVALID");
		}
		builder.append("(");
		if(algorithmUsedToSignToken != null) {
			builder.append(algorithmUsedToSignToken);
		} else {
			builder.append("unknown algorithm");
		}
		builder.append(")");
		if(!valid) {
			builder.append("reason=");
			if(signatureInvalidityReason != null) {
				builder.append(signatureInvalidityReason);
			} else {
				builder.append("unknown");
			}
		}
		builder.append("]");
		return builder.toString();
	}

	public boolean isValid() {
		return valid;
	}

	public CertificateToken getIssuer() {
		return issuer;
	}

	public String getSignatureInvalidityReason() {
		return signatureInvalidityReason;
	}

	public SignatureAlgorithm getAlgorithmUsedToSignToken() {
		return algorithmUsedToSignToken;
	}

}
