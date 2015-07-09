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

import java.io.Serializable;

/**
 * Parameters for a Signature creation/extension
 *
 */
@SuppressWarnings("serial")
public abstract class AbstractSerializableSignatureParameters implements Serializable {

	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 */
	private boolean signWithExpiredCertificate = false;

	private SignatureLevel signatureLevel;
	private SignaturePackaging signaturePackaging;

	/**
	 * XAdES: The ds:SignatureMethod indicates the algorithms used to sign ds:SignedInfo.
	 */
	private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	/**
	 * The encryption algorithm shall be automatically extracted from the signing token.
	 */
	private EncryptionAlgorithm encryptionAlgorithm = signatureAlgorithm.getEncryptionAlgorithm();

	/**
	 * XAdES: The digest algorithm used to hash ds:SignedInfo.
	 */
	private DigestAlgorithm digestAlgorithm = signatureAlgorithm.getDigestAlgorithm();

	/**
	 * The object representing the parameters related to B- level.
	 */
	private BLevelParameters bLevelParams = new BLevelParameters();

	private String deterministicId;

	private TimestampParameters signatureTimestampParameters;
	private TimestampParameters archiveTimestampParameters;
	private TimestampParameters contentTimestampParameters;

	/**
	 * The document to be signed
	 */
	private DSSDocument detachedContent;

	/**
	 * This method returns the document to sign. In the case of the DETACHED signature this is the detached document.
	 *
	 * @return
	 */
	public DSSDocument getDetachedContent() {
		return detachedContent;
	}

	/**
	 * When signing this method is internally invoked by the {@code AbstractSignatureService} and the related variable {@code detachedContent} is overwritten by the service
	 * parameter. In the case of the DETACHED signature this is the detached document. In the case of ASiC-S this is the document to be signed.<p />
	 * When extending this method must be invoked to indicate the {@code detachedContent}.
	 *
	 * @param detachedContent
	 */
	public void setDetachedContent(final DSSDocument detachedContent) {
		this.detachedContent = detachedContent;
	}

	/**
	 * Indicates if it is possible to sign with an expired certificate. The default value is false.
	 *
	 * @return
	 */
	public boolean isSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	/**
	 * Allows to change the default behaviour regarding the use of an expired certificate.
	 *
	 * @param signWithExpiredCertificate
	 */
	public void setSignWithExpiredCertificate(final boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
	}

	/**
	 * Get signature format: XAdES_BES, XAdES_EPES, XAdES_BASELINE_T ../.. CAdES_BES...
	 *
	 * @return the value
	 */
	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	/**
	 * Set signature level. This field cannot be null.
	 *
	 * @param signatureLevel the value
	 */
	public void setSignatureLevel(final SignatureLevel signatureLevel) throws NullPointerException {
		if (signatureLevel == null) {
			throw new NullPointerException();
		}
		this.signatureLevel = signatureLevel;
	}

	/**
	 * Get Signature packaging
	 *
	 * @return the value
	 */
	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	/**
	 * Set Signature packaging
	 *
	 * @param signaturePackaging the value
	 */
	public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}

	/**
	 * @return the digest algorithm
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * @param digestAlgorithm the digest algorithm to set
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		if ((this.digestAlgorithm != null) && (this.encryptionAlgorithm != null)) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
		}
	}

	/**
	 * This setter should be used only when dealing with web services (or when signing in three steps). Usually the encryption algorithm is automatically extrapolated from the
	 * private key.
	 *
	 * @param encryptionAlgorithm
	 */
	@Deprecated
	public void setEncryptionAlgorithm(final EncryptionAlgorithm encryptionAlgorithm) {

		this.encryptionAlgorithm = encryptionAlgorithm;
		if ((this.digestAlgorithm != null) && (this.encryptionAlgorithm != null)) {

			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
		}
	}

	/**
	 * @return the encryption algorithm. It's determined by the privateKeyEntry and is null until the privateKeyEntry is set.
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * Gets the signature algorithm.
	 *
	 * @return the value
	 */
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public BLevelParameters bLevel() {
		return bLevelParams;
	}

	public BLevelParameters getbLevelParams() {
		return bLevelParams;
	}

	public void setBLevelParams(BLevelParameters bLevelParams) {
		this.bLevelParams = bLevelParams;
	}

	public TimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new TimestampParameters();
		}
		return signatureTimestampParameters;
	}

	public void setSignatureTimestampParameters(TimestampParameters signatureTimestampParameters) {
		this.signatureTimestampParameters = signatureTimestampParameters;
	}

	public TimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new TimestampParameters();
		}
		return archiveTimestampParameters;
	}

	public void setArchiveTimestampParameters(TimestampParameters archiveTimestampParameters) {
		this.archiveTimestampParameters = archiveTimestampParameters;
	}

	public TimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new TimestampParameters();
		}
		return contentTimestampParameters;
	}

	public void setContentTimestampParameters(TimestampParameters contentTimestampParameters) {
		this.contentTimestampParameters = contentTimestampParameters;
	}

	/**
	 * This methods reinits the deterministicId to force to recompute it
	 */
	public void reinitDeterministicId() {
		deterministicId = null;
	}

	@Override
	public String toString() {
		return "SignatureParameters{" +
				"signWithExpiredCertificate=" + signWithExpiredCertificate +
				", signatureLevel=" + signatureLevel +
				", signaturePackaging=" + signaturePackaging +
				", signatureAlgorithm=" + signatureAlgorithm +
				", encryptionAlgorithm=" + encryptionAlgorithm +
				", digestAlgorithm=" + digestAlgorithm +
				", bLevelParams=" + bLevelParams +
				", deterministicId='" + deterministicId + '\'' +
				", signatureTimestampParameters=" + ((signatureTimestampParameters == null) ? null : signatureTimestampParameters.toString()) +
				", archiveTimestampParameters=" + ((archiveTimestampParameters == null) ? null : archiveTimestampParameters.toString()) +
				", detachedContent=" + detachedContent + '}';
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((archiveTimestampParameters == null) ? 0 : archiveTimestampParameters.hashCode());
		result = (prime * result) + ((bLevelParams == null) ? 0 : bLevelParams.hashCode());
		result = (prime * result) + ((contentTimestampParameters == null) ? 0 : contentTimestampParameters.hashCode());
		result = (prime * result) + ((detachedContent == null) ? 0 : detachedContent.hashCode());
		result = (prime * result) + ((deterministicId == null) ? 0 : deterministicId.hashCode());
		result = (prime * result) + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = (prime * result) + ((encryptionAlgorithm == null) ? 0 : encryptionAlgorithm.hashCode());
		result = (prime * result) + (signWithExpiredCertificate ? 1231 : 1237);
		result = (prime * result) + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
		result = (prime * result) + ((signatureLevel == null) ? 0 : signatureLevel.hashCode());
		result = (prime * result) + ((signaturePackaging == null) ? 0 : signaturePackaging.hashCode());
		result = (prime * result) + ((signatureTimestampParameters == null) ? 0 : signatureTimestampParameters.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AbstractSerializableSignatureParameters other = (AbstractSerializableSignatureParameters) obj;
		if (archiveTimestampParameters == null) {
			if (other.archiveTimestampParameters != null) {
				return false;
			}
		} else if (!archiveTimestampParameters.equals(other.archiveTimestampParameters)) {
			return false;
		}
		if (bLevelParams == null) {
			if (other.bLevelParams != null) {
				return false;
			}
		} else if (!bLevelParams.equals(other.bLevelParams)) {
			return false;
		}
		if (contentTimestampParameters == null) {
			if (other.contentTimestampParameters != null) {
				return false;
			}
		} else if (!contentTimestampParameters.equals(other.contentTimestampParameters)) {
			return false;
		}
		if (detachedContent == null) {
			if (other.detachedContent != null) {
				return false;
			}
		} else if (!detachedContent.equals(other.detachedContent)) {
			return false;
		}
		if (deterministicId == null) {
			if (other.deterministicId != null) {
				return false;
			}
		} else if (!deterministicId.equals(other.deterministicId)) {
			return false;
		}
		if (digestAlgorithm != other.digestAlgorithm) {
			return false;
		}
		if (encryptionAlgorithm != other.encryptionAlgorithm) {
			return false;
		}
		if (signWithExpiredCertificate != other.signWithExpiredCertificate) {
			return false;
		}
		if (signatureAlgorithm != other.signatureAlgorithm) {
			return false;
		}
		if (signatureLevel != other.signatureLevel) {
			return false;
		}
		if (signaturePackaging != other.signaturePackaging) {
			return false;
		}
		if (signatureTimestampParameters == null) {
			if (other.signatureTimestampParameters != null) {
				return false;
			}
		} else if (!signatureTimestampParameters.equals(other.signatureTimestampParameters)) {
			return false;
		}
		return true;
	}


}
