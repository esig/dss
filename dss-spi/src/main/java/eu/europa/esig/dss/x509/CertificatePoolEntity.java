package eu.europa.esig.dss.x509;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class re-groups equivalent certificates.
 * 
 * All certificates for a given {@code CertificatePoolEntity} have the same
 * public key.
 */
class CertificatePoolEntity implements Serializable {
	
	private static final long serialVersionUID = -8670353777128605464L;

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePoolEntity.class);

	/**
	 * Unique Id for all certificates (Hash of the common public key
	 */
	private final String id;

	/**
	 * Equivalent certificates (which have the same public key)
	 */
	private final List<CertificateToken> equivalentCertificates = Collections.synchronizedList(new ArrayList<CertificateToken>());

	/**
	 * This Set contains the different sources for this certificate.
	 */
	private final Set<CertificateSourceType> sources = Collections.synchronizedSet(new HashSet<CertificateSourceType>());

	CertificatePoolEntity(CertificateToken initialCert, CertificateSourceType source) {
		id = initialCert.getEntityKey();
		equivalentCertificates.add(initialCert);
		sources.add(source);
	}

	void addEquivalentCertificate(CertificateToken token) {
		if (!equivalentCertificates.contains(token)) {
			LOG.trace("Certificate with same public key detected : {}", token.getAbbreviation());
			// we manually recompute the SKI (we had cases with wrongly encoded value in the
			// certificate)
			final byte[] newSKI = DSSASN1Utils.computeSkiFromCert(token);
			CertificateToken equivalent = equivalentCertificates.iterator().next();
			final byte[] skiEquivalent = DSSASN1Utils.computeSkiFromCert(equivalent);
			// This should never happen
			if (!Arrays.equals(newSKI, skiEquivalent) && LOG.isWarnEnabled()) {

				LOG.warn("{} \nCERT : {} \nSKI : {} \nPubKey : {}", token, Utils.toBase64(token.getEncoded()), Utils.toBase64(newSKI),
						Utils.toBase64(token.getPublicKey().getEncoded()));

				LOG.warn("is not equivalent to");

				LOG.warn("{} \nCERT : {} \nSKI : {} \nPubKey : {}", equivalent, Utils.toBase64(equivalent.getEncoded()), Utils.toBase64(skiEquivalent),
						Utils.toBase64(token.getPublicKey().getEncoded()));
			} else {
				equivalentCertificates.add(token);
			}
		}
	}

	void addSource(CertificateSourceType source) {
		sources.add(source);
	}

	List<CertificateToken> getEquivalentCertificates() {
		return Collections.unmodifiableList(equivalentCertificates);
	}

	Set<CertificateSourceType> getSources() {
		return Collections.unmodifiableSet(sources);
	}

	boolean isTrusted() {
		return sources.contains(CertificateSourceType.TRUSTED_LIST) || sources.contains(CertificateSourceType.TRUSTED_STORE);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		CertificatePoolEntity other = (CertificatePoolEntity) obj;
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		return true;
	}

}