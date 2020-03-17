package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;

import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;

/**
 * Represents a Source of certificates embedded into an OCSP Token
 *
 */
@SuppressWarnings("serial")
public class OCSPCertificateSource extends RevocationCertificateSource {
	
	private final BasicOCSPResp basicOCSPResp;
	
	/* Cached values */
	private List<CertificateToken> basicRespCertificates;
	private CertificateRef signingCertificateRef;
	
	public OCSPCertificateSource(final BasicOCSPResp basicOCSPResp) {
		Objects.requireNonNull(basicOCSPResp, "basicOCSPResponse must be provided!");
		this.basicOCSPResp = basicOCSPResp;
		
		getBasicOCSPRespCertificates();
	}
	
	/**
	 * Returns a list of CertificateTokens embedded into basic OCSP response
	 * 
	 * @return a list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getBasicOCSPRespCertificates() {
		if (basicRespCertificates == null) {
			basicRespCertificates = new ArrayList<>();
			for (final X509CertificateHolder x509CertificateHolder : basicOCSPResp.getCerts()) {
				CertificateToken certificateToken = DSSASN1Utils.getCertificate(x509CertificateHolder);
				addCertificate(certificateToken);
				if (!basicRespCertificates.contains(certificateToken)) {
					basicRespCertificates.add(certificateToken);
				}
			}
		}
		return basicRespCertificates;
	}

	@Override
	public List<CertificateRef> getAllCertificateRefs() {
		return Arrays.asList(getSigningCertificateRef());
	}
	
	/**
	 * Returns a signing certificate reference based on the embedded Responder ID
	 * 
	 * @return {@link CertificateRef}
	 */
	public CertificateRef getSigningCertificateRef() {
		if (signingCertificateRef == null) {
			final RespID respId = basicOCSPResp.getResponderId();
			final ResponderID responderIdAsASN1Object = respId.toASN1Primitive();
			final DERTaggedObject derTaggedObject = (DERTaggedObject) responderIdAsASN1Object.toASN1Primitive();
			if (1 == derTaggedObject.getTagNo()) {
				final ASN1Primitive derObject = derTaggedObject.getObject();
				final byte[] derEncoded = DSSASN1Utils.getDEREncoded(derObject);
				
				CertificateRef certificateRef = new CertificateRef();
				ResponderId responderId = new ResponderId();
				responderId.setX500Principal(new X500Principal(derEncoded));
				certificateRef.setResponderId(responderId);
				
				certificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
				signingCertificateRef = certificateRef;
				
			} else if (2 == derTaggedObject.getTagNo()) {
				final ASN1OctetString hashOctetString = (ASN1OctetString) derTaggedObject.getObject();
				final byte[] skiHash = hashOctetString.getOctets();

				CertificateRef certificateRef = new CertificateRef();
				ResponderId responderId = new ResponderId();
				// see RFC 6960 (B.1.  OCSP in ASN.1 - 1998 Syntax) :
				// KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
				// (excluding the tag and length fields)
				responderId.setSki(skiHash);
				certificateRef.setResponderId(responderId);
				certificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
				signingCertificateRef = certificateRef;
				
			} else {
				throw new DSSException("Unsupported tag No " + derTaggedObject.getTagNo());
				
			}
		}
		return signingCertificateRef;
	}
	
	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.OCSP_RESPONSE;
	}

}
