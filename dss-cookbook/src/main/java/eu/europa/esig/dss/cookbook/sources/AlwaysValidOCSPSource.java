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
package eu.europa.esig.dss.cookbook.sources;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.cookbook.example.Cookbook;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

public class AlwaysValidOCSPSource implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(AlwaysValidOCSPSource.class);

	private final PrivateKey privateKey;

	private final X509Certificate signingCert;
	private Date ocspDate = new Date();

	private CertificateStatus expectedResponse = CertificateStatus.GOOD;

	static {

		try {

			Security.addProvider(new BouncyCastleProvider());
		} catch (Throwable e) {
			LOG.error(e.getMessage(), e);
		}
	}

	/**
	 * The default constructor for MockConfigurableOCSPSource using "src/test/resources/ocsp.p12" file as OCSP responses source.
	 */
	public AlwaysValidOCSPSource() {

		this("/ocsp.p12", "password");
	}

	/**
	 * The default constructor for MockOCSPSource.
	 *
	 * @param signerPkcs12Name
	 * @param password
	 * @throws Exception
	 */
	public AlwaysValidOCSPSource(final String signerPkcs12Name, final String password) {

		try {

			final KeyStore keyStore = KeyStore.getInstance("PKCS12");
			final String pathFromResource = Cookbook.getPathFromResource(signerPkcs12Name);
			final FileInputStream fileInputStream = new FileInputStream(pathFromResource);
			keyStore.load(fileInputStream, password.toCharArray());
			final String alias = keyStore.aliases().nextElement();
			signingCert = (X509Certificate) keyStore.getCertificate(alias);
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			if (LOG.isTraceEnabled()) {

				final CommonCertificateSource certificateSource = new CommonCertificateSource();
				final CertificateToken certificateToken = certificateSource.addCertificate(new CertificateToken(signingCert));
				LOG.trace("OCSP mockup with signing certificate:\n" + certificateToken);
			}
		} catch (Exception e) {

			throw new DSSException(e);
		}
	}

	public CertificateStatus getExpectedResponse() {

		return expectedResponse;
	}

	/**
	 * This method allows to set the status of the cert to GOOD.
	 */
	public void setGoodStatus() {

		this.expectedResponse = CertificateStatus.GOOD;
	}

	/**
	 * This method allows to set the status of the cert to UNKNOWN.
	 */
	public void setUnknownStatus() {

		this.expectedResponse = new UnknownStatus();
	}

	/**
	 * This method allows to set the status of the cert to REVOKED.
	 *
	 * unspecified = 0; keyCompromise = 1; cACompromise = 2; affiliationChanged = 3; superseded = 4; cessationOfOperation = 5; certificateHold = 6; // 7 -> unknown removeFromCRL = 8; privilegeWithdrawn = 9; aACompromise = 10;
	 *
	 * @param revocationDate
	 * @param revocationReasonId
	 */
	public void setRevokedStatus(final Date revocationDate, final int revocationReasonId) {

		this.expectedResponse = new RevokedStatus(revocationDate, revocationReasonId);
	}

	@Override
	public OCSPToken getOCSPToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {

		try {

			final X509Certificate cert = certificateToken.getCertificate();
			final BigInteger serialNumber = cert.getSerialNumber();
			X509Certificate issuerCert = issuerCertificateToken.getCertificate();
			final OCSPReq ocspReq = generateOCSPRequest(issuerCert, serialNumber);

			final DigestCalculator digestCalculator = DSSUtils.getSHA1DigestCalculator();
			final BasicOCSPRespBuilder basicOCSPRespBuilder = new JcaBasicOCSPRespBuilder(issuerCert.getPublicKey(), digestCalculator);
			final Extension extension = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			if (extension != null) {

				basicOCSPRespBuilder.setResponseExtensions(new Extensions(new Extension[] {
						extension
				}));
			}
			final Req[] requests = ocspReq.getRequestList();
			for (int ii = 0; ii != requests.length; ii++) {

				final Req req = requests[ii];
				final CertificateID certID = req.getCertID();

				boolean isOK = true;

				if (isOK) {

					basicOCSPRespBuilder.addResponse(certID, CertificateStatus.GOOD, ocspDate, null, null);
				} else {

					Date revocationDate = DSSUtils.getDate(ocspDate, -1);
					basicOCSPRespBuilder.addResponse(certID, new RevokedStatus(revocationDate, CRLReason.privilegeWithdrawn));
				}
			}

			final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
			final X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(issuerCert.getEncoded());
			final X509CertificateHolder[] chain = {
					x509CertificateHolder
			};
			BasicOCSPResp basicResp = basicOCSPRespBuilder.build(contentSigner, chain, ocspDate);
			final SingleResp[] responses = basicResp.getResponses();

			final OCSPToken ocspToken = new OCSPToken(basicResp, responses[0]);
			//final OCSPResp ocspResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);
			return ocspToken;
		} catch (OCSPException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		}
	}

	public OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws DSSException {

		try {

			final DigestCalculator digestCalculator = DSSUtils.getSHA1DigestCalculator();
			// Generate the id for the certificate we are looking for
			CertificateID id = new CertificateID(digestCalculator, new X509CertificateHolder(issuerCert.getEncoded()), serialNumber);

			// basic request generation with nonce
			OCSPReqBuilder ocspGen = new OCSPReqBuilder();

			ocspGen.addRequest(id);

			// create details for nonce extension
			BigInteger nonce = BigInteger.valueOf(ocspDate.getTime());

			Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
			ocspGen.setRequestExtensions(new Extensions(new Extension[] {
					ext
			}));

			return ocspGen.build();
		} catch (OCSPException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	public void setOcspDate(Date ocspDate) {
		this.ocspDate = ocspDate;
	}

}