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
package eu.europa.esig.dss.cookbook.example.sign;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.sc.PcscEid;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cookbook.sources.AppletView;
import eu.europa.esig.dss.cookbook.sources.EidPrivateKeyEntry;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.x509.CertificateToken;

public class EidNativeSignatureTokenConnection implements SignatureTokenConnection {

	private static final Logger logger = LoggerFactory.getLogger(EidNativeSignatureTokenConnection.class);

	private PcscEid eid;

	/**
	 * The default constructor for EidNativeSignatureTokenConnection.
	 */
	public EidNativeSignatureTokenConnection(AppletView view) {
		this.eid = new PcscEid(view, new Messages(Locale.ENGLISH));
	}

	@Override
	public void close() {
		eid.close();
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry)
			throws DSSException {

		if (digestAlgorithm != DigestAlgorithm.SHA1) {
			throw new RuntimeException("Only SH1 supported in cookbook");
		}

		byte[] digestValue = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());

		try {
			eid.isEidPresent();
			byte[] sig = this.eid.sign(digestValue, digestAlgorithm.getName());
			SignatureValue sigval = new SignatureValue(SignatureAlgorithm.RSA_SHA1, sig);
			return sigval;
		} catch (Exception e) {
			logger.error("An error occured while signing : " + e.getMessage(), e);
			throw new DSSException(e);
		}

	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() {
		try {
			eid.isEidPresent();

			List<X509Certificate> signatureChain = eid.getSignCertificateChain();
			List<DSSPrivateKeyEntry> entries = new ArrayList<DSSPrivateKeyEntry>();
			entries.add(new EidPrivateKeyEntry(new CertificateToken(signatureChain.get(0)), signatureChain));
			return entries;
		} catch (Exception e) {
			logger.error("An error occured while retrieving keys : " + e.getMessage(), e);
			throw new DSSException(e);
		}
	}

}
