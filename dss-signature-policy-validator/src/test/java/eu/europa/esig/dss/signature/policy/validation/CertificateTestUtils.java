/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.util.encoders.Hex;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateTestUtils {
	
	public static CertificateToken loadIssuers(File certFile, CertificatePool certPool) throws CertificateException, IOException {
		return loadIssuers(DSSUtils.loadCertificate(certFile), certPool);
	}
	
	public static CertificateToken loadIssuers(CertificateToken certificate, CertificatePool certPool) {
		DataLoader loader = new NativeHTTPDataLoader() {
			private static final long serialVersionUID = 1L;

			@Override
			public byte[] get(String url) {
				if (url.startsWith("ldap")) {
					return null;
				}
				return super.get(url);
			}
		};
		CertificateToken cert = certPool.getInstance(certificate, CertificateSourceType.SIGNATURE);
		return loadIssuers(loader, cert, certPool);
	}

	
	public static CertificateToken loadIssuers(DataLoader loader, CertificateToken certificate, CertificatePool certPool) {
		return loadIssuers(loader,  certificate, certPool, 0, Collections.<CertificateToken>emptyList());
	}
	
	private static CertificateToken loadIssuers(DataLoader loader, CertificateToken certificate, CertificatePool certPool, int currentPathLength, List<CertificateToken> ignore) {
		if (certificate.getIssuerToken() == null && !certificate.isSelfSigned()) {
			Collection<CertificateToken> issuerCertificates = certPool.get(certificate.getIssuerX500Principal());
			if (issuerCertificates == null || issuerCertificates.isEmpty()) {
				loadIssuerFromAiaExtension(loader, certificate, certPool);
				issuerCertificates = certPool.get(certificate.getIssuerX500Principal());
			}
			// Avoid concurrent modifications
			issuerCertificates = new ArrayList<>(issuerCertificates);
			issuerCertificates.removeAll(ignore);
//			printCertHierarchy(certificate, currentPathLength, issuerCertificates);
			
			ignore = new ArrayList<>(ignore);
			if (containsOnlyBridgeCertificates(issuerCertificates)) {
				// If all the certificates retrieved contain the same key (shared private key), they are connecting 2
				// certification paths. So they will appear again up in the path processing so the best option is to 
				// ignore them if they show up in the future and process them here only.
				ignore.addAll(issuerCertificates);
			}
			for (CertificateToken issuerCertificateToken : issuerCertificates) {
				if (isIssuer(certificate, issuerCertificateToken)) {
					loadIssuers(loader, issuerCertificateToken, certPool, currentPathLength+1, ignore);
				}
			}
		}
		return certificate;
	}

	private static boolean containsOnlyBridgeCertificates(Collection<CertificateToken> issuerCertificates) {
		Object pk = null;
		for (CertificateToken issuerCertificateToken : issuerCertificates) {
			if (pk == null) {
				pk = issuerCertificateToken.getPublicKey();
			} else if (!pk.equals(issuerCertificateToken.getPublicKey())) {
				return false;
			}
		}
		return true;
	}

	@SuppressWarnings("unused")
	private static void printCertHierarchy(CertificateToken certificate, int max, Collection<CertificateToken> issuerCertificates) {
		StringBuilder prefix = new StringBuilder();
		for(int i=0;i<max;i++)
			prefix.append(" ");
		prefix.append("|->");
		System.out.println(prefix.toString() + certificate.getSubjectX500Principal()+"/"+certificate.getIssuerX500Principal() + " - Size: "+issuerCertificates.size());
	}

	private static void loadIssuerFromAiaExtension(DataLoader loader, CertificateToken certificate, CertificatePool certPool) {
		Collection<CertificateToken> issuerCertificates = DSSUtils.loadPotentialIssuerCertificates(certificate, loader);

		if (issuerCertificates != null) {
			for (CertificateToken certificateToken : issuerCertificates) {
				certPool.getInstance(certificateToken, CertificateSourceType.AIA);
				
//				try {
//					java.nio.file.Files.write(java.nio.file.Paths.get(new File("c:/temp", certificateToken.getSubjectX500Principal().toString().replaceAll( "[\u0001-\u001f<>:\"/\\\\|?*\u007f]+", "" ).trim()+".cer").toURI()), certificateToken.getEncoded());
//				} catch (IOException e) {
//					e.printStackTrace();
//				}
			}
		}
	}

	private static boolean isIssuer(CertificateToken certificateToken, CertificateToken issuerCertificateToken){
		if (!certificateToken.isSignedBy(issuerCertificateToken)) {
			return false;
		}
		
		String ski = GetSubjectKeyIdentifier(issuerCertificateToken);
		String aki = GetAuthorityKeyIdentifier(certificateToken);
		if (ski != null && aki != null && !ski.equals(aki)) {
			return false;
		}
		
		return certificateToken.getIssuerX500Principal().equals(issuerCertificateToken.getSubjectX500Principal());
	}
	
	private static String GetSubjectKeyIdentifier(CertificateToken token) {
		byte[] skiValue = token.getCertificate().getExtensionValue(Extension.subjectKeyIdentifier.getId());
		if (skiValue != null) {
			byte[] ski = ASN1OctetString.getInstance(skiValue).getOctets();
			byte[] id = SubjectKeyIdentifier.getInstance(ski).getKeyIdentifier();
			return Hex.toHexString(id);
		}
		return null;
	}
	
	private static String GetAuthorityKeyIdentifier(CertificateToken token) {
		byte[] akiValue = token.getCertificate().getExtensionValue(Extension.authorityKeyIdentifier.getId());
		if (akiValue != null) {
			AuthorityKeyIdentifier authorityKeyIdentifier;
			byte[] aki = ASN1OctetString.getInstance(akiValue).getOctets();
			authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(aki);
			return Hex.toHexString(authorityKeyIdentifier.getKeyIdentifier());
		}
		return null;
	}
}
