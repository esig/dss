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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.CommitmentQualifier;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.XAdES319132Utils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.transform.dom.DOMSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How to add signed properties to the signature.
 */
class SignXmlXadesBPropertiesTest extends CookbookTools {

	@Test
	void testWithProperties() throws Exception {

		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import eu.europa.esig.dss.enumerations.CommitmentType;
			// import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.enumerations.SignatureLevel;
			// import eu.europa.esig.dss.enumerations.SignaturePackaging;
			// import eu.europa.esig.dss.model.BLevelParameters;
			// import eu.europa.esig.dss.model.DSSDocument;
			// import eu.europa.esig.dss.model.SignatureValue;
			// import eu.europa.esig.dss.model.SignerLocation;
			// import eu.europa.esig.dss.model.ToBeSigned;
			// import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
			// import eu.europa.esig.dss.validation.timestamp.TimestampToken;
			// import eu.europa.esig.dss.xades.XAdESSignatureParameters;
			// import eu.europa.esig.dss.xades.signature.XAdESService;
			// import java.util.ArrayList;
			// import java.util.Arrays;
			// import java.util.List;

			XAdESSignatureParameters xadesSignatureParameters = new XAdESSignatureParameters();

			// Basic signature configuration
			xadesSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
			xadesSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			xadesSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
			xadesSignatureParameters.setSigningCertificate(privateKey.getCertificate());
			xadesSignatureParameters.setCertificateChain(privateKey.getCertificateChain());
			// tag::prettyPrint[]
			xadesSignatureParameters.setPrettyPrint(true);
			// end::prettyPrint[]

			// Configuration of several signed attributes like ...
			BLevelParameters bLevelParameters = xadesSignatureParameters.bLevel();

			// Contains claimed roles assumed by the signer when creating the signature
			bLevelParameters.setClaimedSignerRoles(Arrays.asList("Manager"));

			// signer location
			SignerLocation signerLocation = new SignerLocation();
			signerLocation.setCountry("BE");
			signerLocation.setStateOrProvince("Luxembourg");
			signerLocation.setPostalCode("1234");
			signerLocation.setLocality("SimCity");
			// Contains the indication of the purported place where the signer claims to have produced the signature
			bLevelParameters.setSignerLocation(signerLocation);

			// Identifies the commitment undertaken by the signer in signing (a) signed data object(s)
			// in the context of the selected signature policy
			List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfOrigin);
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);

			// Alternatively a custom CommitmentType may be defined
			CommonCommitmentType commitmentType = new CommonCommitmentType();
			commitmentType.setUri("http://some.server.com/custom-commitment");
			commitmentType.setDescription("This is a custom test commitment");
			commitmentType.setDocumentationReferences("http://some.server.com/custom-commitment/documentation");

			// It is also possible to define a custom qualifier, by providing its content (e.g. XML-encoded for XAdES)
			CommitmentQualifier commitmentQualifier = new CommitmentQualifier();
			String xmlContent = "<base:ext xmlns:base=\"http://same.server.com/custom-namespace\">Custom qualifier</base:ext>";
			commitmentQualifier.setContent(new InMemoryDocument(xmlContent.getBytes()));
			commitmentType.setCommitmentTypeQualifiers(commitmentQualifier);

			// Add custom commitment to the list
			commitmentTypeIndications.add(commitmentType);

			// NOTE: CommitmentType supports also IDQualifier and documentationReferences.
			// To use it, you need to have a custom implementation of the interface.
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(certificateVerifier);
			service.setTspSource(getTSPSource());

			// Allows setting of content-timestamp (part of the signed attributes)
			TimestampToken contentTimestamp = service.getContentTimestamp(toSignDocument, xadesSignatureParameters);
			xadesSignatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

			// Signature process with its 3 stateless steps
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, xadesSignatureParameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, xadesSignatureParameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, xadesSignatureParameters, signatureValue);

			// end::demo[]

			// tag::requirements[]

			// This parameter defines whether a revocation check shall be performed on a signature creation/extension
			// Default : false (revocation check is not performed)
			// NOTE: a behavior of the revocation check shall be defined with alerts within the used {@code eu.europa.esig.dss.validation.CertificateVerifier}
			xadesSignatureParameters.setCheckCertificateRevocation(false);

			// end::requirements[]

			testFinalDocument(signedDocument);

			DSSDocument xadesSignatureDocument = signedDocument;
			// tag::validateStructure[]
			Document signatureDocDom = DomUtils.buildDOM(xadesSignatureDocument);
			List<String> errors = XAdES319132Utils.getInstance().validateAgainstXSD(new DOMSource(signatureDocDom));
			// end::validateStructure[]
			assertTrue(Utils.isCollectionEmpty(errors));

		}
	}

}
