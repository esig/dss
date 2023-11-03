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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xml.utils.SantuarioInitializer;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.SignatureProfile;
import eu.europa.esig.dss.xades.XAdESProfileParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * XAdES implementation of DocumentSignatureService
 */
public class XAdESService extends AbstractSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> 
					implements MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters>,
					CounterSignatureService<XAdESCounterSignatureParameters> {

	private static final long serialVersionUID = -391276429698752703L;

	static {
		SantuarioInitializer.init();
		DSSXMLUtils.registerXAdESNamespaces();
	}

	private static final Logger LOG = LoggerFactory.getLogger(XAdESService.class);

	/**
	 * This is the constructor to create an instance of the {@code XAdESService}. A certificate verifier must be
	 * provided.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
	 */
	public XAdESService(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ XAdESService created");
	}

	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, XAdESSignatureParameters parameters) {
		return getContentTimestamp(Arrays.asList(toSignDocument), parameters);
	}

	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, XAdESSignatureParameters parameters) {
		Objects.requireNonNull(tspSource, "A TSPSource is required !");
		AllDataObjectsTimeStampBuilder builder = new AllDataObjectsTimeStampBuilder(tspSource, parameters);
		return builder.build(toSignDocuments);
	}

	@Override
	public ToBeSigned getDataToSign(final DSSDocument toSignDocument, final XAdESSignatureParameters parameters) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		
		assertSigningCertificateValid(parameters);
		final XAdESLevelBaselineB levelBaselineB = new XAdESLevelBaselineB(certificateVerifier);
		final byte[] dataToSign = levelBaselineB.getDataToSign(toSignDocument, parameters);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Data to sign: ");
			LOG.trace(new String(dataToSign));
		}
		parameters.getContext().setProfile(levelBaselineB);
		return new ToBeSigned(dataToSign);
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, XAdESSignatureParameters parameters) {
		Objects.requireNonNull(toSignDocuments, "toSignDocuments cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");

		assertMultiDocumentsAllowed(parameters);
		assertDocumentsValid(toSignDocuments);
		parameters.getContext().setDetachedContents(toSignDocuments);
		return getDataToSign(toSignDocuments.get(0), parameters);
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final XAdESSignatureParameters parameters, SignatureValue signatureValue)
	{
		Objects.requireNonNull(toSignDocument, "toSignDocument is not defined!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(parameters.getSignatureLevel(), "SignatureLevel must be defined!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
		
		assertSigningCertificateValid(parameters);
		parameters.getContext().setOperationKind(SigningOperation.SIGN);
		SignatureProfile profile;
		final XAdESProfileParameters context = parameters.getContext();
		if (context.getProfile() != null) {
			profile = context.getProfile();
		} else {
			profile = new XAdESLevelBaselineB(certificateVerifier);
		}
		
		DSSDocument result = profile.signDocument(toSignDocument, parameters, signatureValue.getValue());
		final SignatureExtension<XAdESSignatureParameters> extension = getExtensionProfile(parameters);
		if (extension != null) {
			if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging()) && Utils.isCollectionEmpty(parameters.getDetachedContents())) {
				List<DSSDocument> detachedContents = new ArrayList<>();
				detachedContents.add(toSignDocument);
				parameters.getContext().setDetachedContents(detachedContents);
			}
			result = extension.extendSignatures(result, parameters);
		}

		// The internal parameters (e.g. deterministic Id) are reset between two consecutive signing operations.
		// It prevents sharing two signatures the same cached data.
		parameters.reinit();
		result.setName(getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
		return result;
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, XAdESSignatureParameters parameters,
			SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocuments, "toSignDocuments cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(parameters.getSignatureLevel(), "SignatureLevel must be defined!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");

		assertMultiDocumentsAllowed(parameters);
		assertDocumentsValid(toSignDocuments);
		parameters.getContext().setDetachedContents(toSignDocuments);
		return signDocument(toSignDocuments.get(0), parameters, signatureValue);
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final XAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument cannot be null!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");
		Objects.requireNonNull(parameters.getSignatureLevel(), "SignatureLevel must be defined!");
		
		parameters.getContext().setOperationKind(SigningOperation.EXTEND);
		final SignatureExtension<XAdESSignatureParameters> extension = getExtensionProfile(parameters);
		if (extension != null) {
			final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
			dssDocument.setName(getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
			return dssDocument;
		}
		throw new UnsupportedOperationException(
				String.format("Unsupported signature format '%s' for extension.", parameters.getSignatureLevel()));
	}

	@Override
	public DSSDocument timestamp(List<DSSDocument> toTimestampDocuments, XAdESTimestampParameters parameters) {
		throw new UnsupportedOperationException("Unsupported operation for this file format");
	}

	/**
	 * The choice of profile according to the passed parameter.
	 *
	 * @param parameters {@link XAdESSignatureParameters}
	 * @return {@link SignatureExtension}
	 */
	private SignatureExtension<XAdESSignatureParameters> getExtensionProfile(final XAdESSignatureParameters parameters) {
		switch (parameters.getSignatureLevel()) {
		case XAdES_BASELINE_B:
			return null;
		case XAdES_BASELINE_T:
			final XAdESLevelBaselineT extensionT = new XAdESLevelBaselineT(certificateVerifier);
			extensionT.setTspSource(tspSource);
			return extensionT;
		case XAdES_C:
			final XAdESLevelC extensionC = new XAdESLevelC(certificateVerifier);
			extensionC.setTspSource(tspSource);
			return extensionC;
		case XAdES_X:
			final XAdESLevelX extensionX = new XAdESLevelX(certificateVerifier);
			extensionX.setTspSource(tspSource);
			return extensionX;
		case XAdES_XL:
			final XAdESLevelXL extensionXL = new XAdESLevelXL(certificateVerifier);
			extensionXL.setTspSource(tspSource);
			return extensionXL;
		case XAdES_A:
			final XAdESLevelA extensionA = new XAdESLevelA(certificateVerifier);
			extensionA.setTspSource(tspSource);
			return extensionA;
		case XAdES_BASELINE_LT:
			final XAdESLevelBaselineLT extensionLT = new XAdESLevelBaselineLT(certificateVerifier);
			extensionLT.setTspSource(tspSource);
			return extensionLT;
		case XAdES_BASELINE_LTA:
			final XAdESLevelBaselineLTA extensionLTA = new XAdESLevelBaselineLTA(certificateVerifier);
			extensionLTA.setTspSource(tspSource);
			return extensionLTA;
		default:
			throw new UnsupportedOperationException(
					String.format("Unsupported signature format '%s' for extension.", parameters.getSignatureLevel()));
		}
	}

	/**
	 * Only DETACHED and ENVELOPING signatures are allowed
	 * 
	 * @param parameters {@link XAdESSignatureParameters}
	 */
	private void assertMultiDocumentsAllowed(XAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters.getSignaturePackaging(), "SignaturePackaging shall be defined!");
		SignaturePackaging signaturePackaging = parameters.getSignaturePackaging();
		if (signaturePackaging == null || SignaturePackaging.ENVELOPED == signaturePackaging) {
			throw new IllegalArgumentException("Not supported operation (only DETACHED or ENVELOPING are allowed)");
		}
	}

	private void assertDocumentsValid(List<DSSDocument> toSignDocuments) {
		List<String> documentNames = new ArrayList<>();
		for (DSSDocument document : toSignDocuments) {
			if (toSignDocuments.size() > 1 && Utils.isStringBlank(document.getName())) {
				throw new IllegalArgumentException("All documents in the list to be signed shall have names!");
			}
			if (documentNames.contains(document.getName())) {
				throw new IllegalArgumentException(String.format("The documents to be signed shall have different names! "
						+ "The name '%s' appears multiple times.", document.getName()));
			}
			documentNames.add(document.getName());
		}
	}

	/**
	 * Incorporates a Signature Policy Store as an unsigned property into the XAdES Signature
	 * 
	 * @param document             {@link DSSDocument} containing a XAdES Signature
	 *                             to add a SignaturePolicyStore to
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} XAdESSignature with an incorporated SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(document, "The document cannot be null");
		Objects.requireNonNull(signaturePolicyStore, "The signaturePolicyStore cannot be null");
		
		SignaturePolicyStoreBuilder builder = new SignaturePolicyStoreBuilder();
		DSSDocument signatureWithPolicyStore = builder.addSignaturePolicyStore(document, signaturePolicyStore);
		signatureWithPolicyStore.setName(getFinalFileName(document, SigningOperation.ADD_SIG_POLICY_STORE));
		signatureWithPolicyStore.setMimeType(document.getMimeType());
		return signatureWithPolicyStore;
	}

	@Override
	public ToBeSigned getDataToBeCounterSigned(DSSDocument signatureDocument, XAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		verifyAndSetCounterSignatureParameters(parameters);
		
		CounterSignatureBuilder counterSignatureBuilder = new CounterSignatureBuilder(certificateVerifier);
		final DSSDocument signatureValue = counterSignatureBuilder.getCanonicalizedSignatureValue(signatureDocument, parameters);
		
		DSSReference counterSignatureReference = counterSignatureBuilder.buildCounterSignatureDSSReference(signatureDocument, parameters);
		parameters.setReferences(Collections.singletonList(counterSignatureReference));
		
		return getDataToSign(signatureValue, parameters);
	}

	@Override
	public DSSDocument counterSignSignature(DSSDocument signatureDocument, XAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
		verifyAndSetCounterSignatureParameters(parameters);

		CounterSignatureBuilder counterSignatureBuilder = new CounterSignatureBuilder(certificateVerifier);
		final DSSDocument signatureValueToSign = counterSignatureBuilder.getCanonicalizedSignatureValue(signatureDocument, parameters);
		parameters.getContext().setDetachedContents(Arrays.asList(signatureValueToSign));

		DSSReference counterSignatureReference = counterSignatureBuilder.buildCounterSignatureDSSReference(signatureDocument, parameters);
		parameters.setReferences(Collections.singletonList(counterSignatureReference));
		
		final DSSDocument counterSignature = signDocument(signatureValueToSign, parameters, signatureValue);
		final DSSDocument counterSigned = counterSignatureBuilder.buildEmbeddedCounterSignature(signatureDocument, counterSignature, parameters);
		
		parameters.reinit();
		counterSigned.setName(getFinalFileName(signatureDocument, SigningOperation.COUNTER_SIGN, parameters.getSignatureLevel()));
		counterSigned.setMimeType(signatureDocument.getMimeType());
		
		return counterSigned;
	}
	
	private void verifyAndSetCounterSignatureParameters(XAdESCounterSignatureParameters parameters) {
		if (parameters.getSignaturePackaging() == null) {
			parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		} else if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			throw new IllegalArgumentException(String.format("The SignaturePackaging '%s' is not supported by XAdES Counter Signature!", 
					parameters.getSignaturePackaging()));
		}
	}

}
