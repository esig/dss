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
package eu.europa.esig.dss.applet.wizard.signature;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.applet.controller.ActivityController;
import eu.europa.esig.dss.applet.controller.DSSWizardController;
import eu.europa.esig.dss.applet.main.DSSAppletCore;
import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardController;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.util.SigningUtils;
import eu.europa.esig.dss.applet.view.signature.CertificateView;
import eu.europa.esig.dss.applet.view.signature.FileView;
import eu.europa.esig.dss.applet.view.signature.FinishView;
import eu.europa.esig.dss.applet.view.signature.PKCS11View;
import eu.europa.esig.dss.applet.view.signature.PKCS12View;
import eu.europa.esig.dss.applet.view.signature.PersonalDataView;
import eu.europa.esig.dss.applet.view.signature.SaveView;
import eu.europa.esig.dss.applet.view.signature.SignatureDigestAlgorithmView;
import eu.europa.esig.dss.applet.view.signature.SignatureView;
import eu.europa.esig.dss.applet.view.signature.TokenView;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.wsclient.signature.DigestAlgorithm;
import eu.europa.esig.dss.wsclient.signature.DssTransform;
import eu.europa.esig.dss.wsclient.signature.EncryptionAlgorithm;
import eu.europa.esig.dss.wsclient.signature.Policy;
import eu.europa.esig.dss.wsclient.signature.SignatureLevel;
import eu.europa.esig.dss.wsclient.signature.SignaturePackaging;
import eu.europa.esig.dss.wsclient.signature.WsChainCertificate;
import eu.europa.esig.dss.wsclient.signature.WsParameters;
import eu.europa.esig.dss.wsclient.signature.WsdssReference;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class SignatureWizardController extends DSSWizardController<SignatureModel> {

	private FileView fileView;
	private SignatureView signatureView;
	private TokenView tokenView;
	private PKCS11View pkcs11View;
	private PKCS12View pkcs12View;
	private SignatureDigestAlgorithmView signatureDigestAlgorithmView;
	private CertificateView certificateView;
	private PersonalDataView personalDataView;
	private SaveView saveView;
	private FinishView signView;

	/**
	 * The default constructor for SignatureWizardController.
	 *
	 * @param core
	 * @param model
	 */
	public SignatureWizardController(final DSSAppletCore core, final SignatureModel model) {
		super(core, model);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardController#doCancel()
	 */
	@Override
	protected void doCancel() {

		getCore().getController(ActivityController.class).display();
	}

	/**
	 *
	 */
	public void doRefreshPrivateKeys() {

		try {
			final SignatureTokenConnection tokenConnection = getModel().getTokenConnection();
			getModel().setPrivateKeys(tokenConnection.getKeys());
		} catch (final DSSException e) {
			// FIXME
			LOG.error(e.getMessage(), e);
		}

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardController#doStart()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, ? extends WizardController<SignatureModel>>> doStart() {

		return FileStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardController#registerViews()
	 */
	@Override
	protected void registerViews() {

		fileView = new FileView(getCore(), this, getModel());
		signatureView = new SignatureView(getCore(), this, getModel());
		tokenView = new TokenView(getCore(), this, getModel());
		pkcs11View = new PKCS11View(getCore(), this, getModel());
		pkcs12View = new PKCS12View(getCore(), this, getModel());
		signatureDigestAlgorithmView = new SignatureDigestAlgorithmView(getCore(), this, getModel());
		certificateView = new CertificateView(getCore(), this, getModel());
		personalDataView = new PersonalDataView(getCore(), this, getModel());
		saveView = new SaveView(getCore(), this, getModel());
		signView = new FinishView(getCore(), this, getModel());
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardController#registerWizardStep()
	 */
	@Override
	protected Map<Class<? extends WizardStep<SignatureModel, ? extends WizardController<SignatureModel>>>, ? extends WizardStep<SignatureModel, ? extends WizardController<SignatureModel>>> registerWizardStep() {

		final SignatureModel model = getModel();

		final Map steps = new HashMap();
		steps.put(FileStep.class, new FileStep(model, fileView, this));
		steps.put(SignatureStep.class, new SignatureStep(model, signatureView, this));
		steps.put(TokenStep.class, new TokenStep(model, tokenView, this));
		steps.put(PKCS11Step.class, new PKCS11Step(model, pkcs11View, this));
		steps.put(PKCS12Step.class, new PKCS12Step(model, pkcs12View, this));
		steps.put(SignatureDigestAlgorithmStep.class, new SignatureDigestAlgorithmStep(model, signatureDigestAlgorithmView, this));
		steps.put(CertificateStep.class, new CertificateStep(model, certificateView, this));
		steps.put(PersonalDataStep.class, new PersonalDataStep(model, personalDataView, this));
		steps.put(SaveStep.class, new SaveStep(model, saveView, this));
		steps.put(FinishStep.class, new FinishStep(model, signView, this));

		return steps;
	}

	/**
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws DSSException
	 */
	public void signDocument() throws IOException, NoSuchAlgorithmException, DSSException {

		final SignatureModel model = getModel();

		final File fileToSign = model.getSelectedFile();
		final SignatureTokenConnection tokenConnection = model.getTokenConnection();
		final DSSPrivateKeyEntry privateKey = model.getSelectedPrivateKey();

		final WsParameters parameters = new WsParameters();

		parameters.setSigningCertificateBytes(privateKey.getCertificate().getEncoded());

		List<WsChainCertificate> chainCertificateList = parameters.getChainCertificateList();
		WsChainCertificate certificate = new WsChainCertificate();
		certificate.setX509Certificate(privateKey.getCertificate().getEncoded());
		chainCertificateList.add(certificate);
		CertificateToken[] certificateChain = privateKey.getCertificateChain();
		if (ArrayUtils.isNotEmpty(certificateChain)){
			for (CertificateToken certificateToken : certificateChain) {
				WsChainCertificate c = new WsChainCertificate();
				c.setX509Certificate(certificateToken.getEncoded());
				chainCertificateList.add(c);
			}
		}

		parameters.setEncryptionAlgorithm(EncryptionAlgorithm.fromValue(privateKey.getEncryptionAlgorithm().name()));

		parameters.setSigningDate(DSSXMLUtils.createXMLGregorianCalendar(new Date()));

		DigestAlgorithm digestAlgorithm = model.getSignatureDigestAlgorithm();
		if (digestAlgorithm == null) {
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		} else {
			parameters.setDigestAlgorithm(digestAlgorithm);
		}

		if (model.isTslSignatureCheck()) {
			prepareTSLSignature(parameters, fileToSign);
		} else {
			prepareCommonSignature(model, parameters);
		}

		final DSSDocument signedDocument = SigningUtils.signDocument(serviceURL, fileToSign, parameters, privateKey, tokenConnection);
		final FileOutputStream fileOutputStream = new FileOutputStream(model.getTargetFile());
		final InputStream inputStream = signedDocument.openStream();
		IOUtils.copy(inputStream, fileOutputStream);
		IOUtils.closeQuietly(inputStream);
		IOUtils.closeQuietly(fileOutputStream);
	}

	private void prepareCommonSignature(SignatureModel model, WsParameters parameters) {

		final String signatureLevelString = model.getLevel();
		parameters.setSignatureLevel(SignatureLevel.valueOf(signatureLevelString));
		parameters.setSignaturePackaging(model.getPackaging());

		if (model.isClaimedCheck()) {
			parameters.getClaimedSignerRole().add(model.getClaimedRole());
		}

		if (model.isSignaturePolicyCheck()) {

			final byte[] hashValue = Base64.decodeBase64(model.getSignaturePolicyValue());
			final Policy policy = new Policy();
			policy.setId(model.getSignaturePolicyId());
			final DigestAlgorithm policyDigestAlgorithm = DigestAlgorithm.valueOf(model.getSignaturePolicyAlgo());
			policy.setDigestAlgorithm(policyDigestAlgorithm);
			policy.setDigestValue(hashValue);
			parameters.setSignaturePolicy(policy);
		}
	}

	private void prepareTSLSignature(WsParameters parameters, File fileToSign) {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

		final List<WsdssReference> references = new ArrayList<WsdssReference>();

		WsdssReference dssReference = new WsdssReference();
		dssReference.setId("xml_ref_id");
		dssReference.setUri("");
		dssReference.setContents(SigningUtils.toWsDocument(new FileDocument(fileToSign)));
		dssReference.setDigestMethodAlgorithm(parameters.getDigestAlgorithm());

		final List<DssTransform> transforms = new ArrayList<DssTransform>();

		DssTransform dssTransform = new DssTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.ENVELOPED);
		transforms.add(dssTransform);
		dssReference.getTransforms().add(dssTransform);

		dssTransform = new DssTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
		transforms.add(dssTransform);
		dssReference.getTransforms().add(dssTransform);

		references.add(dssReference);

		parameters.getReferences().addAll(references);
	}
}
